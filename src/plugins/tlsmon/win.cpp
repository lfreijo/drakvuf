/*
 * DRAKVUF - GPL v2 - See COPYING for full license text.
 * Copyright (C) 2014-2024 Tamas K Lengyel.
 *
 * Windows Schannel TLS secret extraction.
 * Hooks lsass.exe -> ncrypt.dll!SslGenerateSessionKeys to capture
 * CLIENT_RANDOM and master key for Wireshark decryption.
 */

#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <assert.h>
#include <array>
#include <vector>
#include <libdrakvuf/json-util.h>

#include "plugins/output_format.h"
#include "private.h"
#include "win.h"


static std::optional<std::string> ssl_get_master_key(
    drakvuf_t drakvuf, drakvuf_trap_info* info, vmi_instance_t vmi, access_context_t ctx
)
{
    tlsmon_priv::ssl_master_secret_t master_secret;

    addr_t ncrypt_ssl_key_addr = drakvuf_get_function_argument(drakvuf, info, 2);

    tlsmon_priv::ncrypt_ssl_key_t ncrypt_ssl_key;
    ctx.addr = ncrypt_ssl_key_addr;
    if (VMI_SUCCESS != vmi_read(vmi, &ctx, sizeof(ncrypt_ssl_key), &ncrypt_ssl_key, nullptr))
    {
        PRINT_DEBUG("[TLSMON] Can't read NCryptSslKey structure\n");
        return {};
    }

    if (ncrypt_ssl_key.magic != tlsmon_priv::NCRYPT_SSL_KEY_MAGIC_BYTES)
    {
        PRINT_DEBUG("[TLSMON] Wrong NCryptSslKey magic\n");
        return {};
    }

    ctx.addr = (addr_t) ncrypt_ssl_key.master_secret;
    if (VMI_SUCCESS != vmi_read(vmi, &ctx, sizeof(master_secret), &master_secret, nullptr))
    {
        PRINT_DEBUG("[TLSMON] Can't read SslMasterSecret structure\n");
        return {};
    }

    if (master_secret.magic != tlsmon_priv::MASTER_SECRET_MAGIC_BYTES)
    {
        PRINT_DEBUG("[TLSMON] Wrong SslMasterSecret magic\n");
        return {};
    }

    std::string master_key_str = tlsmon_priv::byte2str(master_secret.master_key, tlsmon_priv::MASTER_KEY_SZ);
    return master_key_str;
}

static
std::optional< std::vector<tlsmon_priv::ncrypt_buffer_t> > ssl_get_ncrypt_buffers(
    drakvuf_t drakvuf, drakvuf_trap_info* info, vmi_instance_t vmi, access_context_t ctx
)
{
    ctx.addr = drakvuf_get_function_argument(drakvuf, info, 5);
    tlsmon_priv::ncrypt_buffer_desc_t ncrypt_buffer_desc;
    if (VMI_SUCCESS != vmi_read(vmi, &ctx, sizeof(ncrypt_buffer_desc), &ncrypt_buffer_desc, nullptr))
    {
        PRINT_DEBUG("[TLSMON] Failed to read ncrypt parameter list\n");
        return {};
    }

    size_t ncrypt_buffers_size = ncrypt_buffer_desc.cbuffers;
    if ( ncrypt_buffers_size != 2 )
    {
        PRINT_DEBUG("[TLSMON] Ncrypt parameter list has different size than 2\n");
        return {};
    }

    std::vector<tlsmon_priv::ncrypt_buffer_t> ncrypt_buffers = std::vector<tlsmon_priv::ncrypt_buffer_t>(ncrypt_buffers_size);
    ctx.addr = (addr_t) ncrypt_buffer_desc.buffers;
    if (VMI_SUCCESS != vmi_read(vmi, &ctx, (ncrypt_buffers_size * sizeof(tlsmon_priv::ncrypt_buffer_t)), ncrypt_buffers.data(), nullptr))
    {
        PRINT_DEBUG("[TLSMON] Failed to read ncrypt parameter list buffers\n");
        return {};
    }
    return ncrypt_buffers;
}


static
event_response_t ssl_generate_session_keys_cb(drakvuf_t drakvuf, drakvuf_trap_info* info)
{
    auto plugin = static_cast<win_tlsmon*>(drakvuf_get_extra_from_running_trap(info->trap));
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    );

    auto vmi = vmi_lock_guard(drakvuf);

    auto master_key = ssl_get_master_key(drakvuf, info, vmi, ctx);
    if (!master_key)
    {
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto ncrypt_buffers = ssl_get_ncrypt_buffers(drakvuf, info, vmi, ctx);
    if (!ncrypt_buffers)
    {
        return VMI_EVENT_RESPONSE_NONE;
    }

    std::array<char, tlsmon_priv::CLIENT_RANDOM_SZ> randoms_buffer = std::array<char, tlsmon_priv::CLIENT_RANDOM_SZ>();

    for (tlsmon_priv::ncrypt_buffer_t ncrypt_buffer_iter: *ncrypt_buffers)
    {
        uint32_t buffer_type = ncrypt_buffer_iter.buffer_type;
        uint32_t size = ncrypt_buffer_iter.cbbuffer;;
        if ( size != tlsmon_priv::CLIENT_RANDOM_SZ )
        {
            PRINT_DEBUG("[TLSMON] Wrong ncrypt buffer size\n");
            continue;
        }

        ctx.addr = (addr_t) ncrypt_buffer_iter.buffer;
        if (VMI_SUCCESS != vmi_read(vmi, &ctx, randoms_buffer.size(), randoms_buffer.data(), nullptr))
        {
            PRINT_DEBUG("[TLSMON] Failed to read ncrypt buffer\n");
            continue;
        }
        std::string client_random_str = tlsmon_priv::byte2str((unsigned char*)randoms_buffer.data(), 32);

        if (buffer_type == tlsmon_priv::NCRYPTBUFFER_SSL_CLIENT_RANDOM)
        {
            fmt::print(plugin->m_output_format, "tlsmon", drakvuf, info,
                keyval("client_random", fmt::Qstr(client_random_str)),
                keyval("master_key", fmt::Qstr(*master_key))
            );
        }
        else if (buffer_type != tlsmon_priv::NCRYPTBUFFER_SSL_SERVER_RANDOM)
        {
            PRINT_DEBUG("[TLSMON] Unknown ncrypt buffer type.\n");
            continue;
        }
    }
    return VMI_EVENT_RESPONSE_NONE;
}


void win_tlsmon::hook_lsass(drakvuf_t drakvuf)
{
    addr_t lsass_base = 0;
    if (!drakvuf_find_process(drakvuf, ~0, "lsass.exe", &lsass_base))
        return;
    drakvuf_request_userhook_on_running_process(drakvuf, lsass_base, "ncrypt.dll", "SslGenerateSessionKeys", ssl_generate_session_keys_cb, this);
}


win_tlsmon::win_tlsmon(drakvuf_t drakvuf, output_format_t output)
    : pluginex(drakvuf, output)
{
    if (!drakvuf_are_userhooks_supported(drakvuf))
    {
        PRINT_DEBUG("[TLSMON] Usermode hooking not supported.\n");
        return;
    }

    this->hook_lsass(drakvuf);
}


win_tlsmon::~win_tlsmon() {}
