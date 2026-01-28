/*
 * DRAKVUF - GPL v2 - See COPYING for full license text.
 * Copyright (C) 2014-2024 Tamas K Lengyel.
 *
 * Linux/Android TLS secret extraction via BoringSSL/OpenSSL.
 * Hooks ssl_log_secret() in libssl.so to capture TLS secrets
 * (CLIENT_RANDOM for TLS 1.2, traffic secrets for TLS 1.3).
 */

#ifndef TLSMON_LINUX_H
#define TLSMON_LINUX_H

#include <array>
#include <string>
#include <vector>

#include "plugins/plugins_ex.h"
#include "linux_private.h"

struct tlsmon_config
{
    const char* libssl_profile;
};

class linux_tlsmon : public pluginex
{
public:
    linux_tlsmon(drakvuf_t drakvuf, const tlsmon_config* config, output_format_t output);
    ~linux_tlsmon() = default;

private:
    std::array<size_t, linux_tlsmon_priv::__SSL_OFFSET_MAX> ssl_offsets;
    std::array<size_t, linux_tlsmon_priv::__KERN_OFFSET_MAX> kern_offsets;
    addr_t ssl_log_secret_rva;

    /* Deferred re-scan: hooks entry_SYSCALL_64 and after N events,
     * re-scans physical memory for new ssl_log_secret pages that
     * appeared after the initial scan (e.g., from demand-paging). */
    int deferred_scan_counter_;
    bool deferred_scan_done_;
    unsigned char ref_bytes_[32];
    size_t ref_bytes_len_;

    bool setup_libssl_hook(drakvuf_t drakvuf);
    int scan_physical_memory_for_hooks(
        drakvuf_t drakvuf,
        const unsigned char* ref_bytes, size_t ref_len,
        addr_t page_offset,
        std::vector<addr_t>& hooked_pas);

    static event_response_t ssl_log_secret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
    static event_response_t deferred_scan_trigger_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
    void run_deferred_scan(drakvuf_t drakvuf);

    std::string read_client_random(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t ssl_ptr);
};

#endif
