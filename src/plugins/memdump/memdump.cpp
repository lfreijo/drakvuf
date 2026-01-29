/* DRAKVUF LICENSE - See LICENSE file */

#include <inttypes.h>
#include <assert.h>

#include "plugins/plugins.h"
#include "plugins/output_format.h"

#include "memdump.h"
#include "win.h"
#include "linux.h"
#include "private.h"

#define DUMP_NAME_PLACEHOLDER "(not configured)"

static void save_file_metadata(const drakvuf_trap_info_t* info,
    const char* file_path,
    const char* data_file_name,
    size_t dump_size,
    addr_t dump_address,
    const char* method,
    const char* dump_reason,
    int sequence_number,
    extras_t* extras)
{
    char* file = NULL;
    if ( asprintf(&file, "%s.metadata", file_path) < 0 )
        return;

    FILE* fp = fopen(file, "w");
    free(file);
    if (!fp)
        return;

    json_object* jobj = json_object_new_object();
    json_object_object_add(jobj, "Method", json_object_new_string(method));
    json_object_object_add(jobj, "DumpReason", json_object_new_string(dump_reason));
    json_object_object_add(jobj, "DumpAddress", json_object_new_string_fmt("0x%" PRIx64, dump_address));
    json_object_object_add(jobj, "DumpSize", json_object_new_string_fmt("0x%" PRIx64, dump_size));
    json_object_object_add(jobj, "PID", json_object_new_int(info->attached_proc_data.pid));
    json_object_object_add(jobj, "PPID", json_object_new_int(info->attached_proc_data.ppid));
    json_object_object_add(jobj, "ProcessName", json_object_new_string(info->attached_proc_data.name));

    if (extras && extras->type == WriteVirtualMemoryExtras)
    {
        json_object_object_add(jobj, "TargetPID", json_object_new_int(extras->write_virtual_memory_extras.target_pid));
        json_object_object_add(jobj, "TargetProcessName", json_object_new_string(extras->write_virtual_memory_extras.target_name));
        json_object_object_add(jobj, "TargetBaseAddress", json_object_new_string_fmt("0x%" PRIx64, extras->write_virtual_memory_extras.base_address));
    }

    json_object_object_add(jobj, "DataFileName", json_object_new_string(data_file_name));
    json_object_object_add(jobj, "SequenceNumber", json_object_new_int(sequence_number));

    fprintf(fp, "%s\n", json_object_get_string(jobj));
    fclose(fp);

    json_object_put(jobj);
}

bool dump_memory_region(
    drakvuf_t drakvuf,
    vmi_instance_t vmi,
    drakvuf_trap_info_t* info,
    memdump* plugin,
    access_context_t* ctx,
    size_t len_bytes,
    const char* reason,
    extras_t* extras,
    bool print_extras)
{
    char* metafile = nullptr;
    char* file = nullptr;
    char* file_path = nullptr;
    char* tmp_file_path = nullptr;
    const char* display_file = nullptr;
    void** access_ptrs = nullptr;
    FILE* fp = nullptr;
    bool ret = false;

    const gchar* chk_str = nullptr;

    addr_t aligned_addr;
    addr_t intra_page_offset;
    size_t aligned_len;
    size_t len_remainder;
    size_t num_pages;

    GChecksum* checksum = nullptr;

    size_t tmp_len_bytes = len_bytes;

    std::optional<fmt::Nval<decltype(extras->write_virtual_memory_extras.target_pid)>> target_pid;
    std::optional<fmt::Xval<decltype(extras->write_virtual_memory_extras.base_address)>> write_addr;

    int sequence_number = ++plugin->dumps_count;

    if (!plugin->memdump_dir)
    {
        ret = true;
        display_file = DUMP_NAME_PLACEHOLDER;
        goto printout;
    }

    aligned_addr = ctx->addr & ~(VMI_PS_4KB - 1);
    intra_page_offset = ctx->addr & (VMI_PS_4KB - 1);

    aligned_len = len_bytes & ~(VMI_PS_4KB - 1);
    len_remainder = len_bytes & (VMI_PS_4KB - 1);

    if (len_remainder)
    {
        aligned_len += VMI_PS_4KB;
    }

    ctx->addr = aligned_addr;
    num_pages = aligned_len / VMI_PS_4KB;

    access_ptrs = (void**)g_malloc(num_pages * sizeof(void*));

    if (VMI_SUCCESS != vmi_mmap_guest(vmi, ctx, num_pages, PROT_READ, access_ptrs))
    {
        PRINT_DEBUG("[MEMDUMP] Failed mmap guest\n");
        goto done;
    }

    checksum = g_checksum_new(G_CHECKSUM_SHA256);

    if (asprintf(&tmp_file_path, "%s/dump.tmp", plugin->memdump_dir) < 0)
        goto done;

    fp = fopen(tmp_file_path, "w");

    if (!fp)
    {
        PRINT_DEBUG("[MEMDUMP] Failed to open file\n");
        goto done;
    }

    for (size_t i = 0; i < num_pages; i++)
    {
        size_t write_length = tmp_len_bytes;

        if (write_length > VMI_PS_4KB - intra_page_offset)
            write_length = VMI_PS_4KB - intra_page_offset;

        if (access_ptrs[i])
        {
            fwrite((char*)access_ptrs[i] + intra_page_offset, write_length, 1, fp);
            g_checksum_update(checksum, (const guchar*)access_ptrs[i] + intra_page_offset, write_length);
            munmap(access_ptrs[i], VMI_PS_4KB);
        }
        else
        {
            uint8_t zeros[VMI_PS_4KB] = {};
            fwrite(zeros + intra_page_offset, write_length, 1, fp);
            g_checksum_update(checksum, (const guchar*)zeros + intra_page_offset, write_length);
        }

        intra_page_offset = 0;
        tmp_len_bytes -= write_length;
    }

    fclose(fp);

    chk_str = g_checksum_get_string(checksum);

    if (asprintf(&file, "%llx_%.16s", (unsigned long long) ctx->addr, chk_str) < 0)
        goto done;

    if (asprintf(&file_path, "%s/%s", plugin->memdump_dir, file) < 0)
        goto done;

    display_file = (const char*)file;

    if (rename(tmp_file_path, file_path) != 0)
        goto done;

    if (asprintf(&metafile, "%s/memdump.%06d", plugin->memdump_dir, sequence_number) < 0)
        goto done;

    save_file_metadata(info, metafile, file, len_bytes, ctx->addr, info->trap->name, reason, sequence_number, extras);

    ret = true;

printout:
    {
        auto default_print = std::make_tuple(
                keyval("DumpReason", fmt::Qstr(reason)),
                keyval("DumpPID", fmt::Nval(info->attached_proc_data.pid)),
                keyval("DumpAddr", fmt::Xval(ctx->addr, false)),
                keyval("DumpSize", fmt::Xval(len_bytes)),
                keyval("DumpFilename", fmt::Qstr(display_file)),
                keyval("DumpsCount", fmt::Nval(sequence_number))
            );
        if (print_extras)
        {
            target_pid = fmt::Nval(extras->write_virtual_memory_extras.target_pid);
            write_addr = fmt::Xval(extras->write_virtual_memory_extras.base_address, false);
            auto extra_arguments = std::make_tuple(
                    keyval("TargetPID", target_pid),
                    keyval("WriteAddr", write_addr)
                );
            fmt::print(plugin->m_output_format, "memdump", drakvuf, info, default_print, extra_arguments);
        }
        else
        {
            fmt::print(plugin->m_output_format, "memdump", drakvuf, info, default_print);
        }
    }

done:
    free(file);
    free(file_path);
    free(tmp_file_path);
    free(metafile);
    g_free(access_ptrs);
    g_checksum_free(checksum);
    return ret;
}

bool is_kernel_addr(drakvuf_t drakvuf, addr_t addr)
{
    bool const is_os_64bit = (drakvuf_get_page_mode(drakvuf) == VMI_PM_IA32E);
    return is_os_64bit ? VMI_GET_BIT(addr, 47) : VMI_GET_BIT(addr, 31);
}

bool inspect_stack_ptr(drakvuf_t drakvuf, drakvuf_trap_info_t* info, memdump* plugin, bool is_32bit, addr_t stack_ptr)
{
    auto vmi = vmi_lock_guard(drakvuf);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = stack_ptr
    );

    size_t bytes_read = 0;
    uint8_t buf[512];

    (void)vmi_read(vmi, &ctx, 512, buf, &bytes_read);

    size_t stack_width = is_32bit ? 4 : 8;
    for (size_t i = 0; i < bytes_read; i += stack_width)
    {
        uint64_t stack_val = 0;
        memcpy(&stack_val, buf+i, stack_width);

        mmvad_info_t mmvad;
        if (!drakvuf_find_mmvad(drakvuf, info->attached_proc_data.base_addr, stack_val, &mmvad))
            continue;

        addr_t begin = mmvad.starting_vpn << 12;
        size_t len = (mmvad.ending_vpn - mmvad.starting_vpn + 1) << 12;

        page_info_t p_info = {};

        if (vmi_pagetable_lookup_extended(vmi, info->regs->cr3, stack_val, &p_info) != VMI_SUCCESS)
            continue;

        bool page_valid = (p_info.x86_ia32e.pte_value & (1UL << 0)) != 0;
        bool page_execute = (p_info.x86_ia32e.pte_value & (1UL << 63)) == 0;

        if (page_valid && page_execute && mmvad.file_name_ptr)
        {
            sptr_type_t res = check_module_linked(drakvuf, vmi, plugin, info, mmvad.starting_vpn << 12);

            if (res == ERROR)
            {
                PRINT_DEBUG("[MEMDUMP] Something is corrupted\n");
                continue;
            }

            if (res == LINKED)
            {
                PRINT_DEBUG("[MEMDUMP] Linked stack entry %llx\n", (unsigned long long) stack_val);
                continue;
            }
            else if (res == UNLINKED)
            {
                PRINT_DEBUG("[MEMDUMP] UNLINKED stack entry %llx\n", (unsigned long long) stack_val);
            }
            else if (res == MAIN)
            {
                PRINT_DEBUG("[MEMDUMP] MAIN stack entry %llx\n", (unsigned long long) stack_val);
            }
        }

        if (page_valid && page_execute)
        {
            PRINT_DEBUG("[MEMDUMP] VX stack entry %llx\n", (unsigned long long) stack_val);

            ctx.addr = begin;

            if (!dump_memory_region(drakvuf, vmi, info, plugin, &ctx, len, "Stack heuristic",
                    nullptr, false))
            {
                PRINT_DEBUG("[MEMDUMP] Failed to save memory dump - internal error\n");
            }

            break;
        }
    }

    PRINT_DEBUG("[MEMDUMP] Done stack walk\n");

    return VMI_EVENT_RESPONSE_NONE;
}

bool dump_from_stack(drakvuf_t drakvuf, drakvuf_trap_info_t* info, memdump* plugin)
{
    bool is_32bit = drakvuf_process_is32bit(drakvuf, info);
    addr_t stack_ptr;
    addr_t frame_ptr;

    if (is_kernel_addr(drakvuf, info->regs->rip))
    {
        bool result = false;
        if (is_32bit)
        {
            result = drakvuf_get_user_stack32(drakvuf, info, &stack_ptr, &frame_ptr);
        }
        else
        {
            result = drakvuf_get_user_stack64(drakvuf, info, &stack_ptr);
        }
        if (!result)
        {
            PRINT_DEBUG("[MEMDUMP] Failed to get stack pointer\n");
            return VMI_EVENT_RESPONSE_NONE;
        }
    }
    else
    {
        stack_ptr = info->regs->rsp;
    }

    PRINT_DEBUG("[MEMDUMP] Got stack pointer: %llx\n", (unsigned long long)stack_ptr);
    return inspect_stack_ptr(drakvuf, info, plugin, is_32bit, stack_ptr);
}

bool dotnet_assembly_native_load_image_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info, memdump* plugin)
{
    const auto ptr_size = drakvuf_get_process_address_width(drakvuf, info);

    auto vmi = vmi_lock_guard(drakvuf);
    vmi_v2pcache_flush(vmi, info->regs->cr3);

    addr_t addr = drakvuf_get_function_argument(drakvuf, info, 1) + ptr_size;

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = addr
    );

    addr_t data_size = 0;
    if (vmi_read(vmi, &ctx, ptr_size, &data_size, nullptr) != VMI_SUCCESS)
    {
        PRINT_DEBUG("[MEMDUMP.NET] failed to read size of dump from memory.");
        return false;
    }

    PRINT_DEBUG("[MEMDUMP.NET] dumping assembly from memory (size = %lu)\n", data_size);

    ctx.addr += ptr_size;

    if (!dump_memory_region(drakvuf, vmi, info, plugin, &ctx, data_size, ".NET AssemblyNative::LoadImage", nullptr, false))
    {
        PRINT_DEBUG("[MEMDUMP] Failed to store memory dump due to an internal error\n");
        return false;
    }

    return true;
}

memdump::memdump(drakvuf_t drakvuf, const memdump_config* c, output_format_t output)
    : pluginex(drakvuf, output)
    , dumps_count()
    , memdump_dir(c->memdump_dir)
    , dll_base_rva(0)
    , dll_base_wow_rva(0)
{
    auto os = drakvuf_get_os_type(drakvuf);
    PRINT_DEBUG("[MEMDUMP] Initializing memdump, OS type: %d\n", os);
    if (os == VMI_OS_WINDOWS)
    {
        PRINT_DEBUG("[MEMDUMP] Creating Windows memdump\n");
        this->wm = std::make_unique<win_memdump>(drakvuf, c, output, this);
        // Copy RVAs for stack_util.cpp compatibility
        this->dll_base_rva = this->wm->dll_base_rva;
        this->dll_base_wow_rva = this->wm->dll_base_wow_rva;
    }
    else
    {
        PRINT_DEBUG("[MEMDUMP] Creating Linux memdump\n");
        this->lm = std::make_unique<linux_memdump>(drakvuf, c, output, this);
    }
    PRINT_DEBUG("[MEMDUMP] Memdump initialization complete\n");
}

memdump::~memdump()
{
    userhook_destroy();
}

bool memdump::stop_impl()
{
    return this->userhooks_stop() && pluginex::stop_impl();
}
