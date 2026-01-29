/* DRAKVUF LICENSE - See LICENSE file */

#ifndef MEMDUMP_LINUX_H
#define MEMDUMP_LINUX_H

#include "plugins/plugins_ex.h"
#include "private.h"

class memdump;

namespace memdump_ns
{

// Linux kernel struct offsets needed for memdump
enum linux_memdump_offsets
{
    TASK_STRUCT_MM,
    MM_STRUCT_MMAP,
    MM_STRUCT_PGD,
    VM_AREA_STRUCT_VM_START,
    VM_AREA_STRUCT_VM_END,
    VM_AREA_STRUCT_VM_FLAGS,
    VM_AREA_STRUCT_VM_NEXT,
    VM_AREA_STRUCT_VM_FILE,
    __LINUX_MEMDUMP_OFFSET_MAX
};

static const char* linux_memdump_offset_names[__LINUX_MEMDUMP_OFFSET_MAX][2] =
{
    [TASK_STRUCT_MM] = {"task_struct", "mm"},
    [MM_STRUCT_MMAP] = {"mm_struct", "mmap"},
    [MM_STRUCT_PGD] = {"mm_struct", "pgd"},
    [VM_AREA_STRUCT_VM_START] = {"vm_area_struct", "vm_start"},
    [VM_AREA_STRUCT_VM_END] = {"vm_area_struct", "vm_end"},
    [VM_AREA_STRUCT_VM_FLAGS] = {"vm_area_struct", "vm_flags"},
    [VM_AREA_STRUCT_VM_NEXT] = {"vm_area_struct", "vm_next"},
    [VM_AREA_STRUCT_VM_FILE] = {"vm_area_struct", "vm_file"},
};

// pt_regs offsets for reading syscall arguments
enum linux_pt_regs
{
    PT_REGS_R15,
    PT_REGS_R14,
    PT_REGS_R13,
    PT_REGS_R12,
    PT_REGS_RBP,
    PT_REGS_RBX,
    PT_REGS_R11,
    PT_REGS_R10,
    PT_REGS_R9,
    PT_REGS_R8,
    PT_REGS_RAX,
    PT_REGS_RCX,
    PT_REGS_RDX,
    PT_REGS_RSI,
    PT_REGS_RDI,
    PT_REGS_ORIG_RAX,
    PT_REGS_RIP,
    PT_REGS_CS,
    PT_REGS_EFLAGS,
    PT_REGS_RSP,
    PT_REGS_SS,
    __PT_REGS_MAX
};

static const char* linux_pt_regs_names[__PT_REGS_MAX][2] =
{
    [PT_REGS_R15]      = {"pt_regs", "r15"},
    [PT_REGS_R14]      = {"pt_regs", "r14"},
    [PT_REGS_R13]      = {"pt_regs", "r13"},
    [PT_REGS_R12]      = {"pt_regs", "r12"},
    [PT_REGS_RBP]      = {"pt_regs", "bp"},
    [PT_REGS_RBX]      = {"pt_regs", "bx"},
    [PT_REGS_R11]      = {"pt_regs", "r11"},
    [PT_REGS_R10]      = {"pt_regs", "r10"},
    [PT_REGS_R9]       = {"pt_regs", "r9"},
    [PT_REGS_R8]       = {"pt_regs", "r8"},
    [PT_REGS_RAX]      = {"pt_regs", "ax"},
    [PT_REGS_RCX]      = {"pt_regs", "cx"},
    [PT_REGS_RDX]      = {"pt_regs", "dx"},
    [PT_REGS_RSI]      = {"pt_regs", "si"},
    [PT_REGS_RDI]      = {"pt_regs", "di"},
    [PT_REGS_ORIG_RAX] = {"pt_regs", "orig_ax"},
    [PT_REGS_RIP]      = {"pt_regs", "ip"},
    [PT_REGS_CS]       = {"pt_regs", "cs"},
    [PT_REGS_EFLAGS]   = {"pt_regs", "flags"},
    [PT_REGS_RSP]      = {"pt_regs", "sp"},
    [PT_REGS_SS]       = {"pt_regs", "ss"},
};

// Linux x86_64 syscall numbers for memory operations
enum linux_memory_syscalls
{
    __NR_mmap = 9,
    __NR_mprotect = 10,
    __NR_munmap = 11,
    __NR_mremap = 25,
    __NR_clone = 56,
    __NR_exit_group = 231,
    __NR_process_vm_writev = 311,
    __NR_pkey_mprotect = 329,
};

// VM flags from linux/mm.h (kernel internal values, not exposed in userspace headers)
enum vm_flags
{
    VM_READ = 0x00000001,
    VM_WRITE = 0x00000002,
    VM_EXEC = 0x00000004,
    VM_SHARED = 0x00000008,
};

} // namespace memdump_ns

// Use system-defined PROT_* and CLONE_* macros
#include <sys/mman.h>
#include <sched.h>

class linux_memdump : public pluginex
{
public:
    memdump* parent;

    // Config flags (mapped from Windows equivalents)
    bool disable_free_vm;      // Disables munmap monitoring
    bool disable_protect_vm;   // Disables mprotect monitoring
    bool disable_write_vm;     // Disables process_vm_writev monitoring
    bool disable_terminate_proc; // Disables exit_group monitoring
    bool disable_create_thread;  // Disables clone monitoring
    bool disable_shellcode_detect; // Disables RWX mmap detection

    // Kernel struct offsets
    std::array<size_t, memdump_ns::__LINUX_MEMDUMP_OFFSET_MAX> offsets;
    std::array<size_t, memdump_ns::__PT_REGS_MAX> regs;

    // Syscall hooks
    std::unique_ptr<libhook::SyscallHook> syscall_hook;

    // Return hooks for async syscall results
    std::map<std::pair<uint64_t, addr_t>, std::unique_ptr<libhook::ReturnHook>> ret_hooks;

    // Callbacks
    event_response_t syscall_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

    // Helper functions
    bool get_pt_regs_and_nr(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t* pt_regs_addr, uint64_t* nr);
    bool read_pt_regs_arg(drakvuf_t drakvuf, addr_t pt_regs_addr, int arg_index, uint64_t* value);
    bool is_rwx_region(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t addr);
    bool check_elf_header(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t addr);

    linux_memdump(drakvuf_t drakvuf, const memdump_config* config, output_format_t output, memdump* parent);
    linux_memdump(const linux_memdump&) = delete;
    linux_memdump& operator=(const linux_memdump&) = delete;
};

#endif
