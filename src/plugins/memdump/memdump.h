/* DRAKVUF LICENSE - See LICENSE file */

#ifndef MEMDUMP_H
#define MEMDUMP_H

#include <vector>
#include <memory>

#include <glib.h>
#include <libusermode/userhook.hpp>
#include "plugins/plugins_ex.h"

struct memdump_config
{
    const char* memdump_dir;
    const char* dll_hooks_list;
    const char* clr_profile;
    const char* mscorwks_profile;
    const bool print_no_addr;
    const bool memdump_disable_free_vm;
    const bool memdump_disable_protect_vm;
    const bool memdump_disable_write_vm;
    const bool memdump_disable_terminate_proc;
    const bool memdump_disable_create_thread;
    const bool memdump_disable_set_thread;
    const bool memdump_disable_shellcode_detect;
};

// Forward declarations for OS-specific implementations
class win_memdump;
class linux_memdump;

class memdump: public pluginex
{
public:
    // OS-specific implementations
    std::unique_ptr<win_memdump> wm;
    std::unique_ptr<linux_memdump> lm;

    // Shared state
    int dumps_count;
    const char* memdump_dir;

    // Windows-specific (kept for backward compatibility with stack_util.cpp)
    addr_t dll_base_rva;
    addr_t dll_base_wow_rva;

    wanted_hooks_t wanted_hooks;

    memdump(drakvuf_t drakvuf, const memdump_config* config, output_format_t output);
    memdump(const memdump&) = delete;
    memdump& operator=(const memdump&) = delete;
    ~memdump();

    virtual bool stop_impl() override;

    void userhook_init(const memdump_config* c, output_format_t output);
    void userhook_destroy();
    bool userhooks_stop();

    void setup_dotnet_hooks(const char* dll_name, const char* profile);
};

#endif
