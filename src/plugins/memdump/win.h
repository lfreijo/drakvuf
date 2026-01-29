/* DRAKVUF LICENSE - See LICENSE file */

#ifndef MEMDUMP_WIN_H
#define MEMDUMP_WIN_H

#include "plugins/plugins_ex.h"
#include "private.h"

class memdump;

class win_memdump : public pluginex
{
public:
    memdump* parent;

    // Windows-specific offsets
    addr_t dll_base_rva;
    addr_t dll_base_wow_rva;
    size_t kthread_process_rva;
    size_t wow64context_eip_rva;
    size_t wow64context_eax_rva;

    win_memdump(drakvuf_t drakvuf, const memdump_config* config, output_format_t output, memdump* parent);
    win_memdump(const win_memdump&) = delete;
    win_memdump& operator=(const win_memdump&) = delete;
};

#endif
