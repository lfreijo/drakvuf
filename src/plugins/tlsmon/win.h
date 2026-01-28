/*
 * DRAKVUF - GPL v2 - See COPYING for full license text.
 * Copyright (C) 2014-2024 Tamas K Lengyel.
 */

#ifndef TLSMON_WIN_H
#define TLSMON_WIN_H

#include "plugins/plugins_ex.h"
#include <libusermode/userhook.hpp>

class win_tlsmon : public pluginex
{
public:
    win_tlsmon(drakvuf_t drakvuf, output_format_t output);
    ~win_tlsmon();

private:
    void hook_lsass(drakvuf_t drakvuf);
};

#endif
