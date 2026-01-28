/*
 * DRAKVUF - GPL v2 - See COPYING for full license text.
 * Copyright (C) 2014-2024 Tamas K Lengyel.
 *
 * BoringSSL / OpenSSL struct offset definitions for Linux TLS extraction.
 */

#ifndef TLSMON_LINUX_PRIVATE_H
#define TLSMON_LINUX_PRIVATE_H

#include <sstream>
#include <iomanip>
#include <cstddef>
#include <cstdint>

namespace linux_tlsmon_priv
{

constexpr size_t CLIENT_RANDOM_SZ = 32;
constexpr size_t MAX_SECRET_SZ = 48;
constexpr size_t MAX_LABEL_SZ = 256;

// Kernel struct offsets needed for VMA maple tree traversal (kernel 6.1+).
// These are loaded at runtime from the kernel JSON profile.
enum kern_offset
{
    KERN_TASK_STRUCT_MM = 0,
    KERN_TASK_STRUCT_ACTIVE_MM,
    KERN_TASK_STRUCT_PID,
    KERN_VM_AREA_STRUCT_START,
    KERN_VM_AREA_STRUCT_FILE,
    KERN_FILE_F_PATH,
    KERN_PATH_DENTRY,
    KERN_DENTRY_D_NAME,
    KERN_QSTR_NAME,
    KERN_MM_STRUCT_PGD,
    __KERN_OFFSET_MAX
};

static const char* kern_offset_names[][2] =
{
    [KERN_TASK_STRUCT_MM]         = { "task_struct",     "mm" },
    [KERN_TASK_STRUCT_ACTIVE_MM]  = { "task_struct",     "active_mm" },
    [KERN_TASK_STRUCT_PID]        = { "task_struct",     "pid" },
    [KERN_VM_AREA_STRUCT_START]   = { "vm_area_struct",  "vm_start" },
    [KERN_VM_AREA_STRUCT_FILE]    = { "vm_area_struct",  "vm_file" },
    [KERN_FILE_F_PATH]            = { "file",            "f_path" },
    [KERN_PATH_DENTRY]            = { "path",            "dentry" },
    [KERN_DENTRY_D_NAME]          = { "dentry",          "d_name" },
    [KERN_QSTR_NAME]              = { "qstr",            "name" },
    [KERN_MM_STRUCT_PGD]          = { "mm_struct",       "pgd" },
};

// Maple tree structure offsets (kernel 6.1+, hardcoded from dwarf2json profile).
// These are stable across kernel 6.1-6.x and set by the kernel's struct layout.
namespace maple
{
    constexpr size_t MM_MT_OFFSET = 64;       // mm_struct.mm_mt (embedded struct)
    constexpr size_t MT_MA_ROOT   = 8;        // maple_tree.ma_root
    constexpr size_t MR64_SLOT    = 128;      // maple_range_64.slot
    constexpr size_t MA64_SLOT    = 80;       // maple_arange_64.slot
    constexpr int    MR64_SLOTS   = 16;       // maple_range_64 slot count
    constexpr int    MA64_SLOTS   = 10;       // maple_arange_64 slot count
    constexpr uint64_t NODE_MASK  = 0x7F;     // low 7 bits encode node metadata
    constexpr int    TYPE_LEAF_64   = 1;      // maple_leaf_64
    constexpr int    TYPE_RANGE_64  = 2;      // maple_range_64 (internal)
    constexpr int    TYPE_ARANGE_64 = 3;      // maple_arange_64 (internal)
    constexpr int    MAX_DEPTH      = 8;

    inline bool is_node(uint64_t e) { return (e & 3) == 2 && e > 4096; }
    inline addr_t addr(uint64_t e)  { return e & ~NODE_MASK; }
    inline int type(uint64_t e)     { return (e >> 3) & 0xF; }
}

// BoringSSL offset indices (Android/BlissOS)
enum ssl_offset
{
    SSL_ST_S3 = 0,
    SSL3_STATE_CLIENT_RANDOM,
    __SSL_OFFSET_MAX
};

// Struct name / field name pairs for BoringSSL (json_get_struct_members_array_rva)
static const char* ssl_offset_names[][2] =
{
    [SSL_ST_S3]                = { "ssl_st",     "s3" },
    [SSL3_STATE_CLIENT_RANDOM] = { "SSL3_STATE", "client_random" },
};

// OpenSSL 3.x offset indices (standard Linux distros)
// OpenSSL 3.x uses ssl_connection_st instead of ssl_st
enum openssl_offset
{
    OPENSSL_SSL_CONNECTION_S3 = 0,
    OPENSSL_SSL3_STATE_CLIENT_RANDOM,
    __OPENSSL_OFFSET_MAX
};

// Struct name / field name pairs for OpenSSL 3.x
static const char* openssl_offset_names[][2] =
{
    [OPENSSL_SSL_CONNECTION_S3]           = { "ssl_connection_st", "s3" },
    [OPENSSL_SSL3_STATE_CLIENT_RANDOM]    = { "ssl3_state_st",     "client_random" },
};

inline std::string byte2str(const unsigned char* data, size_t count)
{
    std::stringstream ss;
    ss << std::hex;
    for (size_t i = 0; i < count; ++i)
        ss << std::setw(2) << std::setfill('0') << (int)data[i];
    return ss.str();
}

} // namespace linux_tlsmon_priv

#endif
