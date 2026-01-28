/*
 * DRAKVUF - GPL v2 - See COPYING for full license text.
 * Copyright (C) 2014-2024 Tamas K Lengyel.
 *
 * Linux/Android TLS secret extraction.
 *
 * Hooks BoringSSL's ssl_log_secret() which is called for all TLS secret types:
 *   - TLS 1.2: "CLIENT_RANDOM" label with 48-byte master secret
 *   - TLS 1.3: Various traffic secret labels with 32-48 byte secrets
 *
 * Since ssl_log_secret is an internal (non-exported) symbol, its RVA comes
 * from the JSON profile's symbols section. The breakpoint is set on the
 * physical page backing the code, so it fires for ALL processes sharing
 * that libssl.so mapping.
 *
 * x86_64 SysV ABI argument layout for ssl_log_secret(ssl, label, secret):
 *   rdi = const SSL *ssl
 *   rsi = const char *label
 *   rdx = secret.data_ (Span data pointer)
 *   rcx = secret.size_ (Span length)
 *
 * VMA traversal uses maple tree (kernel 6.1+) since the linked-list
 * mm_struct.mmap / vm_area_struct.vm_next fields were removed.
 */

#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <array>
#include <vector>
#include <memory>
#include <cstring>
#include <libdrakvuf/json-util.h>

#include "plugins/output_format.h"
#include "linux.h"
#include "linux_private.h"

using namespace linux_tlsmon_priv;


/* ---------- Maple tree VMA walker (kernel 6.1+) ---------- */

/*
 * Get a VMA's backing file name.
 * Walks: vm_area_struct -> vm_file -> f_path.dentry -> d_name.name string.
 * Returns empty string on error.
 */
static std::string vma_get_filename(
    vmi_instance_t vmi, access_context_t* ctx,
    addr_t vma, const size_t* ko)
{
    addr_t file_ptr = 0;
    ctx->addr = vma + ko[KERN_VM_AREA_STRUCT_FILE];
    if (VMI_SUCCESS != vmi_read_addr(vmi, ctx, &file_ptr) || !file_ptr)
        return {};

    addr_t dentry = 0;
    ctx->addr = file_ptr + ko[KERN_FILE_F_PATH] + ko[KERN_PATH_DENTRY];
    if (VMI_SUCCESS != vmi_read_addr(vmi, ctx, &dentry) || !dentry)
        return {};

    addr_t name_ptr = 0;
    ctx->addr = dentry + ko[KERN_DENTRY_D_NAME] + ko[KERN_QSTR_NAME];
    if (VMI_SUCCESS != vmi_read_addr(vmi, ctx, &name_ptr) || !name_ptr)
        return {};

    char namebuf[64] = {};
    ctx->addr = name_ptr;
    if (VMI_SUCCESS != vmi_read(vmi, ctx, sizeof(namebuf) - 1, namebuf, nullptr))
        return {};
    namebuf[sizeof(namebuf) - 1] = '\0';

    return std::string(namebuf);
}

/*
 * Check if a VMA's backing file name starts with a given prefix.
 * Walks: vm_area_struct -> vm_file -> f_path.dentry -> d_name.name string.
 */
static bool vma_filename_starts_with(
    vmi_instance_t vmi, access_context_t* ctx,
    addr_t vma, const size_t* ko, const char* prefix)
{
    std::string name = vma_get_filename(vmi, ctx, vma, ko);
    if (name.empty())
        return false;
    return strncmp(name.c_str(), prefix, strlen(prefix)) == 0;
}

/*
 * Check if a VMA's backing file name matches OpenSSL 3.x pattern (libssl.so.3*).
 * OpenSSL 3.x libraries are named libssl.so.3.x.x with soname libssl.so.3.
 */
static bool vma_is_openssl3(
    vmi_instance_t vmi, access_context_t* ctx,
    addr_t vma, const size_t* ko)
{
    std::string name = vma_get_filename(vmi, ctx, vma, ko);
    if (name.empty())
        return false;

    /* Match libssl.so.3 or libssl.so.3.x.x */
    return name.find("libssl.so.3") == 0;
}

/*
 * Given a leaf entry (VMA pointer), check if it matches "libssl" and
 * return its vm_start. Returns 0 on mismatch or error.
 */
static addr_t check_leaf_vma(
    vmi_instance_t vmi, access_context_t* ctx,
    uint64_t entry, const size_t* ko)
{
    if (!entry || (entry & 3))
        return 0;   /* NULL or tagged internal entry */

    addr_t vma = entry;
    if (!vma_filename_starts_with(vmi, ctx, vma, ko, "libssl"))
        return 0;

    /* Read vm_start -- this is the library's base address */
    addr_t vm_start = 0;
    ctx->addr = vma + ko[KERN_VM_AREA_STRUCT_START];
    if (VMI_SUCCESS != vmi_read_addr(vmi, ctx, &vm_start) || !vm_start)
        return 0;

    return vm_start;
}

/*
 * Given a leaf entry (VMA pointer), check if it matches OpenSSL 3.x (libssl.so.3*)
 * and return its vm_start. Returns 0 on mismatch or error.
 */
static addr_t check_leaf_vma_openssl(
    vmi_instance_t vmi, access_context_t* ctx,
    uint64_t entry, const size_t* ko)
{
    if (!entry || (entry & 3))
        return 0;   /* NULL or tagged internal entry */

    addr_t vma = entry;
    if (!vma_is_openssl3(vmi, ctx, vma, ko))
        return 0;

    /* Read vm_start -- this is the library's base address */
    addr_t vm_start = 0;
    ctx->addr = vma + ko[KERN_VM_AREA_STRUCT_START];
    if (VMI_SUCCESS != vmi_read_addr(vmi, ctx, &vm_start) || !vm_start)
        return 0;

    return vm_start;
}

/*
 * Process a maple tree node's slots, searching for a VMA backed by "libssl".
 *
 * The parent determines what its children are:
 *   - TYPE_LEAF_64 (1): slots contain VMA pointers
 *   - TYPE_RANGE_64 (2) / TYPE_ARANGE_64 (3): slots contain child maple_enode
 *
 * The kernel does NOT use is_node() on slot entries from internal nodes.
 * It relies on the parent's type to interpret children.
 */
static addr_t walk_maple_node(
    vmi_instance_t vmi, access_context_t* ctx,
    addr_t node, int ntype, const size_t* ko, int depth);

static addr_t process_internal_slot(
    vmi_instance_t vmi, access_context_t* ctx,
    uint64_t slot_entry, const size_t* ko, int depth)
{
    if (!slot_entry)
        return 0;

    int child_type = maple::type(slot_entry);
    addr_t child_node = maple::addr(slot_entry);

    /* Validate: child node should be 256-byte aligned (slab-allocated) */
    if (child_node & 0xFF)
        return 0;

    /* Validate: must be a kernel address */
    if (child_node < 0xffff000000000000ULL)
        return 0;

    return walk_maple_node(vmi, ctx, child_node, child_type, ko, depth + 1);
}

static addr_t walk_maple_node(
    vmi_instance_t vmi, access_context_t* ctx,
    addr_t node, int ntype, const size_t* ko, int depth)
{
    if (depth > maple::MAX_DEPTH || !node)
        return 0;

    bool is_leaf = (ntype == maple::TYPE_LEAF_64);

    size_t slot_offset;
    int slot_count;

    switch (ntype)
    {
    case maple::TYPE_LEAF_64:
    case maple::TYPE_RANGE_64:
        slot_offset = maple::MR64_SLOT;
        slot_count  = maple::MR64_SLOTS;
        break;
    case maple::TYPE_ARANGE_64:
        slot_offset = maple::MA64_SLOT;
        slot_count  = maple::MA64_SLOTS;
        break;
    default:
        return 0;
    }

    for (int i = 0; i < slot_count; i++)
    {
        uint64_t slot = 0;
        ctx->addr = node + slot_offset + (i * sizeof(uint64_t));
        if (VMI_SUCCESS != vmi_read_64(vmi, ctx, &slot) || !slot)
            continue;

        if (is_leaf)
        {
            addr_t result = check_leaf_vma(vmi, ctx, slot, ko);
            if (result)
                return result;
        }
        else
        {
            addr_t result = process_internal_slot(vmi, ctx, slot, ko, depth);
            if (result)
                return result;
        }
    }

    return 0;
}

/*
 * Entry point: walk the maple tree starting from ma_root.
 * ma_root can be: NULL (empty tree), a single VMA pointer, or a tagged
 * maple_enode pointer (identified by is_node()).
 */
static addr_t walk_maple_tree(
    vmi_instance_t vmi, access_context_t* ctx,
    uint64_t ma_root, const size_t* ko)
{
    if (!ma_root)
        return 0;

    if (maple::is_node(ma_root))
    {
        addr_t node = maple::addr(ma_root);
        int ntype = maple::type(ma_root);
        return walk_maple_node(vmi, ctx, node, ntype, ko, 0);
    }

    /* Single-entry tree: ma_root is a direct VMA pointer */
    return check_leaf_vma(vmi, ctx, ma_root, ko);
}


/* ---------- OpenSSL 3.x maple tree walker (parallel to BoringSSL) ---------- */

static addr_t walk_maple_node_openssl(
    vmi_instance_t vmi, access_context_t* ctx,
    addr_t node, int ntype, const size_t* ko, int depth);

static addr_t process_internal_slot_openssl(
    vmi_instance_t vmi, access_context_t* ctx,
    uint64_t slot_entry, const size_t* ko, int depth)
{
    if (!slot_entry)
        return 0;

    int child_type = maple::type(slot_entry);
    addr_t child_node = maple::addr(slot_entry);

    /* Validate: child node should be 256-byte aligned (slab-allocated) */
    if (child_node & 0xFF)
        return 0;

    /* Validate: must be a kernel address */
    if (child_node < 0xffff000000000000ULL)
        return 0;

    return walk_maple_node_openssl(vmi, ctx, child_node, child_type, ko, depth + 1);
}

static addr_t walk_maple_node_openssl(
    vmi_instance_t vmi, access_context_t* ctx,
    addr_t node, int ntype, const size_t* ko, int depth)
{
    if (depth > maple::MAX_DEPTH || !node)
        return 0;

    bool is_leaf = (ntype == maple::TYPE_LEAF_64);

    size_t slot_offset;
    int slot_count;

    switch (ntype)
    {
    case maple::TYPE_LEAF_64:
    case maple::TYPE_RANGE_64:
        slot_offset = maple::MR64_SLOT;
        slot_count  = maple::MR64_SLOTS;
        break;
    case maple::TYPE_ARANGE_64:
        slot_offset = maple::MA64_SLOT;
        slot_count  = maple::MA64_SLOTS;
        break;
    default:
        return 0;
    }

    for (int i = 0; i < slot_count; i++)
    {
        uint64_t slot = 0;
        ctx->addr = node + slot_offset + (i * sizeof(uint64_t));
        if (VMI_SUCCESS != vmi_read_64(vmi, ctx, &slot) || !slot)
            continue;

        if (is_leaf)
        {
            addr_t result = check_leaf_vma_openssl(vmi, ctx, slot, ko);
            if (result)
                return result;
        }
        else
        {
            addr_t result = process_internal_slot_openssl(vmi, ctx, slot, ko, depth);
            if (result)
                return result;
        }
    }

    return 0;
}

/*
 * Entry point for OpenSSL maple tree walk.
 */
static addr_t walk_maple_tree_openssl(
    vmi_instance_t vmi, access_context_t* ctx,
    uint64_t ma_root, const size_t* ko)
{
    if (!ma_root)
        return 0;

    if (maple::is_node(ma_root))
    {
        addr_t node = maple::addr(ma_root);
        int ntype = maple::type(ma_root);
        return walk_maple_node_openssl(vmi, ctx, node, ntype, ko, 0);
    }

    /* Single-entry tree: ma_root is a direct VMA pointer */
    return check_leaf_vma_openssl(vmi, ctx, ma_root, ko);
}


/* ---------- Process enumeration callback ---------- */

struct libssl_match
{
    addr_t lib_base;
    addr_t dtb;
    vmi_pid_t pid;
};

struct libssl_search_ctx
{
    const size_t* kern_offsets;
    std::vector<libssl_match> matches;
};

/* OpenSSL-specific search context (same structure, different callback) */
struct openssl_search_ctx
{
    const size_t* kern_offsets;
    std::vector<libssl_match> matches;
};

static void find_libssl_process_cb(drakvuf_t drakvuf, addr_t process, void* data)
{
    auto search = static_cast<libssl_search_ctx*>(data);
    const size_t* ko = search->kern_offsets;

    vmi_pid_t pid = 0;
    if (!drakvuf_get_process_pid(drakvuf, process, &pid))
        return;
    if (pid <= 1)
        return;  /* skip idle/swapper (0) and init (1) */

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    /*
     * Use pid=0 (kernel page table) for all reads. Kernel structures
     * (task_struct, mm_struct, vm_area_struct, dentry) are all in kernel
     * virtual address space and accessible via the kernel DTB.
     */
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .pid = 0
    );

    /* Read task_struct.mm (skip kernel threads with NULL mm) */
    addr_t mm = 0;
    ctx.addr = process + ko[KERN_TASK_STRUCT_MM];
    if (VMI_SUCCESS != vmi_read_addr(vmi, &ctx, &mm) || !mm)
    {
        drakvuf_release_vmi(drakvuf);
        return;
    }

    /* Read mm->mm_mt.ma_root (mm_mt is embedded at offset 64, ma_root at +8) */
    uint64_t ma_root = 0;
    ctx.addr = mm + maple::MM_MT_OFFSET + maple::MT_MA_ROOT;
    if (VMI_SUCCESS != vmi_read_64(vmi, &ctx, &ma_root) || !ma_root)
    {
        drakvuf_release_vmi(drakvuf);
        return;
    }

    addr_t base = walk_maple_tree(vmi, &ctx, ma_root, ko);

    if (base)
    {
        /*
         * Compute DTB from mm->pgd. The pgd field is a kernel virtual address.
         * Convert it to a physical address using vmi_translate_kv2p() -- this
         * gives us the CR3 value needed for breakpoint setup.
         */
        addr_t pgd_virt = 0;
        ctx.addr = mm + ko[KERN_MM_STRUCT_PGD];
        if (VMI_SUCCESS == vmi_read_addr(vmi, &ctx, &pgd_virt) && pgd_virt)
        {
            addr_t pgd_phys = 0;
            if (VMI_SUCCESS == vmi_translate_kv2p(vmi, pgd_virt, &pgd_phys) && pgd_phys)
            {
                search->matches.push_back({base, pgd_phys, pid});
                PRINT_DEBUG("[TLSMON-LINUX] Found libssl.so at 0x%" PRIx64 " in pid %d (DTB=0x%" PRIx64 ")\n",
                    base, pid, pgd_phys);
            }
        }
    }

    drakvuf_release_vmi(drakvuf);
}

/*
 * OpenSSL 3.x process enumeration callback.
 * Looks for libssl.so.3* instead of libssl.so (BoringSSL).
 */
static void find_openssl_process_cb(drakvuf_t drakvuf, addr_t process, void* data)
{
    auto search = static_cast<openssl_search_ctx*>(data);
    const size_t* ko = search->kern_offsets;

    vmi_pid_t pid = 0;
    if (!drakvuf_get_process_pid(drakvuf, process, &pid))
        return;
    if (pid <= 1)
        return;  /* skip idle/swapper (0) and init (1) */

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .pid = 0
    );

    /* Read task_struct.mm (skip kernel threads with NULL mm) */
    addr_t mm = 0;
    ctx.addr = process + ko[KERN_TASK_STRUCT_MM];
    if (VMI_SUCCESS != vmi_read_addr(vmi, &ctx, &mm) || !mm)
    {
        drakvuf_release_vmi(drakvuf);
        return;
    }

    /* Read mm->mm_mt.ma_root */
    uint64_t ma_root = 0;
    ctx.addr = mm + maple::MM_MT_OFFSET + maple::MT_MA_ROOT;
    if (VMI_SUCCESS != vmi_read_64(vmi, &ctx, &ma_root) || !ma_root)
    {
        drakvuf_release_vmi(drakvuf);
        return;
    }

    /* Use OpenSSL-specific maple tree walk */
    addr_t base = walk_maple_tree_openssl(vmi, &ctx, ma_root, ko);

    if (base)
    {
        addr_t pgd_virt = 0;
        ctx.addr = mm + ko[KERN_MM_STRUCT_PGD];
        if (VMI_SUCCESS == vmi_read_addr(vmi, &ctx, &pgd_virt) && pgd_virt)
        {
            addr_t pgd_phys = 0;
            if (VMI_SUCCESS == vmi_translate_kv2p(vmi, pgd_virt, &pgd_phys) && pgd_phys)
            {
                search->matches.push_back({base, pgd_phys, pid});
                PRINT_DEBUG("[TLSMON-LINUX] Found libssl.so.3 (OpenSSL) at 0x%" PRIx64 " in pid %d (DTB=0x%" PRIx64 ")\n",
                    base, pid, pgd_phys);
            }
        }
    }

    drakvuf_release_vmi(drakvuf);
}


/* ---------- Hook callback ---------- */

event_response_t linux_tlsmon::ssl_log_secret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<linux_tlsmon>(info);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    );

    auto vmi = vmi_lock_guard(drakvuf);

    /* rdi = SSL *ssl, rsi = label string, rdx = secret data ptr, rcx = secret size */
    addr_t ssl_ptr = info->regs->rdi;
    addr_t label_addr = info->regs->rsi;
    addr_t secret_data = info->regs->rdx;
    uint64_t secret_size = info->regs->rcx;

    /* Read the label string from guest memory */
    char label_buf[MAX_LABEL_SZ] = {};
    ctx.addr = label_addr;
    if (VMI_SUCCESS != vmi_read(vmi, &ctx, sizeof(label_buf) - 1, label_buf, nullptr))
        return VMI_EVENT_RESPONSE_NONE;
    label_buf[sizeof(label_buf) - 1] = '\0';
    std::string label(label_buf);

    /* Validate secret size */
    if (secret_size == 0 || secret_size > MAX_SECRET_SZ)
        return VMI_EVENT_RESPONSE_NONE;

    /* Read the secret bytes from guest memory */
    std::vector<unsigned char> secret_bytes(secret_size);
    ctx.addr = secret_data;
    if (VMI_SUCCESS != vmi_read(vmi, &ctx, secret_size, secret_bytes.data(), nullptr))
        return VMI_EVENT_RESPONSE_NONE;

    /* Read client_random: ssl->s3->client_random (two pointer hops) */
    std::string client_random_str = plugin->read_client_random(drakvuf, info, ssl_ptr);
    if (client_random_str.empty())
        return VMI_EVENT_RESPONSE_NONE;

    std::string secret_str = byte2str(secret_bytes.data(), secret_size);

    fmt::print(plugin->m_output_format, "tlsmon", drakvuf, info,
        keyval("label", fmt::Qstr(label)),
        keyval("client_random", fmt::Qstr(client_random_str)),
        keyval("secret", fmt::Qstr(secret_str))
    );

    return VMI_EVENT_RESPONSE_NONE;
}


/* ---------- Client random extraction ---------- */

std::string linux_tlsmon::read_client_random(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t ssl_ptr)
{
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    );

    auto vmi = vmi_lock_guard(drakvuf);

    /* Read ssl->s3 pointer */
    addr_t s3_ptr = 0;
    ctx.addr = ssl_ptr + this->ssl_offsets[SSL_ST_S3];
    if (VMI_SUCCESS != vmi_read_addr(vmi, &ctx, &s3_ptr) || !s3_ptr)
        return {};

    /* Read s3->client_random (32 bytes inline) */
    unsigned char client_random[CLIENT_RANDOM_SZ] = {};
    ctx.addr = s3_ptr + this->ssl_offsets[SSL3_STATE_CLIENT_RANDOM];
    if (VMI_SUCCESS != vmi_read(vmi, &ctx, CLIENT_RANDOM_SZ, client_random, nullptr))
        return {};

    return byte2str(client_random, CLIENT_RANDOM_SZ);
}

/*
 * Read client_random from OpenSSL 3.x ssl_connection_st struct.
 * OpenSSL 3.x uses ssl_connection_st instead of ssl_st, with similar layout.
 */
std::string linux_tlsmon::read_openssl_client_random(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t ssl_conn_ptr)
{
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    );

    auto vmi = vmi_lock_guard(drakvuf);

    /* Read ssl_connection->s3 pointer */
    addr_t s3_ptr = 0;
    ctx.addr = ssl_conn_ptr + this->openssl_offsets[OPENSSL_SSL_CONNECTION_S3];
    if (VMI_SUCCESS != vmi_read_addr(vmi, &ctx, &s3_ptr) || !s3_ptr)
        return {};

    /* Read s3->client_random (32 bytes inline) */
    unsigned char client_random[CLIENT_RANDOM_SZ] = {};
    ctx.addr = s3_ptr + this->openssl_offsets[OPENSSL_SSL3_STATE_CLIENT_RANDOM];
    if (VMI_SUCCESS != vmi_read(vmi, &ctx, CLIENT_RANDOM_SZ, client_random, nullptr))
        return {};

    return byte2str(client_random, CLIENT_RANDOM_SZ);
}


/* ---------- OpenSSL 3.x hook callback ---------- */

/*
 * OpenSSL 3.x keylog callback. Supports two function signatures:
 *
 * 1. nss_keylog_int (preferred, used by LTO builds like RHEL/AlmaLinux):
 *    x86_64 SysV ABI:
 *      rdi = const char *prefix (label)
 *      rsi = SSL *ssl (unused)
 *      rdx = const uint8_t *client_random
 *      rcx = size_t client_random_len (typically 32)
 *      r8  = const uint8_t *secret
 *      r9  = size_t secret_len
 *
 * 2. ssl_log_secret (fallback):
 *    x86_64 SysV ABI:
 *      rdi = SSL_CONNECTION *s
 *      rsi = const char *label
 *      rdx = const uint8_t *secret
 *      rcx = size_t secret_len
 *    (requires struct traversal to read client_random)
 */
event_response_t linux_tlsmon::openssl_ssl_log_secret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<linux_tlsmon>(info);

    PRINT_DEBUG("[TLSMON-LINUX] OpenSSL callback fired! RIP=0x%" PRIx64 " PID=%d\n",
        info->regs->rip, info->proc_data.pid);
    PRINT_DEBUG("[TLSMON-LINUX]   rdi=0x%" PRIx64 " rsi=0x%" PRIx64 " rdx=0x%" PRIx64 "\n",
        info->regs->rdi, info->regs->rsi, info->regs->rdx);
    PRINT_DEBUG("[TLSMON-LINUX]   rcx=0x%" PRIx64 " r8=0x%" PRIx64 " r9=0x%" PRIx64 "\n",
        info->regs->rcx, info->regs->r8, info->regs->r9);

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3
    );

    auto vmi = vmi_lock_guard(drakvuf);

    std::string label;
    std::string client_random_str;
    std::string secret_str;

    if (plugin->openssl_use_nss_keylog_int_)
    {
        /* nss_keylog_int mode: all data passed as direct parameters */
        addr_t label_addr = info->regs->rdi;
        addr_t client_random_ptr = info->regs->rdx;
        uint64_t client_random_len = info->regs->rcx;
        addr_t secret_ptr = info->regs->r8;
        uint64_t secret_len = info->regs->r9;

        /* Read the label string */
        char label_buf[MAX_LABEL_SZ] = {};
        ctx.addr = label_addr;
        if (VMI_SUCCESS != vmi_read(vmi, &ctx, sizeof(label_buf) - 1, label_buf, nullptr))
        {
            PRINT_DEBUG("[TLSMON-LINUX] Failed to read label at 0x%" PRIx64 "\n", label_addr);
            return VMI_EVENT_RESPONSE_NONE;
        }
        label_buf[sizeof(label_buf) - 1] = '\0';
        label = label_buf;
        PRINT_DEBUG("[TLSMON-LINUX] Label: %s\n", label.c_str());

        /* Validate lengths */
        if (client_random_len != 32 || secret_len == 0 || secret_len > MAX_SECRET_SZ)
        {
            PRINT_DEBUG("[TLSMON-LINUX] Invalid lengths: cr_len=%" PRIu64 " secret_len=%" PRIu64 "\n",
                client_random_len, secret_len);
            return VMI_EVENT_RESPONSE_NONE;
        }

        /* Read client_random (direct parameter) */
        unsigned char client_random[32];
        ctx.addr = client_random_ptr;
        if (VMI_SUCCESS != vmi_read(vmi, &ctx, 32, client_random, nullptr))
        {
            PRINT_DEBUG("[TLSMON-LINUX] Failed to read client_random at 0x%" PRIx64 "\n", client_random_ptr);
            return VMI_EVENT_RESPONSE_NONE;
        }
        client_random_str = byte2str(client_random, 32);

        /* Read secret bytes (direct parameter) */
        std::vector<unsigned char> secret_bytes(secret_len);
        ctx.addr = secret_ptr;
        if (VMI_SUCCESS != vmi_read(vmi, &ctx, secret_len, secret_bytes.data(), nullptr))
        {
            PRINT_DEBUG("[TLSMON-LINUX] Failed to read secret at 0x%" PRIx64 "\n", secret_ptr);
            return VMI_EVENT_RESPONSE_NONE;
        }
        secret_str = byte2str(secret_bytes.data(), secret_len);
    }
    else
    {
        /* ssl_log_secret mode: need to traverse struct for client_random */
        addr_t ssl_conn_ptr = info->regs->rdi;
        addr_t label_addr = info->regs->rsi;
        addr_t secret_ptr = info->regs->rdx;
        uint64_t secret_len = info->regs->rcx;

        /* Read the label string */
        char label_buf[MAX_LABEL_SZ] = {};
        ctx.addr = label_addr;
        if (VMI_SUCCESS != vmi_read(vmi, &ctx, sizeof(label_buf) - 1, label_buf, nullptr))
        {
            PRINT_DEBUG("[TLSMON-LINUX] ssl_log_secret: Failed to read label at 0x%" PRIx64 "\n", label_addr);
            return VMI_EVENT_RESPONSE_NONE;
        }
        label_buf[sizeof(label_buf) - 1] = '\0';
        label = label_buf;
        PRINT_DEBUG("[TLSMON-LINUX] ssl_log_secret: Label: %s\n", label.c_str());

        /* Validate secret length */
        if (secret_len == 0 || secret_len > MAX_SECRET_SZ)
        {
            PRINT_DEBUG("[TLSMON-LINUX] ssl_log_secret: Invalid secret_len=%" PRIu64 "\n", secret_len);
            return VMI_EVENT_RESPONSE_NONE;
        }

        /* Read the secret bytes */
        std::vector<unsigned char> secret_bytes(secret_len);
        ctx.addr = secret_ptr;
        if (VMI_SUCCESS != vmi_read(vmi, &ctx, secret_len, secret_bytes.data(), nullptr))
        {
            PRINT_DEBUG("[TLSMON-LINUX] ssl_log_secret: Failed to read secret at 0x%" PRIx64 "\n", secret_ptr);
            return VMI_EVENT_RESPONSE_NONE;
        }
        secret_str = byte2str(secret_bytes.data(), secret_len);

        /* Read client_random from ssl_connection_st->s3->client_random */
        client_random_str = plugin->read_openssl_client_random(drakvuf, info, ssl_conn_ptr);
        if (client_random_str.empty())
        {
            PRINT_DEBUG("[TLSMON-LINUX] ssl_log_secret: Failed to read client_random from struct\n");
            return VMI_EVENT_RESPONSE_NONE;
        }
    }

    fmt::print(plugin->m_output_format, "tlsmon", drakvuf, info,
        keyval("library", fmt::Qstr("openssl")),
        keyval("label", fmt::Qstr(label)),
        keyval("client_random", fmt::Qstr(client_random_str)),
        keyval("secret", fmt::Qstr(secret_str))
    );

    return VMI_EVENT_RESPONSE_NONE;
}


/* ---------- Deferred re-scan via entry_SYSCALL_64 ---------- */

/*
 * This callback fires on every syscall (~126/sec). After sufficient events
 * (giving injected processes time to load libssl.so), it re-scans physical
 * memory for new ssl_log_secret pages and hooks them.
 */
event_response_t linux_tlsmon::deferred_scan_trigger_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<linux_tlsmon>(info);

    if (plugin->deferred_scan_done_)
        return VMI_EVENT_RESPONSE_NONE;

    plugin->deferred_scan_counter_++;

    /* Wait ~32 seconds (4000 events at ~126/sec) before scanning */
    if (plugin->deferred_scan_counter_ < 4000)
        return VMI_EVENT_RESPONSE_NONE;

    plugin->deferred_scan_done_ = true;
    plugin->run_deferred_scan(drakvuf);

    return VMI_EVENT_RESPONSE_NONE;
}

void linux_tlsmon::run_deferred_scan(drakvuf_t drakvuf)
{
    /* Run deferred scan for BoringSSL if enabled */
    if (this->boringssl_ref_bytes_len_ > 0)
    {
        addr_t page_offset = this->ssl_log_secret_rva & 0xFFF;

        PRINT_DEBUG("[TLSMON-LINUX] Deferred scan: re-scanning physical memory for new ssl_log_secret pages (BoringSSL)\n");

        /* Collect existing hooked PAs from setup phase */
        std::vector<addr_t> existing_pas;
        {
            vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

            /* Re-verify first hooked PA to get the set */
            libssl_search_ctx search = {
                .kern_offsets = this->kern_offsets.data(),
                .matches = {}
            };

            /* Enumerate processes to find all current libssl.so mappings */
            drakvuf_release_vmi(drakvuf);
            drakvuf_enumerate_processes(drakvuf, find_libssl_process_cb, &search);

            vmi = drakvuf_lock_and_get_vmi(drakvuf);
            for (const auto& match : search.matches)
            {
                addr_t func_va = match.lib_base + this->ssl_log_secret_rva;
                addr_t pa = 0;
                addr_t pid_dtb = 0;
                if (VMI_SUCCESS == vmi_pid_to_dtb(vmi, match.pid, &pid_dtb))
                    vmi_pagetable_lookup(vmi, pid_dtb, func_va, &pa);
                if (pa)
                    existing_pas.push_back(pa);
            }
            drakvuf_release_vmi(drakvuf);
        }

        this->scan_physical_memory_for_hooks(
            drakvuf, this->boringssl_ref_bytes_, this->boringssl_ref_bytes_len_, page_offset,
            existing_pas, ssl_log_secret_cb, "ssl_log_secret");
    }

    /* Run deferred scan for OpenSSL if enabled */
    if (this->openssl_ref_bytes_len_ > 0)
    {
        addr_t page_offset = this->openssl_hook_rva_ & 0xFFF;

        PRINT_DEBUG("[TLSMON-LINUX] Deferred scan: re-scanning physical memory for OpenSSL hook pages\n");

        std::vector<addr_t> existing_pas;
        int new_hooks = this->scan_physical_memory_for_hooks(
            drakvuf, this->openssl_ref_bytes_, this->openssl_ref_bytes_len_, page_offset,
            existing_pas, openssl_ssl_log_secret_cb, "openssl_ssl_log_secret");

        if (new_hooks > 0)
        {
            PRINT_DEBUG("[TLSMON-LINUX] Deferred scan placed %d new OpenSSL hooks\n", new_hooks);
        }
    }
}


/* ---------- Physical memory scan ---------- */

/*
 * Scan ALL guest physical memory for pages containing the target function.
 *
 * This solves the demand-paging + multiple filesystem copies problem:
 * even if no process has a PTE for a particular libssl.so copy's
 * ssl_log_secret page, the page may exist in the kernel's page cache.
 *
 * We scan every physical page at the target function's page offset
 * (RVA & 0xFFF), comparing against reference bytes from a known-good
 * copy. With 32 bytes of reference, false positive probability is ~10^-77.
 *
 * New matches are hooked via LOOKUP_NONE (direct PA breakpoint).
 */
int linux_tlsmon::scan_physical_memory_for_hooks(
    drakvuf_t drakvuf,
    const unsigned char* ref_bytes, size_t ref_len,
    addr_t page_offset,
    std::vector<addr_t>& hooked_pas,
    event_response_t (*callback)(drakvuf_t, drakvuf_trap_info_t*),
    const char* trap_name)
{
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    uint64_t memsize = vmi_get_memsize(vmi);

    /*
     * Optimized scan using chunked reads. Instead of one vmi_read_pa per
     * 4KB page (~750K hypercalls for 3GB), read 1MB chunks (~3K hypercalls).
     */
    constexpr size_t CHUNK_SIZE = 1024 * 1024;
    constexpr size_t PAGE_SIZE = 4096;
    auto chunk = std::make_unique<unsigned char[]>(CHUNK_SIZE);

    std::vector<addr_t> new_pas;

    for (uint64_t base = 0; base < memsize; base += CHUNK_SIZE)
    {
        size_t to_read = CHUNK_SIZE;
        if (base + to_read > memsize)
            to_read = memsize - base;

        size_t actually_read = 0;
        if (VMI_SUCCESS != vmi_read_pa(vmi, base, to_read, chunk.get(), &actually_read))
        {
            /* Chunk read failed -- fall back to page-by-page for this range */
            for (addr_t pa = base + page_offset; pa < base + to_read; pa += PAGE_SIZE)
            {
                unsigned char buf[64] = {};
                if (VMI_SUCCESS != vmi_read_pa(vmi, pa, ref_len, buf, nullptr))
                    continue;
                if (memcmp(buf, ref_bytes, ref_len) != 0)
                    continue;

                addr_t gfn = pa >> 12;
                bool already_hooked = false;
                for (addr_t existing : hooked_pas)
                    if ((existing >> 12) == gfn) { already_hooked = true; break; }

                if (!already_hooked)
                    new_pas.push_back(pa);
            }
            continue;
        }

        /* Scan within the chunk at every page_offset stride */
        for (size_t off = page_offset; off < actually_read; off += PAGE_SIZE)
        {
            if (off + ref_len > actually_read)
                break;

            if (memcmp(chunk.get() + off, ref_bytes, ref_len) != 0)
                continue;

            addr_t pa = base + off;
            addr_t gfn = pa >> 12;
            bool already_hooked = false;
            for (addr_t existing : hooked_pas)
            {
                if ((existing >> 12) == gfn)
                {
                    already_hooked = true;
                    break;
                }
            }

            if (!already_hooked)
                new_pas.push_back(pa);
        }
    }

    drakvuf_release_vmi(drakvuf);

    /* Place breakpoints on new PAs using LOOKUP_NONE (direct PA) */
    int hooks_added = 0;
    for (addr_t pa : new_pas)
    {
        auto trap = this->register_trap(
            nullptr,
            callback,
            [pa](drakvuf_t drak, drakvuf_trap_info_t*, drakvuf_trap_t* t) -> bool {
                t->type = BREAKPOINT;
                t->breakpoint.lookup_type = LOOKUP_NONE;
                t->breakpoint.addr = pa;
                return drakvuf_add_trap(drak, t);
            },
            trap_name
        );

        if (trap)
        {
            hooked_pas.push_back(pa);
            hooks_added++;
            PRINT_DEBUG("[TLSMON-LINUX] Physical scan: hook placed at PA 0x%" PRIx64 "\n", pa);
        }
    }

    return hooks_added;
}


/* ---------- Hook setup ---------- */

bool linux_tlsmon::setup_libssl_hook(drakvuf_t drakvuf)
{
    libssl_search_ctx search = {
        .kern_offsets = this->kern_offsets.data(),
        .matches = {}
    };
    drakvuf_enumerate_processes(drakvuf, find_libssl_process_cb, &search);

    if (search.matches.empty())
    {
        PRINT_DEBUG("[TLSMON-LINUX] No process with libssl.so found\n");
        return false;
    }

    PRINT_DEBUG("[TLSMON-LINUX] Found %zu processes with libssl.so\n", search.matches.size());

    /*
     * Android has multiple copies of libssl.so (system, vendor, APEX/Conscrypt).
     * Each copy maps to different physical pages even if the content is identical.
     *
     * Set a breakpoint on each UNIQUE physical address backing ssl_log_secret.
     * Uses LOOKUP_PID to resolve VA->PA via LibVMI's vmi_pid_to_dtb().
     * If two processes share the same physical page, we skip duplicates.
     */
    std::vector<addr_t> hooked_pas;
    int hooks_placed = 0;

    for (const auto& match : search.matches)
    {
        addr_t func_va = match.lib_base + this->ssl_log_secret_rva;

        /* Translate VA->PA to check for duplicates */
        vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
        addr_t pa = 0;
        addr_t pid_dtb = 0;
        if (VMI_SUCCESS == vmi_pid_to_dtb(vmi, match.pid, &pid_dtb))
            vmi_pagetable_lookup(vmi, pid_dtb, func_va, &pa);
        if (!pa)
            vmi_pagetable_lookup(vmi, match.dtb, func_va, &pa);
        drakvuf_release_vmi(drakvuf);

        if (!pa)
            continue;

        /* Skip if we already have a breakpoint on this physical page */
        bool duplicate = false;
        for (addr_t existing_pa : hooked_pas)
        {
            if ((existing_pa >> 12) == (pa >> 12))
            {
                duplicate = true;
                break;
            }
        }
        if (duplicate)
            continue;

        vmi_pid_t hook_pid = match.pid;
        auto trap = this->register_trap(
            nullptr,
            ssl_log_secret_cb,
            [hook_pid, func_va](drakvuf_t drak, drakvuf_trap_info_t*, drakvuf_trap_t* t) -> bool {
                t->type = BREAKPOINT;
                t->breakpoint.lookup_type = LOOKUP_PID;
                t->breakpoint.pid = hook_pid;
                t->breakpoint.addr_type = ADDR_VA;
                t->breakpoint.addr = func_va;
                return drakvuf_add_trap(drak, t);
            },
            "ssl_log_secret"
        );

        if (trap)
        {
            hooked_pas.push_back(pa);
            hooks_placed++;
            PRINT_DEBUG("[TLSMON-LINUX] Hook %d placed at PA 0x%" PRIx64 " (pid %d, VA 0x%" PRIx64 ")\n",
                hooks_placed, pa, hook_pid, func_va);
        }
    }

    PRINT_DEBUG("[TLSMON-LINUX] Phase 1: %d ssl_log_secret hooks on %d unique pages\n",
        hooks_placed, (int)hooked_pas.size());

    /*
     * Phase 2: Scan guest physical memory for additional ssl_log_secret pages.
     *
     * On Android, libssl.so exists as multiple filesystem copies (system,
     * vendor, APEX/Conscrypt). Each maps to different physical pages.
     * Scanning physical memory finds ALL cached copies, regardless of
     * per-process page tables.
     */
    if (!hooked_pas.empty())
    {
        constexpr size_t REF_BYTES_LEN = 32;
        {
            vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
            vmi_read_pa(vmi, hooked_pas[0], REF_BYTES_LEN, this->boringssl_ref_bytes_, nullptr);
            this->boringssl_ref_bytes_len_ = REF_BYTES_LEN;
            drakvuf_release_vmi(drakvuf);
        }

        addr_t page_offset = this->ssl_log_secret_rva & 0xFFF;
        int scan_hooks = this->scan_physical_memory_for_hooks(
            drakvuf, this->boringssl_ref_bytes_, this->boringssl_ref_bytes_len_, page_offset,
            hooked_pas, ssl_log_secret_cb, "ssl_log_secret");
        hooks_placed += scan_hooks;

        PRINT_DEBUG("[TLSMON-LINUX] Total ssl_log_secret hooks after scan: %d\n", hooks_placed);
    }

    return hooks_placed > 0;
}


/* ---------- OpenSSL 3.x hook setup ---------- */

/*
 * Setup hooks for OpenSSL 3.x ssl_log_secret function.
 *
 * OpenSSL 3.x uses libssl.so.3.x.x (soname libssl.so.3).
 * The internal ssl_log_secret() function has the same purpose as BoringSSL's
 * but is in a different library with different struct layouts.
 */
bool linux_tlsmon::setup_openssl_hook(drakvuf_t drakvuf)
{
    openssl_search_ctx search = {
        .kern_offsets = this->kern_offsets.data(),
        .matches = {}
    };
    drakvuf_enumerate_processes(drakvuf, find_openssl_process_cb, &search);

    if (search.matches.empty())
    {
        PRINT_DEBUG("[TLSMON-LINUX] No process with libssl.so.3 (OpenSSL) found\n");

        /* If we have a host libssl path, read reference bytes from file and scan physical memory */
        if (!this->openssl_libssl_path_.empty())
        {
            PRINT_DEBUG("[TLSMON-LINUX] Attempting direct physical scan using host library: %s\n",
                this->openssl_libssl_path_.c_str());

            /* Read reference bytes from host file at the hook RVA offset */
            FILE* f = fopen(this->openssl_libssl_path_.c_str(), "rb");
            if (!f)
            {
                PRINT_DEBUG("[TLSMON-LINUX] Failed to open host library file\n");
                return false;
            }

            constexpr size_t REF_BYTES_LEN = 32;
            if (fseek(f, this->openssl_hook_rva_, SEEK_SET) != 0)
            {
                PRINT_DEBUG("[TLSMON-LINUX] Failed to seek to RVA 0x%" PRIx64 " in host library\n",
                    this->openssl_hook_rva_);
                fclose(f);
                return false;
            }

            size_t read = fread(this->openssl_ref_bytes_, 1, REF_BYTES_LEN, f);
            fclose(f);

            if (read != REF_BYTES_LEN)
            {
                PRINT_DEBUG("[TLSMON-LINUX] Failed to read %zu bytes at RVA 0x%" PRIx64 " (got %zu)\n",
                    REF_BYTES_LEN, this->openssl_hook_rva_, read);
                return false;
            }

            this->openssl_ref_bytes_len_ = REF_BYTES_LEN;
            PRINT_DEBUG("[TLSMON-LINUX] Read %zu reference bytes from host library at offset 0x%" PRIx64 "\n",
                REF_BYTES_LEN, this->openssl_hook_rva_);

            /* Scan physical memory for matching pages */
            addr_t page_offset = this->openssl_hook_rva_ & 0xFFF;
            std::vector<addr_t> hooked_pas;

            int hooks_placed = this->scan_physical_memory_for_hooks(
                drakvuf, this->openssl_ref_bytes_, this->openssl_ref_bytes_len_,
                page_offset, hooked_pas, openssl_ssl_log_secret_cb, "openssl_ssl_log_secret");

            PRINT_DEBUG("[TLSMON-LINUX] Direct physical scan found %d matching pages\n", hooks_placed);
            return hooks_placed > 0;
        }

        return false;
    }

    PRINT_DEBUG("[TLSMON-LINUX] Found %zu processes with libssl.so.3 (OpenSSL)\n", search.matches.size());

    std::vector<addr_t> hooked_pas;
    int hooks_placed = 0;

    for (const auto& match : search.matches)
    {
        addr_t func_va = match.lib_base + this->openssl_hook_rva_;

        /* Translate VA->PA to check for duplicates */
        vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
        addr_t pa = 0;
        addr_t pid_dtb = 0;
        if (VMI_SUCCESS == vmi_pid_to_dtb(vmi, match.pid, &pid_dtb))
            vmi_pagetable_lookup(vmi, pid_dtb, func_va, &pa);
        if (!pa)
            vmi_pagetable_lookup(vmi, match.dtb, func_va, &pa);
        drakvuf_release_vmi(drakvuf);

        if (!pa)
            continue;

        /* Skip if we already have a breakpoint on this physical page */
        bool duplicate = false;
        for (addr_t existing_pa : hooked_pas)
        {
            if ((existing_pa >> 12) == (pa >> 12))
            {
                duplicate = true;
                break;
            }
        }
        if (duplicate)
            continue;

        vmi_pid_t hook_pid = match.pid;
        auto trap = this->register_trap(
            nullptr,
            openssl_ssl_log_secret_cb,
            [hook_pid, func_va](drakvuf_t drak, drakvuf_trap_info_t*, drakvuf_trap_t* t) -> bool {
                t->type = BREAKPOINT;
                t->breakpoint.lookup_type = LOOKUP_PID;
                t->breakpoint.pid = hook_pid;
                t->breakpoint.addr_type = ADDR_VA;
                t->breakpoint.addr = func_va;
                return drakvuf_add_trap(drak, t);
            },
            "openssl_ssl_log_secret"
        );

        if (trap)
        {
            hooked_pas.push_back(pa);
            hooks_placed++;
            PRINT_DEBUG("[TLSMON-LINUX] OpenSSL hook %d placed at PA 0x%" PRIx64 " (pid %d, VA 0x%" PRIx64 ")\n",
                hooks_placed, pa, hook_pid, func_va);
        }
    }

    PRINT_DEBUG("[TLSMON-LINUX] OpenSSL: %d ssl_log_secret hooks on %d unique pages\n",
        hooks_placed, (int)hooked_pas.size());

    /* Store reference bytes for potential future scanning */
    if (!hooked_pas.empty())
    {
        constexpr size_t REF_BYTES_LEN = 32;
        vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
        vmi_read_pa(vmi, hooked_pas[0], REF_BYTES_LEN, this->openssl_ref_bytes_, nullptr);
        this->openssl_ref_bytes_len_ = REF_BYTES_LEN;
        drakvuf_release_vmi(drakvuf);
    }

    return hooks_placed > 0;
}


/* ---------- Constructor ---------- */

linux_tlsmon::linux_tlsmon(drakvuf_t drakvuf, const tlsmon_config* config, output_format_t output)
    : pluginex(drakvuf, output)
    , ssl_offsets{}
    , ssl_log_secret_rva(0)
    , boringssl_ref_bytes_{}
    , boringssl_ref_bytes_len_(0)
    , openssl_offsets{}
    , openssl_hook_rva_(0)
    , openssl_use_nss_keylog_int_(false)
    , openssl_ref_bytes_{}
    , openssl_ref_bytes_len_(0)
    , openssl_enabled_(false)
    , kern_offsets{}
    , deferred_scan_counter_(0)
    , deferred_scan_done_(false)
{
    if (!config)
    {
        PRINT_DEBUG("[TLSMON-LINUX] No config provided, Linux TLS monitoring disabled\n");
        return;
    }

    bool have_boringssl = config->boringssl_profile != nullptr;
    bool have_openssl = config->openssl_profile != nullptr;

    if (!have_boringssl && !have_openssl)
    {
        PRINT_DEBUG("[TLSMON-LINUX] No TLS library profiles provided, Linux TLS monitoring disabled\n");
        return;
    }

    /* Load kernel struct offsets for VMA maple tree traversal (shared by both) */
    addr_t kern_rva[__KERN_OFFSET_MAX] = {};
    if (!drakvuf_get_kernel_struct_members_array_rva(
            drakvuf,
            kern_offset_names,
            __KERN_OFFSET_MAX,
            kern_rva))
    {
        PRINT_DEBUG("[TLSMON-LINUX] Warning: some kernel struct offsets missing\n");
    }
    for (int i = 0; i < __KERN_OFFSET_MAX; i++)
        this->kern_offsets[i] = kern_rva[i];

    /* ---- BoringSSL setup (Android/BlissOS) ---- */
    if (have_boringssl)
    {
        PRINT_DEBUG("[TLSMON-LINUX] Loading BoringSSL profile: %s\n", config->boringssl_profile);
        profile_guard profile(config->boringssl_profile);

        addr_t rva_array[__SSL_OFFSET_MAX] = {};
        if (!json_get_struct_members_array_rva(
                drakvuf, profile, ssl_offset_names, __SSL_OFFSET_MAX, rva_array))
        {
            PRINT_DEBUG("[TLSMON-LINUX] Failed to get BoringSSL struct offsets from profile\n");
        }
        else
        {
            for (int i = 0; i < __SSL_OFFSET_MAX; i++)
                this->ssl_offsets[i] = rva_array[i];

            if (!json_get_symbol_rva(drakvuf, profile, "ssl_log_secret", &this->ssl_log_secret_rva))
            {
                PRINT_DEBUG("[TLSMON-LINUX] Failed to get ssl_log_secret RVA from BoringSSL profile\n");
            }
            else
            {
                PRINT_DEBUG("[TLSMON-LINUX] BoringSSL ssl_log_secret RVA: 0x%" PRIx64 "\n", this->ssl_log_secret_rva);
                PRINT_DEBUG("[TLSMON-LINUX] BoringSSL ssl_st.s3 offset: 0x%zx\n", this->ssl_offsets[SSL_ST_S3]);
                PRINT_DEBUG("[TLSMON-LINUX] BoringSSL SSL3_STATE.client_random offset: 0x%zx\n",
                    this->ssl_offsets[SSL3_STATE_CLIENT_RANDOM]);

                this->setup_libssl_hook(drakvuf);
            }
        }
    }

    /* ---- OpenSSL 3.x setup (standard Linux distros) ---- */
    if (have_openssl)
    {
        PRINT_DEBUG("[TLSMON-LINUX] Loading OpenSSL 3.x profile: %s\n", config->openssl_profile);
        profile_guard profile(config->openssl_profile);

        /* Try nss_keylog_int first (preferred - RHEL/AlmaLinux LTO builds inline ssl_log_secret).
         * nss_keylog_int has a better signature that gives us direct parameter access:
         *   nss_keylog_int(prefix, ssl, client_random, cr_len, secret, secret_len)
         */
        bool got_hook = false;
        if (json_get_symbol_rva(drakvuf, profile, "nss_keylog_int", &this->openssl_hook_rva_))
        {
            PRINT_DEBUG("[TLSMON-LINUX] OpenSSL nss_keylog_int RVA: 0x%" PRIx64 " (preferred hook)\n",
                this->openssl_hook_rva_);
            this->openssl_use_nss_keylog_int_ = true;
            got_hook = true;
        }
        else if (json_get_symbol_rva(drakvuf, profile, "ssl_log_secret", &this->openssl_hook_rva_))
        {
            /* Fallback to ssl_log_secret - requires struct offsets to read client_random */
            PRINT_DEBUG("[TLSMON-LINUX] OpenSSL ssl_log_secret RVA: 0x%" PRIx64 " (fallback hook)\n",
                this->openssl_hook_rva_);
            this->openssl_use_nss_keylog_int_ = false;
            got_hook = true;

            /* Load struct offsets (only needed for ssl_log_secret mode) */
            addr_t rva_array[__OPENSSL_OFFSET_MAX] = {};
            if (json_get_struct_members_array_rva(
                    drakvuf, profile, openssl_offset_names, __OPENSSL_OFFSET_MAX, rva_array))
            {
                for (int i = 0; i < __OPENSSL_OFFSET_MAX; i++)
                    this->openssl_offsets[i] = rva_array[i];
                PRINT_DEBUG("[TLSMON-LINUX] OpenSSL ssl_connection_st.s3 offset: 0x%zx\n",
                    this->openssl_offsets[OPENSSL_SSL_CONNECTION_S3]);
                PRINT_DEBUG("[TLSMON-LINUX] OpenSSL ssl3_state_st.client_random offset: 0x%zx\n",
                    this->openssl_offsets[OPENSSL_SSL3_STATE_CLIENT_RANDOM]);
            }
            else
            {
                PRINT_DEBUG("[TLSMON-LINUX] Warning: Could not load OpenSSL struct offsets\n");
            }
        }

        /* Store host libssl path for direct physical memory scan */
        if (config->openssl_libssl_path)
            this->openssl_libssl_path_ = config->openssl_libssl_path;

        if (got_hook)
        {
            if (this->setup_openssl_hook(drakvuf))
                this->openssl_enabled_ = true;
        }
        else
        {
            PRINT_DEBUG("[TLSMON-LINUX] Failed to get nss_keylog_int or ssl_log_secret RVA from profile\n");
        }
    }

    /*
     * Set up deferred re-scan trigger on entry_SYSCALL_64.
     * This catches ssl_log_secret pages that are demand-paged after the
     * initial scan (e.g., from injected processes loading libssl.so).
     */
    if (this->boringssl_ref_bytes_len_ > 0 || this->openssl_ref_bytes_len_ > 0)
    {
        addr_t syscall_entry_pa = 0;
        {
            vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
            addr_t syscall_entry_va = 0;
            if (VMI_SUCCESS == vmi_get_vcpureg(vmi, &syscall_entry_va, MSR_LSTAR, 0))
                vmi_translate_kv2p(vmi, syscall_entry_va, &syscall_entry_pa);
            drakvuf_release_vmi(drakvuf);
        }

        if (syscall_entry_pa)
        {
            this->register_trap(
                nullptr,
                deferred_scan_trigger_cb,
                [syscall_entry_pa](drakvuf_t drak, drakvuf_trap_info_t*, drakvuf_trap_t* t) -> bool {
                    t->type = BREAKPOINT;
                    t->breakpoint.lookup_type = LOOKUP_NONE;
                    t->breakpoint.addr = syscall_entry_pa;
                    return drakvuf_add_trap(drak, t);
                },
                "deferred_scan_trigger"
            );
        }
    }
}
