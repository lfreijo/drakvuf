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
    const char* boringssl_profile;  // BoringSSL (Android)
    const char* openssl_profile;    // OpenSSL 3.x (standard Linux)
    const char* openssl_libssl_path; // Host path to libssl.so.3 for direct physical scan
};

class linux_tlsmon : public pluginex
{
public:
    linux_tlsmon(drakvuf_t drakvuf, const tlsmon_config* config, output_format_t output);
    ~linux_tlsmon() = default;

private:
    /* BoringSSL state (Android/BlissOS) */
    std::array<size_t, linux_tlsmon_priv::__SSL_OFFSET_MAX> ssl_offsets;
    addr_t ssl_log_secret_rva;
    unsigned char boringssl_ref_bytes_[32];
    size_t boringssl_ref_bytes_len_;

    /* OpenSSL 3.x state (standard Linux distros) */
    std::array<size_t, linux_tlsmon_priv::__OPENSSL_OFFSET_MAX> openssl_offsets;
    addr_t openssl_hook_rva_;           // RVA of hook function (nss_keylog_int or ssl_log_secret)
    bool openssl_use_nss_keylog_int_;   // true = nss_keylog_int, false = ssl_log_secret
    unsigned char openssl_ref_bytes_[32];
    size_t openssl_ref_bytes_len_;
    bool openssl_enabled_;
    std::string openssl_libssl_path_;   // Host path to libssl.so.3 for direct scan

    /* Kernel struct offsets for VMA traversal */
    std::array<size_t, linux_tlsmon_priv::__KERN_OFFSET_MAX> kern_offsets;

    /* Deferred re-scan: hooks entry_SYSCALL_64 and after N events,
     * re-scans physical memory for new ssl_log_secret pages that
     * appeared after the initial scan (e.g., from demand-paging). */
    int deferred_scan_counter_;
    bool deferred_scan_done_;

    /* BoringSSL hook setup (looks for libssl.so with ssl_log_secret) */
    bool setup_libssl_hook(drakvuf_t drakvuf);
    int scan_physical_memory_for_hooks(
        drakvuf_t drakvuf,
        const unsigned char* ref_bytes, size_t ref_len,
        addr_t page_offset,
        std::vector<addr_t>& hooked_pas,
        event_response_t (*callback)(drakvuf_t, drakvuf_trap_info_t*),
        const char* trap_name);

    /* OpenSSL 3.x hook setup (looks for libssl.so.3 with ssl_log_secret) */
    bool setup_openssl_hook(drakvuf_t drakvuf);

    /* BoringSSL callback */
    static event_response_t ssl_log_secret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

    /* OpenSSL 3.x callback */
    static event_response_t openssl_ssl_log_secret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

    static event_response_t deferred_scan_trigger_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
    void run_deferred_scan(drakvuf_t drakvuf);

    /* Read client_random from BoringSSL ssl_st struct */
    std::string read_client_random(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t ssl_ptr);

    /* Read client_random from OpenSSL ssl_connection_st struct */
    std::string read_openssl_client_random(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t ssl_conn_ptr);
};

#endif
