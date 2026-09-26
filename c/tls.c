#include "tls.h"
#include <stddef.h>

int alya_tls_const_eq(const char *a, const char *b) {
    if (a == NULL || b == NULL) {
        return (a == b) ? 1 : 0;
    }
    /* Measure lengths without early exit. */
    size_t la = 0;
    while (a[la] != '\0') {
        la++;
    }
    size_t lb = 0;
    while (b[lb] != '\0') {
        lb++;
    }
    size_t n = (la > lb) ? la : lb;
    unsigned char diff = (unsigned char)(la ^ lb);
    size_t i = 0;
    for (i = 0; i < n; i++) {
        unsigned char ca = (i < la) ? (unsigned char)a[i] : 0;
        unsigned char cb = (i < lb) ? (unsigned char)b[i] : 0;
        diff |= (unsigned char)(ca ^ cb);
    }
    return (diff == 0) ? 1 : 0;
}

int alya_tls_version_code(int major, int minor) {
    if (major < 0 || major > 255 || minor < 0 || minor > 255) {
        return -1;
    }
    return ((major & 0xFF) << 8) | (minor & 0xFF);
}

int alya_tls_version_compare(int a_code, int b_code) {
    if (a_code < b_code) {
        return -1;
    }
    if (a_code > b_code) {
        return 1;
    }
    return 0;
}

int alya_tls_cipher_strength(int suite) {
    switch (suite) {
        /* TLS 1.3 AEAD suites. */
        case 0x1301: /* TLS_AES_128_GCM_SHA256 */
        case 0x1302: /* TLS_AES_256_GCM_SHA384 */
        case 0x1303: /* TLS_CHACHA20_POLY1305_SHA256 */
        /* ECDHE + AEAD with forward secrecy. */
        case 0xC02F: /* ECDHE-RSA-AES128-GCM-SHA256 */
        case 0xC030: /* ECDHE-RSA-AES256-GCM-SHA384 */
        case 0xCCA8: /* ECDHE-RSA-CHACHA20-POLY1305 */
            return 3;
        /* ECDHE + CBC with forward secrecy. */
        case 0xC027: /* ECDHE-RSA-AES128-SHA256 */
        case 0xC028: /* ECDHE-RSA-AES256-SHA384 */
            return 2;
        /* Legacy RSA key exchange (no forward secrecy). */
        case 0x009C: /* RSA-AES128-GCM-SHA256 */
        case 0x009D: /* RSA-AES256-GCM-SHA384 */
        case 0x003C: /* RSA-AES128-SHA256 */
            return 1;
        default:
            return 0;
    }
}

int alya_tls_is_aead(int suite) {
    switch (suite) {
        case 0x1301:
        case 0x1302:
        case 0x1303:
        case 0xC02F:
        case 0xC030:
        case 0xCCA8:
        case 0x009C:
        case 0x009D:
            return 1;
        default:
            return 0;
    }
}

int alya_tls_sock_send(int sock, const unsigned char *buf, int len) {
    int total = 0;
    if (sock < 0 || buf == NULL || len <= 0) {
        return -1;
    }
    while (total < len) {
#ifdef _WIN32
        int n = send(sock, (const char *)buf + total, len - total, 0);
#else
        ssize_t n = send(sock, buf + total, (size_t)(len - total), 0);
#endif
        if (n <= 0) {
            return (total > 0) ? total : -1;
        }
        total += n;
    }
    return total;
}

int alya_tls_sock_recv(int sock, unsigned char *buf, int max_len) {
    if (sock < 0 || buf == NULL || max_len <= 0) {
        return -1;
    }
#ifdef _WIN32
    return recv(sock, (char *)buf, max_len, 0);
#else
    {
        ssize_t n = recv(sock, buf, (size_t)max_len, 0);
        return (int)n;
    }
#endif
}
