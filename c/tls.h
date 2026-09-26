#ifndef ALYA_TLS_H
#define ALYA_TLS_H

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Constant-time string equality (timing-attack resistant).
 * Returns 1 when equal, 0 otherwise. NULL-safe (NULL == NULL). */
int alya_tls_const_eq(const char *a, const char *b);

/* Encodes a TLS version pair into a single comparable code.
 * Returns (major << 8) | minor, or -1 for out-of-range input. */
int alya_tls_version_code(int major, int minor);

/* Compares two version codes. Returns -1, 0, or 1. */
int alya_tls_version_compare(int a_code, int b_code);

/* Ranks a cipher suite id by strength:
 * 3 = modern AEAD with forward secrecy, 2 = strong CBC with PFS,
 * 1 = legacy (no PFS), 0 = unknown/weak. */
int alya_tls_cipher_strength(int suite);

/* Returns 1 when the suite is AEAD-based, 0 otherwise. */
int alya_tls_is_aead(int suite);

/* Binary-safe socket send with explicit length (NUL-safe, unlike strings).
 * Sends the full buffer unless the peer closes. Returns bytes sent or -1. */
int alya_tls_sock_send(int sock, const unsigned char *buf, int len);

/* Binary-safe socket receive into a caller buffer.
 * Returns bytes received, 0 on orderly close, or -1 on error. */
int alya_tls_sock_recv(int sock, unsigned char *buf, int max_len);

#ifdef __cplusplus
}
#endif

#endif
