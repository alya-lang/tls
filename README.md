# tls

[![CI](https://github.com/alya-lang/tls/actions/workflows/ci.yml/badge.svg)](https://github.com/alya-lang/tls/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/alya-lang/tls?color=blue&label=License)](LICENSE)
[![Alya](https://img.shields.io/badge/dynamic/toml?url=https%3A%2F%2Fraw.githubusercontent.com%2Falya-lang%2Ftls%2Fmain%2Falya.toml&query=%24.package.alya-version&label=Alya&color=orange&prefix=%3E%3D)](https://github.com/alya-lang/alya)
[![Package Version](https://img.shields.io/badge/dynamic/toml?url=https%3A%2F%2Fraw.githubusercontent.com%2Falya-lang%2Ftls%2Fmain%2Falya.toml&query=%24.package.version&label=Version&color=brightgreen)](alya.toml)

Native TLS and SSL client, server, certificate verification and secure networking toolkit for Alya

---

## 🌟 Features

- 🔐 **TLS Client & Server**: TCP dial with ClientHello/ServerHello negotiation (`tls_connect`), listener lifecycle with ClientHello inspection (`tls_server_accept`), and SNI-aware sessions
- ✅ **Certificate Verification**: RFC 6125 hostname matching (SAN-first, single-label wildcards), validity-window checks, SHA-256 fingerprint pinning, and `Required/Optional/None` policy modes
- 📜 **X.509 & PEM Tooling**: RFC 7468 armor parsing, DER extraction, minimal field scanner (CN, SAN, validity, serial), plus a real openssl-generated certificate vector in tests
- 🤝 **Handshake & Key Schedule**: Structurally valid ClientHello builder (SNI + ALPN extensions), ServerHello builder/parser roundtrip, `Certificate`-message chain parsing, TLS 1.2 PRF/master-secret/key-block, TLS 1.3 HKDF-Expand-Label, and Finished verify data
- 🔒 **Bulk AEAD Protection**: Suite-aware `tls_protect_aead`/`tls_unprotect_aead` dispatching AES-GCM and ChaCha20-Poly1305 from `crypto` v0.2.0, with error maps instead of throws
- 🧱 **Record Layer**: RFC 8446 framing (encode/decode/validate), 16k fragmentation, ApplicationData wrapping, and alert record builders
- ⚡ **Native C Engine**: Constant-time string comparison (anti-timing-attack), version-code ordering, shared cipher-strength policy, and **binary-safe socket send/receive** (explicit-length buffers, NUL-safe) via zero-dependency FFI
- 🔌 **Binary-First I/O**: Alya strings cannot hold NUL bytes, so every record crosses the socket as a byte array through `io/raw.alya` — string helpers are marked text-safe-only
- 🛡️ **Crypto-Backed**: Randoms, HMAC-SHA256, HKDF, SHA-256 fingerprints, and Base64 DER decoding on top of `alya-lang/crypto`

---

## 📁 Project Architecture

```
tls/
├── alya.toml               # Package manifest (depends on crypto)
├── c/
│   ├── tls.h               # Native helper declarations
│   └── tls.c               # Constant-time compare, version & cipher policy
├── src/
│   ├── lib.alya            # Public API facade & high-level constructors
│   ├── types.alya          # TlsConfig, TlsCertificate, TlsSession, TlsContext
│   ├── ffi.alya            # Native extern "C" declarations
│   ├── io/
│   │   └── raw.alya        # Binary-safe socket send/receive (NUL-safe)
│   ├── core/
│   │   ├── version.alya    # Version codes, labels, negotiation
│   │   ├── cipher.alya     # Suite registry, strength, selection
│   │   ├── protect.alya    # Suite-aware AEAD protect/unprotect
│   │   ├── record.alya     # Record framing, fragmentation, byte helpers
│   │   ├── handshake.alya  # ClientHello, ServerHello, SNI/ALPN, Finished
│   │   └── keys.alya       # PRF, master secret, key block, HKDF label
│   ├── cert/
│   │   ├── pem.alya        # PEM armor, DER extraction, fingerprints
│   │   ├── x509.alya       # Minimal DER field scanner
│   │   └── verify.alya     # Hostname, time, pinning, peer verdicts
│   ├── client/
│   │   └── client.alya     # tls_connect, tunnel I/O, mock sessions
│   └── server/
│       └── server.alya     # Listener lifecycle, hello inspection
├── examples/
│   └── demo.alya           # Comprehensive runnable walkthrough
├── tests/
│   ├── test_basic.alya     # Facade smoke tests
│   ├── test_ffi.alya       # Native engine verification
│   ├── test_version.alya   # Negotiation tests
│   ├── test_cipher.alya    # Suite selection tests
│   ├── test_protect.alya   # AEAD protect/unprotect tests
│   ├── test_record.alya    # Framing roundtrip tests
│   ├── test_handshake.alya # Hello build/parse tests
│   ├── test_keys.alya      # Key schedule tests
│   ├── test_pem.alya       # PEM parsing tests
│   ├── test_x509.alya      # Scanner + real-certificate vector
│   ├── test_verify.alya    # Hostname/time/pin tests
│   └── test_client_server.alya # Offline lifecycle tests
└── benches/
    └── bench_basic.alya    # Micro-benchmarks (negotiation → PRF)
```

> [!NOTE]
> **Scope:** `v0.1.0` negotiates versions/suites over real TCP through binary-safe I/O, parses handshake `Certificate` messages, verifies caller-supplied chains with mode enforcement, protects bulk data with negotiated AEAD (keys caller-managed via `core/keys.alya`), and shuts down cleanly with `close_notify`. Remaining: automatic chain extraction during the live handshake, server-side key exchange (ECDHE), chain building, revocation, and session resumption.
>
> [!NOTE]
> **String limitation:** Alya strings cannot hold NUL bytes, so `bytes_to_wire`/`wire_to_bytes` are text-safe-only helpers. All record transport uses byte arrays with `io/raw.alya` (`raw_send`/`raw_recv`).

---

## 📦 Installation

Add `tls` to your project's `alya.toml`:

```toml
[dependencies]
tls = { git = "https://github.com/alya-lang/tls", branch = "main" }
```

Or install it directly via the `alya` CLI:

```bash
alya add tls --git https://github.com/alya-lang/tls --branch main
alya install
```

---

## 🚀 Quick Start

### 1. Secure client config & mock session

```alya
import "tls" as tls

function main()
    let cfg = tls::config("example.com")
    say "Policy: " + tls::version_to_string(cfg.min_version) + "+"

    # Offline session (no I/O) for framing/policy flows
    let ctx = tls::tls_mock_establish(cfg)
    say tls::session_summary(ctx.session)
end

main()
```

### 2. Live negotiation (real TCP + hello exchange)

```alya
import "tls" as tls

function main()
    let cfg = tls::config("example.com", 443)
    let ctx = tls::connect(cfg)
    if ctx.is_ok() == 0
        say "Handshake failed: " + ctx.last_error
        return
    end
    say tls::session_summary(ctx.session)
    tls::close(ctx)
end

main()
```

### 3. Certificate verification with pinning

```alya
import "tls" as tls

function main()
    let cert = tls::parse_certificate_pem(read_file("server.pem"))
    let verdict = tls::verify_peer(cert, "example.com", tls::TlsVerifyMode.Required, "20260101000000Z", "ab:cd:...")
    say "Verified: " + str(verdict["ok"]) + " (" + verdict["detail"] + ")"
end

main()
```

---

## 📖 API Reference

### Facade (`src/lib.alya`)

| Function | Parameters | Description |
|---|---|---|
| `config(host, port)` | `host: string, port: int` | Secure client config (TLS 1.2+, verification required) |
| `insecure_config(host, port)` | `host: string, port: int` | Dev config without verification (never production) |
| `connect(cfg)` | `cfg: TlsConfig` | TCP dial + binary hello negotiation, never throws |
| `close(ctx)` | `ctx: TlsContext` | Sends `close_notify` (best effort), closes socket |
| `tls_verify_session(ctx, cert, now, pin)` | `ctx, cert, str, str` | Enforces verification mode, records fingerprint |
| `tls_send_data(ctx, bytes)` | `ctx, array` | NUL-safe binary send |
| `tls_recv_data(ctx, max)` | `ctx, int` | NUL-safe binary receive |
| `server(port, host)` | `port: int, host: string` | Creates TLS server listener |
| `tls_server_negotiate(srv, suites, alpn)` | `srv, array, array` | Server-side suite + ALPN selection |
| `tls_server_verify_client(srv, ctx, cert, now, pin)` | `srv, ctx, cert, str, str` | Mutual-TLS client verification |
| `version()` | — | Package version string |
| `secure_compare(a, b)` | `a, b: string` | Constant-time compare via native engine |
| `session_summary(sess)` | `sess: TlsSession` | One-line version/suite/SNI summary |

### Versions & Suites (`core/version.alya`, `core/cipher.alya`)

| Function | Parameters | Description |
|---|---|---|
| `version_negotiate(min_v, max_v, peer)` | `int, int, int` | Highest overlapping version, or 0 |
| `version_to_string(code)` | `code: int` | `"TLSv1.2"` style label |
| `version_is_secure(code)` | `code: int` | `1` for TLS 1.2/1.3 |
| `cipher_select(client, server)` | `array, array` | Strongest common suite, or 0 |
| `cipher_suite_name(suite)` | `suite: int` | IANA suite name |
| `cipher_is_aead(suite)` | `suite: int` | `1` for AEAD suites |
| `tls_protect_aead(suite, key, n12, aad, pt)` | `int, array, array, array, array` | AEAD encrypt → `ciphertext`/`tag`/`error` |
| `tls_unprotect_aead(suite, key, n12, aad, ct, tag)` | `int, array, array, array, array, array` | AEAD decrypt → `plaintext`/`error` |

### Records & Handshake (`core/record.alya`, `core/handshake.alya`, `core/keys.alya`)

| Function | Parameters | Description |
|---|---|---|
| `record_encode(type, ver, frag)` | `int, int, array` | Frames one TLS record (binary bytes) |
| `record_decode(data)` | `data: array` | Parses/validates one record |
| `tls_alert_bytes(level, desc, ver)` | `int, int, int` | 7-byte alert record for `raw_send` |
| `build_client_hello(cfg, suites)` | `cfg, array` | ClientHello with SNI/ALPN (binary bytes) |
| `parse_server_hello(body)` | `body: array` | Extracts version/random/suite |
| `build_server_hello(ver, suite, rnd, sid)` | `int, int, array, str` | ServerHello answering a ClientHello |
| `alpn_select(server, client)` | `array, array` | First overlapping protocol |
| `master_secret(pre, cli, srv)` | `array, array, array` | 48-byte TLS 1.2 master secret |
| `key_block(master, srv, cli, len)` | `array, array, array, int` | Key expansion material |
| `hkdf_expand_label(secret, label, ctx, len)` | `array, str, array, int` | TLS 1.3 key schedule step |

### Certificates (`cert/pem.alya`, `cert/x509.alya`, `cert/verify.alya`)

| Function | Parameters | Description |
|---|---|---|
| `pem_first_cert_der(pem)` | `pem: string` | DER bytes of first CERTIFICATE block |
| `parse_certificate(der)` | `der: array` | Scans CN/SAN/validity/serial/fingerprint |
| `parse_certificate_pem(pem)` | `pem: string` | PEM-to-summary shortcut |
| `parse_certificate_chain(body)` | `body: array` | Parses handshake Certificate message |
| `verify_hostname(cert, host)` | `cert, host: string` | SAN-first RFC 6125 match |
| `verify_fingerprint(cert, pin)` | `cert, pin: string` | Constant-time pin compare |
| `verify_peer(cert, host, mode, now, pin)` | `cert, host, int, str, str` | Full verdict map |

---

## 🧪 Running Tests & Benchmarks

Run all 11 test suites using `alya`:

```bash
alya test
```

Run individual test files:

```bash
alya run tests/test_x509.alya
alya run tests/test_handshake.alya
alya run tests/test_verify.alya
```

Run benchmarks:

```bash
alya run benches/bench_basic.alya
```

Run the demo example:

```bash
alya run examples/demo.alya
```

Check code formatting:

```bash
alya fmt . --check
```

Run static code linter:

```bash
alya lint . --check
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository and clone it locally
2. Install the package tools:
   ```bash
   alya install
   ```
3. Create your feature branch:
   ```bash
   git checkout -b feature/my-feature
   ```
4. Verify tests and code formatting before opening a PR:
   ```bash
   alya test
   alya fmt . --check
   ```
5. Commit your changes:
   ```bash
   git commit -m "feat: add feature description"
   ```
6. Open a Pull Request on GitHub.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
