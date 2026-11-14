# Aether v2 (`AetherFlow-v2`) Usage Guide

Aether v2 (`"type": "aether"`) is a pure-binary proxy protocol built natively into `sing-box` for dedicated-line and cross-network transit (such as IPLC, IEPL, and cross-carrier transit). It removes outer TLS, X.509 certificates, plaintext SNI, and V2Ray transport wrappers while providing per-connection ephemeral X25519 forward secrecy, optional 0-RTT static-key PFS, hardware-accelerated AEAD framing, head-only traffic shaping, native framed UDP, and randomized stealth probe draining.

> **Breaking Change from Aether v1:** Aether v2 is wire-incompatible with Aether v1 and removes all legacy `tls`, `transport`, and `fallback` fields from `aether` inbound and outbound configurations. `sing-box check` rejects configs containing removed v1 fields.

---

## 1. Quick Overview & Architecture

- **Zero Outer TLS / Zero SNI Exposure:** Connections begin directly with an authenticated fixed-size binary prefix (`96 B` in single-user / users-only mode, `112 B` in EIH multi-user mode). There is no plaintext TLS `ClientHello`, SNI, or certificate exchange to trigger SNI allowlist filters or add a 1-RTT TLS handshake penalty.
- **Zero Length Oracle (`S-1`):** The server reads the exact fixed prefix (`96 B` or `112 B`) and verifies its ChaCha20-Poly1305 AEAD tag, timestamp window, and `SlidingBloomFilter` anti-replay state *before* reading `VarHeaderLen`.
- **0-RTT Coalesced Initial Burst:** Client handshake material, `32..384 B` CSPRNG noise padding, encoded target address, and initial application payload (`EarlyWriter`) are coalesced into a single initial write; the server coalesces its `84 B` response prefix with the first downlink frame.
- **Ephemeral X25519 + Dual-Salt Ratchet:** Both sides exchange per-connection ephemeral `X25519` public keys masked with a `ChaCha20` keystream (`HKDF-SHA256(uPSK, Salt, "AetherFlow-v2-EPK-Mask")`) to eliminate Curve25519 MSB (`bit 255 == 0`) bias, and ratchet `ClientSalt(32B) || ServerSalt(32B)` into 5 domain-separated keys (`Resp`, `C2S-Header`, `C2S-Payload`, `S2C-Header`, `S2C-Payload`).
- **Two-Block AEAD Framing & Single-Buffer Writes:** Every frame consists of an `18 B` AEAD-encrypted length header (`HeaderKey`) followed by an AEAD-encrypted body (`PayloadKey`, `PlainFrameLen` `2..16641 B`), written in one pooled `*buf.Buffer` syscall (eliminating `2-Byte` split TCP segments).
- **Head-Only Shaping (`Frame 0..5`) + Full-Speed Steady State (`Frame 6+`):** The first 6 `FrameData` frames add `16..255 B` random padding and split bursts `> 1200 B` into `512..1100 B` chunks to obscure inner TLS `ClientHello` / `Certificate` sizes. From `Frame 6` onward, `PadLen` drops to `0` (`36 B` overhead per `16384 B` payload = `0.2197% < 0.22%`).

---

## 2. Key Generation (`sing-box generate`)

Use the built-in CLI generators to create cryptographically random keys:

### 2.1 Master / User Key (`sing-box generate aether-key`)

Generates 32 CSPRNG bytes encoded with standard Base64 (`44` characters):

```bash
sing-box generate aether-key
# Example output:
# I+kceYpTKz4I80PNPTHcrWmdqDgXs8bKVjZUEgI0Igs=
```

- **Fast-path loading (`< 1 µs`):** Any strict canonical 32-byte Base64 string (`StdEncoding`, `RawStdEncoding`, `URLEncoding`, or `RawURLEncoding`, without `\r`/`\n` and not all-zeros) is decoded directly as the `256-bit` key with zero KDF overhead.
- **Passphrase fallback (`Argon2id`):** If a non-Base64-32B string is provided in `password` or `key`, it **must be at least `16` characters long**. At startup (`NewInbound` / `NewOutbound`), `sing-box` derives the 32-byte key once using `Argon2id(secret, "AetherFlow-v2-KDF", time=3, memory=64 MiB, threads=4)` (zero per-connection Argon2id cost). Empty strings, strings shorter than `16` characters, and all-zero 32-byte Base64 keys are rejected at startup.
- **`password` vs `key` Alias:** Every inbound, outbound, and user object accepts either `"password"` or `"key"` interchangeably (`option.ResolveSecret`). Setting both to different non-empty values fails validation (`conflicting password and key`).

### 2.2 Static X25519 Keypair for 0-RTT PFS (`sing-box generate aether-keypair`)

Generates a static `X25519` keypair for optional 0-RTT forward secrecy:

```bash
sing-box generate aether-keypair
# Example output:
# PrivateKey: gRfye4dDTiHX9HExpHcwIPTuhc4ENqs+HWi3ty+1t7I=
# PublicKey: ZbdxYA/fIFSV1D4b2wDqWef4REpV1nXh+agwWxA7OVg=
```

Copy the Base64 values (without the `PrivateKey: ` / `PublicKey: ` prefixes) into server `"private_key"` and client `"public_key"`.

---

## 3. Configuration Reference

### 3.1 Inbound Options (`"type": "aether"`)

```json
{
  "type": "aether",
  "tag": "aether-in",
  "listen": "::",
  "listen_port": 8443,
  "password": "<32B-base64-key-or-iPSK>",
  "users": [
    {
      "name": "alice",
      "password": "<alice-32B-base64-key>"
    }
  ],
  "private_key": "<optional-server-x25519-private-key>",
  "time_window": "30s",
  "handshake_timeout": "6s",
  "heartbeat_interval": "30s",
  "disable_shaping": false,
  "multiplex": {
    "enabled": true,
    "padding": true
  }
}
```

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| Listen fields | object | — | Standard `sing-box` `ListenOptions` (`listen`, `listen_port`, `reuse_addr`, etc.). |
| `password` / `key` | string | `""` | Shared secret in single-user mode, or server infrastructure key (`iPSK`) in EIH multi-user mode. Leave empty when using `users`-only mode. |
| `users` | array | `[]` | Multi-user list of `{ "name": string, "password"\|"key": string }`. User names and keys must be unique. |
| `private_key` | string | `""` | Optional Base64 32-byte X25519 private key enabling 0-RTT static PFS. |
| `time_window` | duration | `"30s"` | Maximum allowed `|server_now - client_timestamp|` skew. Bloom filter rotates every `2 * time_window`. |
| `handshake_timeout` | duration | `"6s"` | Read deadline for receiving the client handshake prefix and variable header. |
| `heartbeat_interval` | duration | `"30s"` | Baseline idle keepalive interval (`FramePing` sent after `0.75..1.25 * interval`). Negative value (e.g. `"-1s"`) disables keepalive. |
| `disable_shaping` | bool | `false` | Set `true` to disable first-6-frames padding and `> 1200 B` burst splitting (`PadLen = 0` from `Frame 0`). |
| `multiplex` | object | disabled | Optional `InboundMultiplexOptions` (`enabled`, `padding`, `brutal`). Required if clients enable `multiplex`. |

### 3.2 Outbound Options (`"type": "aether"`)

```json
{
  "type": "aether",
  "tag": "aether-out",
  "server": "transit.example.net",
  "server_port": 8443,
  "network": ["tcp", "udp"],
  "password": "<secret-or-iPSK:uPSK>",
  "cipher": "auto",
  "public_key": "<optional-server-x25519-public-key>",
  "heartbeat_interval": "30s",
  "disable_shaping": false,
  "multiplex": {
    "enabled": true,
    "protocol": "h2mux",
    "max_connections": 4,
    "min_streams": 4,
    "padding": true
  }
}
```

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| Dial & Server fields | object | — | Standard `sing-box` `DialerOptions` & `ServerOptions` (`server`, `server_port`, `detour`, `connect_timeout`, etc.). |
| `network` | list/string | TCP & UDP | Optional network filter: `"tcp"`, `"udp"`, or both. |
| `password` / `key` | string | **required** | `<uPSK>` (single-user or `users`-only mode) or `"<iPSK>:<uPSK>"` (EIH multi-user mode). |
| `cipher` | string | `"auto"` | Data-plane AEAD cipher: `"auto"`, `"aes-256-gcm"`, or `"chacha20-poly1305"` (case-sensitive lowercase). |
| `public_key` | string | `""` | Optional Base64 32-byte X25519 public key matching the server's `private_key`. |
| `heartbeat_interval` | duration | `"30s"` | Baseline idle keepalive interval. Negative value (e.g. `"-1s"`) disables keepalive. |
| `disable_shaping` | bool | `false` | Set `true` to disable first-6-frames padding and chunk splitting on client-to-server traffic. |
| `multiplex` | object | disabled | Optional `OutboundMultiplexOptions` (`protocol`: `h2mux` / `smux` / `yamux`, `padding`, `brutal`). Ignored if `udp_over_tcp.enabled` is `true`. |
| `udp_over_tcp` | object/bool | disabled | Optional `UDPOverTCPOptions` (`enabled`, `version`: `1` or `2`). |

---

## 4. Authentication Modes: Single-User vs Multi-User (`EIH`)

Aether v2 supports three authentication modes inferred automatically from the inbound configuration:

| Mode | Server Config | Client `password` / `key` | Wire Prefix | Lookup & Security Properties |
| --- | --- | --- | --- | --- |
| **Single-User** | `password`/`key` set, `users` empty | `<uPSK>` | `96 B` | Direct single-key ChaCha20-Poly1305 verification. |
| **Multi-User EIH** *(Recommended)* | `password`/`key` (`<iPSK>`) **and** `users` set | `<iPSK>:<uPSK>` | `112 B` | `O(1)` salted lookup (`EIH = UserID XOR HKDF(iPSK, ClientSalt, "AetherFlow-v2-EIH")`) with dummy-user fallback on miss to prevent user-existence timing leaks. |
| **Multi-User Users-Only** | `password`/`key` empty (`""`), `users` set | `<uPSK>` | `96 B` | Constant-work full scan over `users` (no early exit) with no `iPSK:` prefix needed on client. Best for small user lists. |

### Multi-User EIH + Per-User Routing Example

1. Generate one server key (`iPSK`) and one key per user (`uPSK`):
   ```bash
   sing-box generate aether-key   # iPSK -> e.g. K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=
   sing-box generate aether-key   # alice -> e.g. 9vJx8mQp2rSt5uVwXyZ1aBcDeFgHiJkLmNoPqRsTuVw=
   sing-box generate aether-key   # bob   -> e.g. M3nOpQrStUvWxYz0123456789+/AbCdEfGhIjKlMnOp=
   ```
2. **Server config** (`iPSK` + `users` + `auth_user` routing):
   ```json
   {
     "inbounds": [
       {
         "type": "aether",
         "tag": "aether-in",
         "listen": "::",
         "listen_port": 8443,
         "password": "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=",
         "users": [
           { "name": "alice", "key": "9vJx8mQp2rSt5uVwXyZ1aBcDeFgHiJkLmNoPqRsTuVw=" },
           { "name": "bob",   "key": "M3nOpQrStUvWxYz0123456789+/AbCdEfGhIjKlMnOp=" }
         ]
       }
     ],
     "route": {
       "rules": [
         { "auth_user": ["alice"], "outbound": "direct-line-a" },
         { "auth_user": ["bob"],   "outbound": "direct-line-b" }
       ]
     }
   }
   ```
3. **Client (`alice`) outbound**:
   ```json
   {
     "type": "aether",
     "tag": "aether-out",
     "server": "transit.example.net",
     "server_port": 8443,
     "key": "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=:9vJx8mQp2rSt5uVwXyZ1aBcDeFgHiJkLmNoPqRsTuVw="
   }
   ```

> **Tip:** Always use 32-byte Base64 keys (`sing-box generate aether-key`) when deploying `<iPSK>:<uPSK>` credentials. Base64 never contains `:`, preventing any colon-splitting ambiguity if a passphrase also contains colons.

---

## 5. Static X25519 0-RTT Forward Secrecy (`private_key` / `public_key`)

By default (without `private_key` / `public_key`), Aether v2 already performs a fresh ephemeral `X25519` ECDH handshake on every connection so **all server-to-client data and all subsequent client-to-server frames have full forward secrecy**. However, because the client sends its first `0-RTT` burst before receiving the server's ephemeral `epk_s`, the initial `FixedHeader` and `VarHeader` (`TargetAddr` + `InitialPayload`) are encrypted solely under `uPSK` + `ClientSalt`.

Configuring a static server `X25519` keypair upgrades the initial `0-RTT` handshake as well:

- `initKey = HKDF-SHA256(uPSK || X25519(ek_c, spk_s), ClientSalt, "AetherFlow-v2-Client-Init")`
- `masterSecret = HKDF-SHA256(uPSK || X25519(ek_c, epk_s) || X25519(ek_c, spk_s), ClientSalt || ServerSalt, "AetherFlow-v2-Session")`

**Operational rules:**
- `private_key` on the server and `public_key` on the client **must be paired**. If only one side sets a static key, or the keys do not match, handshake AEAD authentication fails and the server enters `StealthDrain`.
- `sing-box` validates static keys at startup and immediately rejects malformed Base64, all-zero scalars, and all 14 Curve25519 low-order points.

---

## 6. Cipher Selection (`auto` / `aes-256-gcm` / `chacha20-poly1305`)

Handshakes always use `ChaCha20-Poly1305` for fixed/variable/response headers. For the data plane (frame length headers and frame bodies), the client outbound selects `CipherSuite` and signals it inside `EncryptedFixedHeader`:

- **`"auto"` (default / omitted):** Probes hardware acceleration via `golang.org/x/sys/cpu`:
  - Selects **`AES-256-GCM` (`0x01`)** on CPUs with AES + carryless-multiply hardware (`X86.HasAES && X86.HasPCLMULQDQ`, `ARM64.HasAES && ARM64.HasPMULL`, or `S390X.HasAES && S390X.HasAESGCM`).
  - Selects **`ChaCha20-Poly1305` (`0x02`)** on software routers and CPUs without hardware AES-GCM (e.g., MIPS, older ARMv7, non-crypto ARM64).
- **`"aes-256-gcm"`:** Forces `AES-256-GCM` (`0x01`). Ideal for modern x86_64 and ARM64 servers on 1G–10G dedicated lines.
- **`"chacha20-poly1305"`:** Forces `ChaCha20-Poly1305` (`0x02`). Best when a client or relay lacks hardware AES instructions.

The cipher string is case-sensitive (`"auto"`, `"aes-256-gcm"`, `"chacha20-poly1305"`). Both sides may independently choose whether to set `disable_shaping` (each direction parses `PadLen` from the decrypted frame header dynamically).

---

## 7. UDP Modes: Native `CommandUDP` vs `udp_over_tcp` vs `multiplex`

Aether v2 eliminates Aether v1's `Multiplex` / `UDP` conflict and supports all three UDP transports cleanly. On the outbound, priority follows:

1. **`multiplex` (`CommandMux = 0x03`)** — active when `multiplex.enabled == true` and `udp_over_tcp.enabled != true`.
   - Multiplexes both TCP and Full-Cone UDP streams inside persistent Aether connections (`h2mux` default, `smux`, or `yamux`).
   - Requires `"multiplex": { "enabled": true }` on the server inbound (if the server has `multiplex` disabled, `CommandMux` connections are rejected cleanly).
   - **Recommended for:** High-concurrency mixed TCP/UDP workloads, browser/API bursts, and avoiding per-stream handshake latency.
2. **`udp_over_tcp` (`CommandUoT = 0x04`)** — active when `udp_over_tcp.enabled == true`.
   - Wraps UDP datagrams in SagerNet's UoT protocol (`version: 2` default, or `version: 1`) over an Aether stream.
   - Note: Enabling `udp_over_tcp` disables `multiplex` on that outbound.
   - **Recommended for:** Compatibility with explicit UoT tooling or pipelines expecting UoT v1/v2 framing.
3. **Native `CommandUDP` (`0x02`)** — active by default when both `multiplex` and `udp_over_tcp` are disabled.
   - Encodes datagrams directly as `[Socksaddr][uint16 BE PayloadLen][Payload]` inside encrypted Aether frames with zero UoT magic-address overhead.
   - Supports Full-Cone NAT (`ListenPacket`), bound UDP (`DialContext("udp", ...)`), and jumbo payloads up to `65507 B` (transparently spanning multiple `16384 B` Aether frames).
   - **Recommended for:** Direct low-latency UDP, QUIC/Hysteria2-over-Aether, gaming, or DNS transit when connection multiplexing is not needed.

---

## 8. Stealth Drain, Anti-Replay & NTP Recommendations

### 8.1 Anti-Probe Stealth Drain (`S-1`, `S-7`)

- **Concurrency & Timeout Guards:** The server bounds unauthenticated handshakes with `handshakeSem` (`256` slots) and `handshake_timeout` (default `6s`), and bounds draining sockets with a separate `drainSem` (`512` slots) so probe floods never starve valid handshakes or exhaust file descriptors.
- **No `200ms` or `TCP RST` Fingerprint:** Failed AEAD authentications, invalid header invariants, clock-skew rejections, and replay detections never emit an immediate `200ms` drop or `SetLinger(0)` `TCP RST`. Instead, the server drains incoming bytes silently for a per-connection uniform random **`3s..10s`** duration and closes via normal `TCP FIN`, emitting rate-limited warning logs per source IP.

### 8.2 Anti-Replay & Clock Synchronization (`S-5`)

- **Constant-Memory `SlidingBloomFilter`:** Uses a fixed `~1.00 MiB` 2-generation bitset (`2 * 65536` `uint64` words, `k = 6` CSPRNG-seeded probes over the full 256-bit `ClientSalt`) rotating every `2 * time_window` (`60s` by default). Unlike fixed-count caches that wipe on overflow, it handles high connection rates without clearing valid recent salts, and only inserts salts *after* AEAD fixed-header verification succeeds.
- **NTP Recommendations:**
  - Keep host clocks synchronized with `chrony` / `systemd-timesyncd` or enable `sing-box`'s built-in `"ntp"` service on both client and server:
    ```json
    {
      "ntp": {
        "enabled": true,
        "server": "time.cloudflare.com",
        "server_port": 123,
        "interval": "30m"
      }
    }
    ```
  - Default `"time_window": "30s"` tolerates up to `±30s` clock skew. Only increase `time_window` (for example `"60s"`) on hosts without reliable NTP; memory remains fixed at `~1.00 MiB` regardless of `time_window`.

### 8.3 Heartbeat & Dead Peer Detection (`heartbeat_interval`)

- When idle for `heartbeat_interval * uniform(0.75, 1.25)` (default `30s`), Aether emits a `FramePing` padded with `32..224 B` of CSPRNG bytes. The peer replies asynchronously via a non-blocking cap-1 `pongCh` with an independently padded `FramePong` (`32..224 B`), preventing `Read`/`writeMu` deadlocks under saturated send windows.
- If `lastRead` does not advance within `PongTimeout` (`heartbeat_interval / 2` when `>= 20s`, or `max(heartbeat_interval / 2, 500ms)` for sub-20s intervals), Aether closes the dead socket so `sing-mux` and `urltest` groups recover automatically. Set `"heartbeat_interval": "-1s"` to disable keepalive if desired.

---

## 9. Automated Weekly Upstream-Sync Releases

Repository automation in [.github/workflows/upstream-sync-release.yml](../../.github/workflows/upstream-sync-release.yml) keeps Aether-sing-box synchronized with official `SagerNet/sing-box` releases:

- **Schedule & Manual Trigger:** Runs every Monday at `02:00 UTC` (`cron: '0 2 * * 1'`) and on manual `workflow_dispatch`, using literal `permissions: contents: write` in a single `ubuntu-latest` job (avoiding multi-job Actions artifact quota limits).
- **Strict Stable Release Filtering:** Queries `https://api.github.com/repos/SagerNet/sing-box/releases/latest`, validates the JSON payload with `jq`, enforces `.draft == false` and `.prerelease == false`, and requires `tag_name` to match `^v[0-9]+\.[0-9]+\.[0-9]+$` (excluding `-alpha`, `-beta`, `-rc`, drafts, empty tags, and HTML error pages).
- **Idempotency:** If `refs/tags/<UPSTREAM_TAG>` is already an ancestor of `HEAD` and `<UPSTREAM_TAG>-Custom-Aether` already exists (tag or GitHub Release), the workflow skips cleanly with exit code `0`.
- **Workflow Preservation & Conflict Safety:** Merges `refs/tags/<UPSTREAM_TAG>` with `--no-commit --no-ff`, immediately restores the fork's `.github/workflows/` directory to pre-merge `HEAD` (`0` diff, preventing `GITHUB_TOKEN` `workflows`-scope push rejection and keeping `docker.yml` / `linux.yml` release triggers disabled), resolves `docs/schema.json` / `constant/version.go` conflicts, and aborts cleanly via `git merge --abort` (exiting non-zero) if any source-code conflict remains.
- **Mandatory `-race` Verification Before Release:** Updates `constant/version.go` to `<ver>-Custom-Aether`, regenerates `docs/schema.json`, and runs:
  ```bash
  CGO_ENABLED=1 go test -race -count=1 ./cmd/sing-box/... ./option/... ./schema/... ./protocol/aether/...
  ```
- **Multi-Arch Packaging & Publishing:** Cross-compiles `CGO_ENABLED=0` static binaries for `linux/amd64` and `linux/arm64` with all 9 release build tags (`with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,badlinkname,tfogo_checklinkname0`) and `release/LDFLAGS`, packages `.tar.gz` archives + `SHA256SUMS`, commits `chore(sync): merge upstream sing-box <tag>`, tags `<tag>-Custom-Aether`, pushes branch and tag, and publishes the GitHub Release via `gh release create`.
- **Secrets:** Uses `${{ secrets.WORKFLOW_PAT || secrets.GITHUB_TOKEN }}`. Default `GITHUB_TOKEN` works directly because `.github/workflows/` is never modified in sync commits; an optional `WORKFLOW_PAT` secret may be added if you want tag pushes from the sync job to trigger other workflows.
