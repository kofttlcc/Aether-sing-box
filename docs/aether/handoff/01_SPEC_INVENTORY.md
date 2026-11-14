# AetherFlow-v2 (`dev/aether-v2`) Exhaustive Specification Inventory

- **Miner Agent**: `spec_miner_survey_1` (`teamwork_preview_spec_miner`)
- **Survey Timestamp**: `2026-11-14T02:47:00Z`
- **Authoritative Sources**:
  1. `.agents/teamwork/ORIGINAL_REQUEST.md`
  2. `docs/aether/AETHER_V2_DEVELOPMENT_PLAN.md`
  3. `docs/aether/AETHER_V1_SECURITY_AUDIT.md`
  4. Existing Aether v1 codebase (`option/aether.go`, `protocol/aether/*.go`, `constant/proxy.go`, `include/registry.go`, `cmd/sing-box/cmd_generate*.go`, `.github/workflows/*.yml`, `go.mod`, `Makefile`, `release/*`)
  5. `sing-box` / `sing` reference interfaces (`adapter/*`, `protocol/trojan/*`, `transport/trojan/*`, `protocol/shadowsocks/*`, `protocol/vless/*`, `common/mux/*`, `common/uot/*`, `schema/*`, `github.com/sagernet/sing`, `github.com/sagernet/sing-shadowsocks2`)

---

## 0. Mandatory Governance & Environment Constraints

### 0.1 Sentinel Branch Isolation Override (CRITICAL)
- **Plan Statement Superseded**: `AETHER_V2_DEVELOPMENT_PLAN.md:209` (Phase 4.1) mentions merging `dev/aether-v2` back into `main`.
- **Active Override (`DISPATCH.md:23` & `ORIGINAL_REQUEST.md:15-21`)**:
  > **All repository changes MUST stay strictly on branch `dev/aether-v2`; `main` (`fdaa4c4`) MUST remain completely untouched.**
- **Current Git State**:
  - Active branch: `dev/aether-v2` at `c11bd0e` (`docs(aether): refine Aether v2 plan for dedicated-line transit without outer TLS`), tracking `origin/dev/aether-v2`.
  - Untouched branch: `main` at `fdaa4c4` (`feat: integrate official upstream sing-box v1.14.2 into Custom-Aether`).

### 0.2 Upstream Baseline & Build Toolchain Facts
- **Current Fork Base**: `SagerNet/sing-box` `v1.14.2` (`af6e64c3b69e6132ebaee0e1a3d24e93903f6709`).
- **Latest Official Upstream Stable Release**: `v1.14.4` (`c005f35300ce76427dc285481ec5695f5b179cd2`, published `2026-10-24T01:04:25Z`; `v1.15.0-alpha.1`..`v1.15.0-alpha.13` are prereleases and excluded).
- **Zero External Dependencies Rule (`AETHER_V2_DEVELOPMENT_PLAN.md:28`)**: Must use ONLY Go standard library (`go 1.25.5` in `go.mod`, VM toolchain `go1.27.3`) and packages already required in `go.mod`:
  - `crypto/ecdh`, `crypto/aes`, `crypto/cipher`, `crypto/rand`, `crypto/sha256`, `crypto/hmac`, `crypto/subtle`
  - `golang.org/x/crypto` `v0.54.0` (`argon2`, `chacha20`, `chacha20poly1305`, `hkdf`)
  - `golang.org/x/sys` `v0.47.0` (`cpu`)
  - `github.com/sagernet/sing` `v0.9.6-0.20260922013354-87c33f17688f` (`common/buf`, `common/bufio`, `common/metadata`, `common/network`, `common/ntp`, `common/uot`, `common/auth`, `common/exceptions`, `common/format`, `common/json/badoption`)
  - `github.com/sagernet/sing-mux` `v0.3.8`
- **Cloud VM Build/Test Environment Fact**: `proxy.golang.org` returns HTTP `403 Forbidden` for certain transitive modules (`klauspost/compress`, `pierrec/lz4/v4`); setting **`GOPROXY=direct`** allows both `go test` and full-tag `go build` (`-tags "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api"`) to succeed with exit code `0`.

---

## Features Discovered

| # | Category | Feature | Description | Inputs | Outputs | Error Behavior | Discovered Via |
|---|----------|---------|-------------|--------|---------|----------------|----------------|
| 1 | Baseline & Build | Upstream `v1.14.4` Merge | Merge official `SagerNet/sing-box` `v1.14.4` (`c005f353...`) into `dev/aether-v2` while preserving Aether hooks (`constant/proxy.go`, `include/registry.go`, `docs/aether/*`). | Upstream tag `v1.14.4` | Updated `dev/aether-v2` tree & `constant/version.go` | Resolve merge conflicts on `dev/aether-v2` without touching `main`; verify full build & test pass. | `AETHER_V2_DEVELOPMENT_PLAN.md:6,180`; `git ls-remote` |
| 2 | Baseline & Build | CI Build Tag & Trigger Fix | Add missing `with_quic,with_acme` build tags, update Go version from `1.24.x` to `>=1.25.5` (`go.mod`), and disable inherited `release: published` trigger in `.github/workflows/docker.yml`. | `.github/workflows/build-linux-amd64.yml`, `.github/workflows/docker.yml` | QUIC/Hysteria2/TUIC/ACME-capable binary; no spurious `ghcr.io/sagernet/sing-box` failure | Build fails fast if any tag breaks compilation; `docker.yml` no longer triggers on GitHub Release creation. | `AETHER_V2_DEVELOPMENT_PLAN.md:181`; `AETHER_V1_SECURITY_AUDIT.md:92`; `docker.yml:8-10` |
| 3 | CLI Tooling | `sing-box generate aether-key` | Generate a 32-byte CSPRNG master key encoded in Base64 for Aether `password` config. | No args (`cobra.NoArgs`), `crypto/rand.Reader` (32B) | Stdout: `<44-char Base64 string>\n`, exit code `0` | Calls `log.Fatal(err)` (non-zero exit) if CSPRNG read or stdout write fails, or if extra args are supplied. | `AETHER_V2_DEVELOPMENT_PLAN.md:57,182,229`; `cmd_generate.go:16-92` |
| 4 | CLI Tooling | `sing-box generate aether-keypair` | Generate an optional static X25519 keypair (`private_key` / `public_key`) for 0-RTT first-packet PFS. | No args (`cobra.NoArgs`), `ecdh.X25519().GenerateKey(rand.Reader)` | Stdout: `PrivateKey: <Base64>\nPublicKey: <Base64>\n`, exit code `0` | Calls `log.Fatal(err)` on CSPRNG error or unexpected CLI arguments. | `AETHER_V2_DEVELOPMENT_PLAN.md:63,153,167,182,229`; `cmd_generate_wireguard.go:18-61` |
| 5 | Cryptography | `uPSK` Loading & Argon2id Hardening (`S-6`) | Parse 32B Base64 CSPRNG key directly as `uPSK`, or strengthen passphrase (`>=16` chars) once at startup via `Argon2id(password, "AetherFlow-v2-KDF", time=3, mem=64*1024 KiB, threads=4, keyLen=32)`. | `password` string from `AetherInboundOptions` / `AetherUser` / `AetherOutboundOptions` | `[32]byte` `uPSK` cached in memory (0 connection-time KDF cost) | Startup error (`NewInbound` / `NewOutbound` fails) if password is empty, all-zero 32B key, or non-32B-Base64 string with `len(password) < 16`. | `AETHER_V2_DEVELOPMENT_PLAN.md:57-58,185-186`; `argon2.IDKey` |
| 6 | Cryptography | ChaCha20 Stream-Masked Ephemeral X25519 (`S-6`) | Per-connection `crypto/ecdh.X25519()` keypairs `(ek_c, epk_c)` and `(ek_s, epk_s)` XOR-masked with ChaCha20 keystream derived via `HKDF-SHA256(uPSK, Salt, "AetherFlow-v2-EPK-Mask")`. | `uPSK [32]byte`, `Salt [32]byte` (`ClientSalt` or `ServerSalt`), `epk [32]byte` | `MaskedEPK [32]byte` indistinguishable from uniform random (eliminates byte-31 MSB=0 bias) | Rejects all-zero / low-order X25519 shared secrets via `ecdh.PrivateKey.ECDH` error; `MaskedEPK` tampering fails AEAD `AAD` check. | `AETHER_V2_DEVELOPMENT_PLAN.md:59-61,73,95` |
| 7 | Cryptography | Optional Static X25519 0-RTT PFS | Mix `X25519(ek_c, spk_s)` into `initKey` (and session secret) when `private_key` / `public_key` are configured so even the 0-RTT client burst has forward secrecy. | Server `private_key` (Base64 32B), Client `public_key` (Base64 32B), `ek_c` | `initKey` derived from `uPSK \|\| X25519(ek_c, spk_s)` and `ClientSalt` | Invalid Base64 / wrong key length fails at node startup; mismatched static keys fail `EncryptedFixedHeader` AEAD verification (`Stealth Drain`). | `AETHER_V2_DEVELOPMENT_PLAN.md:42,63,153,167` |
| 8 | Cryptography | Dual-Salt X25519 Session Key Ratchet (`S-3`) | Upgrade bidirectional session secret on server response to `masterSecret = HKDF-SHA256(uPSK \|\| X25519(ek_c, epk_s), ClientSalt \|\| ServerSalt, "AetherFlow-v2-Session")`, then split per-direction `HeaderKey (32B)` + `PayloadKey (32B)`. | `uPSK`, `X25519(ek_c, epk_s)`, `ClientSalt (32B)`, `ServerSalt (32B)` | Independent `c2sHeaderKey`, `c2sPayloadKey`, `s2cHeaderKey`, `s2cPayloadKey` (`32B` each) | Eliminates `S-3` catastrophic AEAD `(Key, Nonce)` reuse even under hypothetical replay bypass or server restart. | `AETHER_V2_DEVELOPMENT_PLAN.md:43,64-65,94-103` |
| 9 | Cryptography | Hardware-Accelerated AEAD Auto-Negotiation | Automatically select `AES-256-GCM` (`0x01`) when CPU supports AES+carryless multiply (`X86.HasAES && X86.HasPCLMULQDQ` or `ARM64.HasAES && ARM64.HasPMULL`), otherwise `ChaCha20-Poly1305` (`0x02`), or honor explicit `cipher` option. | Outbound `cipher` (`"auto"`, `"aes-256-gcm"`, `"chacha20-poly1305"`), `golang.org/x/sys/cpu` | `CipherSuite` byte (`0x01` or `0x02`) in `FixedHeader` and data-plane AEAD instances | Unknown `cipher` config string fails at `NewOutbound`; unknown `CipherSuite` byte (`!=0x01,0x02`) rejected at server `FixedHeader` check. | `AETHER_V2_DEVELOPMENT_PLAN.md:47-48,82,166,187` |
| 10 | Cryptography / Multi-User | Multi-User `EIH` Identification (`S-6`) | Authenticate and route multiple users (`users: [{name, password}]`) via extensible identity header (`EIH`), populating `metadata.User` and per-user audit logs. | `users` list on Inbound, `ClientSalt`, `EIH` (`16B`) | Matched user index / `Name` + `uPSK` | Unknown user / failed `EIH` or `FixedHeader` tag enters `Stealth Drain` (`3s..10s`) with rate-limited log; duplicate user passwords/names rejected at startup. | `AETHER_V2_DEVELOPMENT_PLAN.md:57,74,144-152,187,226` |
| 11 | Wire Format | Authenticated Fixed-Size Client Prefix (`S-1`) | Server always reads fixed prefix (`ClientSalt 32B` + `MaskedClientEPK 32B` + `[EIH 16B]` + `EncryptedFixedHeader 32B`) and verifies ChaCha20-Poly1305 tag (`AAD = ClientSalt \|\| MaskedClientEPK \|\| EIH`), timestamp, and Bloom filter BEFORE reading any variable length. | Raw TCP stream | Validated 16B `FixedHeader` (`Version=0x02`, `Command`, `CipherSuite`, `Reserved=0`, `TimestampSec`, `NoiseLen`, `VarHeaderLen`) | Any invalid tag, version, command, cipher, reserved byte, `NoiseLen` (`<32` or `>384`), `VarHeaderLen` (`>16384`), timestamp skew, or replay triggers `Stealth Drain` without reading `VarHeaderLen` (zero length-oracle). | `AETHER_V2_DEVELOPMENT_PLAN.md:70-89,192` |
| 12 | Wire Format | Authenticated Variable Client Header & 0-RTT Payload (`R-4`) | Decrypt `EncryptedVarHeader` (`VarHeaderLen + 16B Tag`) containing `NoisePadding (32..384B)` + `TargetAddr` (`M.SocksaddrSerializer`) + `InitialPayload` (0-RTT early application data). | `VarHeaderLen` bytes + 16B tag | `TargetAddr (M.Socksaddr)` + `InitialPayload` queued into `ServerConn` unread buffer | Short read, invalid AEAD tag, `VarHeaderLen < NoiseLen + minAddrLen`, or malformed `Socksaddr` aborts handshake (`Stealth Drain`) and closes connection. | `AETHER_V2_DEVELOPMENT_PLAN.md:36-37,77,85-86`; `AETHER_V1_SECURITY_AUDIT.md:89` |
| 13 | Wire Format | Coalesced 84B Server Response Prefix | Server prepends `ServerSalt (32B)` + `MaskedServerEPK (32B)` + `EncryptedRespHeader (4B + 16B Tag)` (`AAD = ClientSalt \|\| ServerSalt \|\| MaskedServerEPK`) to its first downlink frame in one `Write`. | `ClientSalt`, `ServerSalt`, `epk_s`, `4B RespHeader` | 84-byte authenticated prefix coalesced with first downlink frame | Client fails `Read` / `ReadBuffer` with `ErrInvalidTag` / `ErrInvalidHeader` and closes connection if prefix is truncated, tag fails, or `RespHeader` is invalid. | `AETHER_V2_DEVELOPMENT_PLAN.md:90-97` |
| 14 | Wire Format | Two-Block Independent-Key AEAD Data Frame (`S-2`, `S-4`) | Replace unauthenticated XOR `MaskLength` and double `Conn.Write` with `18B` AEAD length header (`HeaderKey`, `nonce=seq`, `2B PlainFrameLen` + `16B Tag`) + `PlainFrameLen + 16B` AEAD body (`PayloadKey`, `nonce=seq`, `[FrameType 1B \| PadLen 1B \| Padding \| Data]`) written in a SINGLE `*buf.Buffer` `Write`. | Application bytes / `*buf.Buffer`, `HeaderKey`, `PayloadKey`, `seq` | Single contiguous wire write (`18 + PlainFrameLen + 16` bytes; `36B` total overhead when `PadLen=0`); zero `2-Byte` TCP segments | Any header tag failure, `PlainFrameLen < 2` or `PlainFrameLen > MaxPlainFrameLen` (`16641`), `2+int(PadLen) > int(PlainFrameLen)`, unknown `FrameType`, or body tag failure immediately terminates connection. | `AETHER_V2_DEVELOPMENT_PLAN.md:44-46,100-113,192-196` |
| 15 | Wire Format & Shaping | Head-Only First-6-Frames Shaping (`S-2`) | On `Frame 0..5` (unless `disable_shaping: true`), attach `16..255B` random padding and split bursts `>1200B` to mask inner TLS `ClientHello`/`Certificate` lengths; from `Frame 6+`, drop `PadLen` to `0` and send up to `16384B` data per frame (`<0.22%` overhead). | Outgoing stream data, `sendFrameIdx`, `disableShaping` bool | Shaped frames (`0..5`) followed by unpadded `<=16420B` wire frames (`6+`) | None on valid data; `disable_shaping: true` bypasses shaping from `Frame 0` (`PadLen=0` on data frames). | `AETHER_V2_DEVELOPMENT_PLAN.md:38,105-107,157,169,194` |
| 16 | Wire Format | Strict Frame Types & TCP Half-Close (`R-4`) | Enforce explicit `FrameType` enum: `0x01=FrameData` (skip 0-length chaff in loop), `0x02=FramePing` (`32..224B` pad), `0x03=FramePong` (`32..224B` independent pad), `0x04=FrameCloseWrite` (`N.WriteCloser`), removing v1's `default:` branch. | Decrypted frame body | Data bytes, async Pong trigger, or clean `io.EOF` on `FrameCloseWrite` | Unknown `FrameType` (`0x00` or `>=0x05`) immediately returns `ErrInvalidFrame` and closes connection; empty `FrameData` NEVER returns `(0, nil)`. | `AETHER_V2_DEVELOPMENT_PLAN.md:108-113,197` |
| 17 | Wire Format / UDP | Native Framed UDP (`CommandUDP = 0x02`) (`R-5`) | Native per-datagram UDP framing (`[Socksaddr][uint16 BE Length][Payload]`) inside encrypted `CommandUDP` stream via `N.PacketConn` (`ReadPacket`/`WritePacket`), working without requiring `udp_over_tcp`. | `*buf.Buffer` UDP payload + `M.Socksaddr` | Encrypted stream-framed UDP datagrams (`net.PacketConn` / `N.PacketConn`) | Malformed `Socksaddr` or truncated datagram returns read error and closes stream; oversized payload `>65535` rejected on write. | `AETHER_V2_DEVELOPMENT_PLAN.md:81,131,192,202` |
| 18 | Security & DoS | Dual-Generation Sliding Bloom Anti-Replay (`S-5`) | Constant-memory (~`1 MB`) rotating Bloom filter over full `[32]byte` `ClientSalt` combined with NTP-calibrated timestamp check (`ntp.TimeFuncFromContext(ctx)`, default `±30s` window), handling millions of handshakes/min with zero full-table wipes. | `[32]byte` `ClientSalt`, `TimestampSec int64`, `ntp` time func | `true` (fresh) or `false` (replay / expired) | Duplicate `ClientSalt` or `|now - TimestampSec| > TimeWindow` rejected; enters `Stealth Drain` + rate-limited warning log. | `AETHER_V2_DEVELOPMENT_PLAN.md:84,117-118,154,188-189` |
| 19 | Security & DoS | Handshake Semaphore & `3s..10s` Stealth Drain (`S-7`) | Bound concurrent unauthenticated handshakes via semaphore (default `256`), enforce `HandshakeTimeout` (default `6s`), and drain failed/replayed connections with per-connection uniform random `3s..10s` silent read-discard timeout + rate-limited IP audit logs (replacing `200ms` `HandleProbe`). | Incoming `net.Conn`, `HandshakeTimeout`, failure reason, `metadata.Source` | Indistinguishable TCP read-timeout behavior; bounded FD/goroutine footprint | Semaphore saturation immediately rejects/closes excess unauthenticated connections with rate-limited warn log; failed handshakes never leak `200ms` FIN oracle. | `AETHER_V2_DEVELOPMENT_PLAN.md:119-121,155,200-201,225` |
| 20 | Flow Control | Non-Blocking `pongCh` Control Plane (`R-1`) | Decouple `FramePing` reception from `FramePong` transmission via buffered channel `pongCh` (cap `1`) serviced by writer coordinator goroutine; `Read` never acquires `writeMu` or calls `Conn.Write`. | Incoming `FramePing` during bidirectional saturation | Non-blocking `pongCh` signal -> async padded `FramePong` write | Zero deadlock even when both TCP send windows are 100% full under heavy `sing-mux` load; duplicate Pings coalesce safely via cap-1 channel. | `AETHER_V2_DEVELOPMENT_PLAN.md:125,197`; `AETHER_V1_SECURITY_AUDIT.md:86` |
| 21 | Flow Control | Atomic Write Error Fusing & Deadline Isolation (`R-2`) | Isolate application `SetWriteDeadline` from background control writes and immediately mark/close connection (`c.closed` / `writeBroken`) on ANY underlying `Conn.Write` error or short write. | Application `Write`/`WriteBuffer` with deadlines + background Ping/Pong | Strictly monotonic, synchronized AEAD `seq` or clean connection teardown | Once underlying `Conn.Write` fails or times out, all subsequent writes fail immediately and underlying socket closes (zero `ErrInvalidTag` desync). | `AETHER_V2_DEVELOPMENT_PLAN.md:126,197`; `AETHER_V1_SECURITY_AUDIT.md:87` |
| 22 | Flow Control | Idle Jittered Heartbeat & `lastRead` DPD (`R-3`) | Send padded `FramePing` (`32..224B`) only when idle beyond `heartbeat_interval * jitter(0.75..1.25)` (default `30s`), and verify `c.lastRead.Load()` advances within `pong_timeout`; actively close dead sockets. | `heartbeat_interval`, `c.lastRead`, `c.lastWrite` | Timely socket closure on blackhole / silent NAT drop | Closes underlying `net.Conn` when `pong_timeout` elapses without any frame received, triggering immediate `sing-mux` / `URLTest` reconnect. | `AETHER_V2_DEVELOPMENT_PLAN.md:39,127,156,168,197` |
| 23 | Zero-Copy & Early Data | `N.ExtendedConn` & 0-RTT `DialEarlyConn` (`R-6`, `R-7`) | Implement `ReadBuffer`/`WriteBuffer`, `FrontHeadroom`/`RearHeadroom`, and `N.EarlyWriter` (`NeedHandshakeForWrite`) using `sing/common/buf` pools so client handshake + noise + target + first write coalesce into one syscall, and steady-state reads/writes avoid heap slice churn. | `*buf.Buffer` from `sing/common/bufio` | Zero-copy in-place seal/open into pooled `*buf.Buffer` | Releases owned `*buf.Buffer` on all error paths in `WriteBuffer` (`defer buffer.Release()` when not delegated); closes `rawConn` if handshake pack/write fails. | `AETHER_V2_DEVELOPMENT_PLAN.md:36-37,129,195-197`; `AETHER_V1_SECURITY_AUDIT.md:91-92` |
| 24 | `sing-box` Integration | Full `Inbound` & `Outbound` Lifecycle + All-Mode UDP (`R-5`, `R-6`) | Inbound implements `adapter.TCPInjectableInbound`, `uot.NewRouter`, `mux.NewRouterWithOptions`, and `CommandUDP` `RoutePacketConnectionEx`. Outbound implements `adapter.OutboundWithMultiplex` (`MultiplexEnabled()`), `InterfaceUpdated(ctx)`, `Close()`, and full UDP across `Multiplex`, `UoT`, and Native `CommandUDP`. | `AetherInboundOptions`, `AetherOutboundOptions`, TCP/UDP connections | Full TCP + Full-Cone/Connected UDP across all 3 modes (`Mux`, `UoT`, `Native UDP`) | Unknown network returns `E.Extend(N.ErrUnknownNetwork, network)`; `Close()` and `InterfaceUpdated(ctx)` cleanly reset/close `multiplexDialer`. | `AETHER_V2_DEVELOPMENT_PLAN.md:130-131,200-202`; `trojan/outbound.go:102-127` |
| 25 | Config & Schema | Pure-Binary `option/aether.go` & JSON Schema | Streamlined dedicated-line v2 options (`AetherUser`, `AetherInboundOptions`, `AetherOutboundOptions`) using `badoption.Duration`, compatible with `sing-box check` and `sing-box schema`. | JSON configuration (`type: "aether"`) | Validated Go structs & JSON Schema node definitions | Unknown JSON fields rejected by `badjson`; invalid durations/enums rejected at unmarshal or startup. | `AETHER_V2_DEVELOPMENT_PLAN.md:135-173,220`; `cmd_schema.go:35-45` |
| 26 | CI/CD Automation | Weekly Upstream `SagerNet/sing-box` Sync & Release Action | `.github/workflows/upstream-sync-release.yml` running weekly (`cron: '0 2 * * 1'`) + `workflow_dispatch`: queries `SagerNet/sing-box/releases/latest` (excluding `alpha`/`beta`/`rc`), merges new stable release, runs `go test -race ./protocol/aether/...`, builds full-tag binary, and publishes GitHub Release. | GitHub schedule / manual dispatch, `SagerNet/sing-box/releases/latest` | Merged tree, verified `-race` tests, and published GitHub Release binary | Aborts release without publishing if merge conflicts occur, prerelease tag detected, or `go test -race` / `go build` fails. | `ORIGINAL_REQUEST.md:12,23`; `AETHER_V2_DEVELOPMENT_PLAN.md:210-212,230` |
| 27 | Quality & Verification | KAT, `-race` Stress, Go Fuzzing & Wire Split Tests | Comprehensive `protocol/aether/*_test.go` suite: crypto KATs, Bloom replay concurrency/boundary tests, `FuzzHandshake` & `FuzzFrameStream`, `-race` small-window bidirectional + heartbeat + random `WriteDeadline` stress test, and custom `net.Conn` write-inspector test proving zero `2-Byte` split writes and head-only shaping. | `go test -race ./protocol/aether/...`, `go test -fuzz=...` | Deterministic pass with 0 data races, 0 panics, 0 goroutine/FD leaks, 0 `2B` split writes | Fails test immediately on any panic, oracle length read before tag check, `2-Byte` write call, nonce desync, deadlock, or leak. | `AETHER_V2_DEVELOPMENT_PLAN.md:203-206,228` |

---

## Edge Cases

| # | Feature | Input | Observed Behavior |
|---|---------|-------|-------------------|
| 1 | `uPSK` Password Validation | Empty string `""`, 15-char ASCII password `"short_password!"`, or Base64 decoding to 32 `0x00` bytes | Rejected at `NewInbound` / `NewOutbound` initialization with descriptive configuration error; node refuses to start with weak/empty key (`S-6`). |
| 2 | `uPSK` Base64 vs Passphrase | 44-char valid `base64.StdEncoding` string encoding 32 CSPRNG bytes vs 20-char passphrase vs 44-char non-Base64 passphrase | Valid 32-byte Base64 decodes directly to 32B `uPSK` in `<1 µs`; non-Base64 (or decoded length `!= 32`) with length `>=16` runs `Argon2id` (`t=3, m=64MiB, p=4`) once at startup. |
| 3 | Server Fixed-Prefix Oracle Resistance (`S-1`) | Attacker sends 34B, 95B, or 512B of random garbage (or bit-flipped `EncryptedFixedHeader`) | Server attempts `io.ReadFull` of exact fixed prefix (96B or 112B) within `6s` `HandshakeTimeout`; on EOF/timeout or AEAD tag mismatch, server NEVER inspects `VarHeaderLen` and transitions into `3s..10s` randomized `Stealth Drain`. |
| 4 | Server-Speaks-First Protocol over 0-RTT `EarlyConn` | Client dials e.g. SSH/SMTP/MySQL target and calls `Conn.Read` / `ReadBuffer` BEFORE calling `Conn.Write` | Client detects `!handshakeWritten`, flushes Client Initial Burst with `len(InitialPayload) == 0` (protected by `32..384B` `NoisePadding`), then reads 84B `ServerResponsePrefix` + server banner without deadlocking. |
| 5 | Target Closes or Pings Before Sending Downlink Data | Server accepts client burst, target TCP server immediately sends `FIN` (`0` bytes) or idle Ping/Pong fires first | Whichever downlink frame is transmitted first (`FrameCloseWrite`, `FramePong`, `FramePing`, or `FrameData`) prepends the 84B `ServerResponsePrefix` in a single buffer write so client handshake always completes cleanly. |
| 6 | 0-RTT `InitialPayload` Exceeding `VarHeader` Budget | First client write is `32 KiB` while max `VarHeaderLen` is `16384B` (minus `NoiseLen 32..384B` and `TargetAddr 7..259B`) | Client packs up to `16384 - NoiseLen - AddrLen` bytes into `InitialPayload` inside `EncryptedVarHeader`, and seamlessly frames the remaining bytes as shaped `FrameData` frame(s), coalesced into the initial write. |
| 7 | Chaff / Zero-Data `FrameData` (`R-4`) | Peer sends `FrameData` (`0x01`) with `PadLen = 64` and `len(Data) == 0` (`PlainFrameLen = 66`) | `Read` / `ReadBuffer` updates `lastRead`, discards padding, and loops to read the next frame — NEVER returning `(0, nil)` (which would trigger `io.ErrNoProgress` in Go `io.Copy`). |
| 8 | Maximum `16384B` Data Frame Boundary | Application writes exact `16384B` buffer at `Frame 6+` (`PadLen = 0`) or during `Frame 0..5` (`PadLen = 255`) | `PlainFrameLen` is `16386` (`2 + 0 + 16384`) or `16641` (`2 + 255 + 16384`); wire size is `16420B` (`36B` overhead = `0.2197%`) or `16675B`. Receiver checks `2 <= PlainFrameLen <= 16641` (NOT `<= 16384`). |
| 9 | Bidirectional Full-Window Saturation + Concurrent `FramePing` (`R-1`) | Both client and server saturate 10Gbps Mux streams (TCP send buffers full) while idle timer / peer sends `FramePing` | `Read` pushes to cap-1 `pongCh` via non-blocking `select` and immediately continues draining incoming TCP receive buffer, unblocking peer's TCP send window and preventing `Read -> writeMu` deadlock. |
| 10 | Application `SetWriteDeadline` Expiry Mid-Stream (`R-2`) | Upper layer sets `SetWriteDeadline(now + 1ms)` which times out during `Conn.Write` | Connection atomically sets `writeBroken` / closes underlying `net.Conn` under `writeMu` so no subsequent write can reuse or skip an AEAD sequence number (`ErrInvalidTag` impossible). |
| 11 | Sliding Bloom Filter Rotation Boundary (`S-5`) | Valid handshake arrives at `t = 29.9s` with client clock `+29s` (`TimestampSec = 59`), replayed at `t = 60.1s` (still within `59 ± 30s`) | Generation rotation interval MUST be `>= 2 * TimeWindow` (`60s` for 2 generations) or use 3 generations rotating every `TimeWindow` (`30s`), guaranteeing `>= 60s` retention across every rotation boundary. Also AEAD tag MUST be verified BEFORE Bloom insertion so unauthenticated probes cannot pollute Bloom bits. |
| 12 | Stealth Drain Flood DoS vs Legitimate Handshakes | Attacker opens 300 connections/sec sending 96 invalid random bytes to trigger `3s..10s` Stealth Drain | Active `handshakeSem` (cap `256`) is released when transitioning into `Stealth Drain`, which uses a separate bounded `drainSem` (e.g. cap `512`); if `drainSem` is full, excess failed probes close immediately without starving legitimate handshakes or exhausting FDs. |
| 13 | Simultaneous `Multiplex` + `UDP` / `UoT` / Native `CommandUDP` (`R-5`) | Outbound configured with `multiplex.enabled=true` receiving `ListenPacket` (QUIC/DNS), or `multiplex` off + `udp_over_tcp` off | When `multiplex` is enabled, `ListenPacket` delegates to `multiplexDialer.ListenPacket` (fixing v1 error); when `multiplex` is off and `udp_over_tcp` is on, uses `uotClient`; when both are off, uses Native `CommandUDP` (`0x02`) `PacketConn` (never misrouting UDP to `CommandTCP`). |
| 14 | Network Switch / Hot Reload (`R-6`) | Mobile/router interface changes (`InterfaceUpdated(ctx)`) or outbound removed (`Close()`) | `InterfaceUpdated(ctx)` calls `multiplexDialer.Reset()`; `Close()` closes `multiplexDialer` and stops all keepalive/coordinator goroutines via `closeOnce` without goroutine or socket leaks. |
| 15 | Jumbo / Domain-Addressed Native UDP Datagram | DNS/QUIC packet to 255-byte FQDN or UDP datagram `> 16384B` (up to `65535B`) over `CommandUDP` | Framed as `[Socksaddr (up to 259B)][uint16 BE Length][Payload]` over encrypted `Conn`; datagrams `<= 16123B` fit in one Aether frame, while larger datagrams transparently span multiple `FrameData` frames and reassemble cleanly in `ReadPacket`. |

---

## 1. Byte-Exact Cryptographic Specification (`protocol/aether/crypto.go`)

### 1.1 Master Pre-Shared Key (`uPSK`) Derivation
1. **Input**: `password` string from configuration.
2. **Validation & Derivation**:
   - Trim/check empty: if `len(password) == 0`, return startup error.
   - Base64 fast path (recommended `sing-box generate aether-key` output):
     - Attempt Base64 decode (see **U-1** for exact `StdEncoding` / `RawStdEncoding` rule). If decoded byte slice has `len == 32`:
       - Verify decoded key is not all-zeros (`[32]byte{}`); if all-zeros, return startup error.
       - Set `uPSK = [32]byte(decoded)`.
   - Passphrase path (when not a 32-byte Base64 key):
     - Enforce `len(password) >= 16` bytes/chars; if `< 16`, return startup error (`weak password rejected: minimum 16 characters required`).
     - Compute once at node startup (`NewInbound` / `NewOutbound`):
       ```go
       uPSK := argon2.IDKey(
           []byte(password),
           []byte("AetherFlow-v2-KDF"),
           3,         // time = 3 iterations
           64 * 1024, // memory = 65536 KiB (64 MiB)
           4,         // threads = 4 lanes
           32,        // keyLen = 32 bytes (256-bit)
       )
       ```

### 1.2 Ephemeral X25519 & ChaCha20 Public Key Stream Masking
1. **Keypair Generation**:
   - Client generates `(ek_c, epk_c)` via `crypto/ecdh.X25519().GenerateKey(crypto/rand.Reader)`.
   - Server generates `(ek_s, epk_s)` via `crypto/ecdh.X25519().GenerateKey(crypto/rand.Reader)`.
2. **Stream Masking (`MaskEPK` / `UnmaskEPK` — Symmetric XOR)**:
   - KDF info label: `"AetherFlow-v2-EPK-Mask"` (`AETHER_V2_DEVELOPMENT_PLAN.md:61`).
   - For Client EPK: `Salt = ClientSalt` (`32B`).
   - For Server EPK: `Salt = ServerSalt` (`32B`) (see **U-2**).
   - Derive ChaCha20 key (+ nonce, see **U-2**):
     - `r := hkdf.New(sha256.New, uPSK[:], salt[:], []byte("AetherFlow-v2-EPK-Mask"))`
     - Read `32B` key + `12B` nonce (44B total, or `32B` key with `12B` zero nonce — frozen in **U-2**).
     - `stream, _ := chacha20.NewUnauthenticatedCipher(maskKey, maskNonce)`
     - `stream.XORKeyStream(dst32, src32)`
   - Because `ClientSalt` and `ServerSalt` are fresh 256-bit CSPRNG values per connection and `MaskedClientEPK` / `MaskedServerEPK` are bound into AEAD `AAD`, the masked 32 bytes are uniformly distributed over `[0x00..0xFF]^32` (no Curve25519 bit-255 == 0 bias) and tamper-evident.

### 1.3 Handshake Key (`initKey`) & Upgraded Session Key (`masterSecret`)
1. **Client Initial Handshake Key (`initKey`)**:
   - Without static server public key (`public_key == ""`):
     - `ikm = uPSK` (`32B`)
   - With static server public key (`public_key != ""`, 0-RTT PFS mode):
     - `ss_static, err := ek_c.ECDH(spk_s)` (client) / `sk_s.ECDH(epk_c)` (server) (`32B`)
     - `ikm = uPSK || ss_static` (`64B`)
   - Derive `initKey` (`32B`) via `HKDF-SHA256(ikm, ClientSalt, info)` (see **U-3** for canonical `info` label, e.g. `"AetherFlow-v2-Client-Init"`).
   - Handshake AEAD: **`chacha20poly1305.New(initKey)`** (`AETHER_V2_DEVELOPMENT_PLAN.md:75`).
     - `EncryptedFixedHeader`: `nonce = 0`, `AAD = ClientSalt || MaskedClientEPK || EIH` (`64B` or `80B`).
     - `EncryptedVarHeader`: `nonce = 1`, `AAD = FixedHeaderPlaintext` (`16B`, or `nil` — frozen in **U-3**).
2. **Session Ratchet (`masterSecret`) & Traffic Subkeys**:
   - Ephemeral ECDH shared secret:
     - `ss_eph, err := ek_c.ECDH(epk_s)` (client) / `ek_s.ECDH(epk_c)` (server) (`32B`)
   - Combined salt:
     - `dualSalt = ClientSalt || ServerSalt` (`64B`)
   - Session Master Secret (`AETHER_V2_DEVELOPMENT_PLAN.md:64`):
     - `masterSecret = HKDF-SHA256(ikm_session, ClientSalt || ServerSalt, "AetherFlow-v2-Session")` (`32B`, where `ikm_session = uPSK || ss_eph`, or `uPSK || ss_eph || ss_static` when static key is configured — see **U-5**).
   - Directional Traffic Keys (`HeaderKey` `32B` + `PayloadKey` `32B` per direction, `AETHER_V2_DEVELOPMENT_PLAN.md:101`) + Server Response Header Key (see **U-5**):
     - Expand from `masterSecret` via `HKDF-Expand-SHA256` (or `hkdf.New(sha256.New, masterSecret, nil, label)`) with distinct domain-separated labels:
       - `"AetherFlow-v2-Server-Resp"` -> `respKey [32]byte` (`EncryptedRespHeader`, `AAD = ClientSalt || ServerSalt || MaskedServerEPK` = `96B`)
       - `"AetherFlow-v2-C2S-Header"` -> `c2sHeaderKey [32]byte`
       - `"AetherFlow-v2-C2S-Payload"` -> `c2sPayloadKey [32]byte`
       - `"AetherFlow-v2-S2C-Header"` -> `s2cHeaderKey [32]byte`
       - `"AetherFlow-v2-S2C-Payload"` -> `s2cPayloadKey [32]byte`

### 1.4 Hardware AEAD Cipher Auto-Negotiation
- `CipherSuite` Wire Codes (`FixedHeader[2]`):
  - `0x01`: `AES-256-GCM` (`aes.NewCipher(key32)` + `cipher.NewGCM(block)`, 12B nonce, 16B tag)
  - `0x02`: `ChaCha20-Poly1305` (`chacha20poly1305.New(key32)`, 12B nonce, 16B tag)
- Auto-Selection Logic (`cipher == ""` or `cipher == "auto"`):
  ```go
  hasAESGCMHardware := (cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ) ||
                       (cpu.ARM64.HasAES && cpu.ARM64.HasPMULL) ||
                       (cpu.S390X.HasAES && cpu.S390X.HasAESGCM)
  ```
  If `hasAESGCMHardware` -> `0x01` (`AES-256-GCM`); else -> `0x02` (`ChaCha20-Poly1305`).

---

## 2. Byte-Exact Wire Format Specification (`protocol/aether/wire.go`)

### 2.1 Client Initial Burst (Single Coalesced Write)
```
+-----------------------+------------------------+------------------+-------------------------------+-----------------------------------+
| ClientSalt (32 Bytes) | MaskedClientEPK (32 B) | EIH (0 or 16 B*) | EncryptedFixedHeader (32 B)   | EncryptedVarHeader (VarLen + 16B) |
+-----------------------+------------------------+------------------+-------------------------------+-----------------------------------+
|<-------------------- AAD (64 B or 80 B*) ----------------------->| ChaCha20-Poly1305(initKey,n=0)| ChaCha20-Poly1305(initKey, n=1)   |
|<------------------- Fixed Server Initial Read (96 B or 112 B*) --------------------------------->|
```
*\*See **U-6** regarding single-user (96B) vs unified/multi-user (112B) EIH wire framing!*

#### `FixedHeader` Plaintext (`16 Bytes`, Big-Endian)
| Byte Offset | Field | Type | Valid Values / Constraints |
| :---: | :--- | :---: | :--- |
| `0` | `Version` | `uint8` | Must be `0x02` |
| `1` | `Command` | `uint8` | `0x01` = TCP, `0x02` = Native UDP, `0x03` = Sing-Mux, `0x04` = UoT |
| `2` | `CipherSuite` | `uint8` | `0x01` = AES-256-GCM, `0x02` = ChaCha20-Poly1305 |
| `3` | `Reserved` | `uint8` | Must be `0x00` |
| `4..12` | `TimestampSec` | `int64` BE | Unix seconds (`ntp.TimeFuncFromContext(ctx)`); server enforces `\|now - ts\| <= TimeWindow` (default `30s`) |
| `12..14` | `NoiseLen` | `uint16` BE | Handshake random padding length: `32 <= NoiseLen <= 384` |
| `14..16` | `VarHeaderLen` | `uint16` BE | Plaintext length of `VarHeader`: `NoiseLen + minAddrLen <= VarHeaderLen <= 16384` |

#### `VarHeader` Plaintext (`VarHeaderLen` Bytes, `<= 16384`)
| Slice | Field | Length | Encoding |
| :---: | :--- | :---: | :--- |
| `[0 : NoiseLen]` | `NoisePadding` | `32..384 B` | CSPRNG random bytes |
| `[NoiseLen : NoiseLen+AddrLen]` | `TargetAddr` | `7..259 B` (or see **U-7**) | `M.SocksaddrSerializer` (`0x01`+IPv4+Port = 7B; `0x04`+IPv6+Port = 19B; `0x03`+Len+FQDN+Port = 4+Len B) |
| `[NoiseLen+AddrLen : VarHeaderLen]` | `InitialPayload` | `0..(16384-NoiseLen-AddrLen)` | 0-RTT early application stream data (or initial framed UDP packet) |

### 2.2 Server Response Prefix (`84 Bytes`, Coalesced with First Downlink Frame)
```
+-----------------------+------------------------+-------------------------------+----------------------------------------+
| ServerSalt (32 Bytes) | MaskedServerEPK (32 B) | EncryptedRespHeader (20 B)    | First Downlink Encrypted Data/Ctrl Frm |
+-----------------------+------------------------+-------------------------------+----------------------------------------+
|          AAD = ClientSalt(32B) || ServerSalt(32B) || MaskedServerEPK(32B)      |
|<------------------------ 84 Bytes Server Response Prefix --------------------->|
```
- `RespHeader` Plaintext (`4 Bytes` — see **U-8**): e.g. `[0] Version = 0x02`, `[1] Status = 0x00`, `[2:4] Reserved = 0x0000`.

### 2.3 Bidirectional Encrypted Data & Control Frames
Each direction maintains an independent `uint64` frame sequence counter `seq = 0, 1, 2, ...` (if `seq == math.MaxUint64`, close connection to prevent wraparound):
```
+----------------------------------------------+-----------------------------------------------------------------------+
| Encrypted Length Header (18 Bytes)           | Encrypted Frame Body (PlainFrameLen + 16 Bytes)                       |
| AEAD_Seal(HeaderKey, nonce=seq,              | AEAD_Seal(PayloadKey, nonce=seq,                                      |
|           [PlainFrameLen (2B uint16 BE)],    |           [FrameType(1B) | PadLen(1B) | Padding(PadLen) | Data],      |
|           aad=nil)                           |           aad=nil)                                                    |
+----------------------------------------------+-----------------------------------------------------------------------+
```
- **Exact Frame Size Math**:
  - `MaxDataLen = 16384` (`16 KiB`)
  - `PadLen` = `0..255` (`uint8`)
  - `PlainFrameLen` = `2 + int(PadLen) + len(Data)` -> valid range **`2..16641`** (`2` when `PadLen=0, len(Data)=0`; `16386` when `PadLen=0, len(Data)=16384`; `16641` when `PadLen=255, len(Data)=16384`).
  - Wire Frame Total Length = `18 + PlainFrameLen + 16 = 34 + PlainFrameLen` (`36 + len(Data)` when `PadLen == 0` -> `36 / 16384 = 0.2197% < 0.22%`).
- **FrameType Values**:
  - `0x01` (`FrameData`): Carries `Data`. If `len(Data) == 0`, treated as chaff cover frame and skipped in `Read` loop.
  - `0x02` (`FramePing`): Idle-only keepalive request; `len(Data) == 0`, `PadLen` uniformly random in **`32..224`**.
  - `0x03` (`FramePong`): Async keepalive response; `len(Data) == 0`, `PadLen` independently uniformly random in **`32..224`**.
  - `0x04` (`FrameCloseWrite`): Half-close EOF marker; `len(Data) == 0`, `PadLen` random `0..64` (or `16..255` if in `Frame 0..5`).
  - Any other byte: Protocol error -> immediate connection close.

### 2.4 Native UDP Stream Datagram Framing (`CommandUDP = 0x02`, see **U-12**)
Inside the decrypted `Conn` byte stream of a `Command == 0x02` session, each UDP datagram (both C->S and S->C) is framed as:
```
+--------------------------------------------+----------------------------+------------------------------+
| Socksaddr (M.SocksaddrSerializer, 7..259B) | PayloadLen (2B uint16 BE)  | UDP Datagram (PayloadLen B)  |
+--------------------------------------------+----------------------------+------------------------------+
```
- Implemented by `PacketConn` (`N.PacketConn` + `net.PacketConn`), supporting both `ListenPacket` (Full-Cone NAT per-packet destination/source `Socksaddr`) and `DialContext(ctx, "udp", dest)` (via `bufio.NewBindPacketConn(packetConn, destination)`).

---

## 3. Security (`S-1`..`S-7`) & Reliability (`R-1`..`R-7`) Complete Traceability Matrix

| ID | v1 Audit Defect (`file:line`) | v2 Countermeasure & Module (`dev/aether-v2`) |
| :---: | :--- | :--- |
| **S-1** | Unauthenticated XOR `MaskLength` + `200ms` `HandleProbe` oracle (`conn.go:178-197`, `probe_guard.go:8-24`) | Fixed-size 96B/112B prefix ChaCha20-Poly1305 verification before reading `VarHeaderLen`; `18B` AEAD length headers; `3s..10s` randomized `Stealth Drain` (`wire.go`, `drain.go`). |
| **S-2** | Bare high-entropy 0-payload handshake + `[2B, NB]` double `Conn.Write` + fixed `17B` heartbeat (`conn.go:88-93, 317-322`, `outbound.go:87`) | 0-RTT `DialEarlyConn` coalescing handshake + noise + app payload; single `*buf.Buffer` write per frame; first-6-frames padding/splitting (`16..255B`); idle-only jittered `32..224B` Ping/Pong (`wire.go`, `conn.go`). |
| **S-3** | Missing `ServerSalt` causing catastrophic ChaCha20-Poly1305 `(Key, Nonce)` reuse on replay/restart (`cipher.go:52-86`) | Per-connection 32B CSPRNG `ServerSalt` + ephemeral `X25519(ek_c, epk_s)` ratcheted into `masterSecret` (`crypto.go`). |
| **S-4** | `seq % 15` bug + bidirectional `maskKey` Two-Time Pad (`noise.go:34-43`, `cipher.go:60-64`) | `noise.go` and `MaskLength` completely deleted; replaced by directional `HeaderKey` AEAD (`wire.go`, `crypto.go`). |
| **S-5** | `ReplayFilter` 10,000-entry full map wipe + 64-bit nonce + no NTP (`replay.go:34-63`) | Constant-memory (~1 MB) `SlidingBloomFilter` over full 256-bit `ClientSalt` + `ntp.TimeFuncFromContext(ctx)` (`replay.go`). |
| **S-6** | Zero forward secrecy, single-round unsalted `SHA-256(password)`, no weak-password check, no multi-user (`cipher.go:48-50`, `inbound.go:36`) | Ephemeral masked X25519 ECDHE (+ optional static key 0-RTT PFS), startup `Argon2id` (`>=16` chars enforced) or 32B Base64 key, multi-user `users` + `EIH` (`crypto.go`, `inbound.go`). |
| **S-7** | No handshake read deadline (Slowloris FD exhaustion) + zero failure logging (`conn.go:156-198`, `inbound.go:80-84`) | `HandshakeTimeout` (default `6s`), `handshakeSem` (cap `256`), separate bounded `drainSem`, and rate-limited security warning logs (`drain.go`, `inbound.go`). |
| **R-1** | `Read` holding `readMu` synchronously calls `sendControlFrame(FramePong)` locking `writeMu` -> TCP full-window deadlock (`conn.go:74-97, 259-261`) | `Read` sends non-blockingly to cap-1 `pongCh`; async writer coordinator sends `FramePong` without `Read` ever touching `writeMu` (`conn.go`). |
| **R-2** | Non-atomic `sendNonce++` before `Conn.Write` desynchronizes AEAD under `SetWriteDeadline` (`conn.go:79-93, 308-322`) | Atomic write-error fusing (`writeBroken` + socket close on any `Write` failure/short write) and deadline isolation for background control frames (`conn.go`). |
| **R-3** | `lastRead` written but never `Load()`ed -> Dead Peer Detection completely non-functional (`conn.go:35, 50-72`) | Jittered idle Ping (`0.75..1.25 * interval`) actively checks `c.lastRead.Load()` within `pong_timeout` and closes dead socket (`conn.go`). |
| **R-4** | Empty `FrameData` returns `(0, nil)` (`io.ErrNoProgress`), `default:` corrupts stream, server drops `header.Payload` (`conn.go:264-286`, `inbound.go:80-91`) | Empty `FrameData` loops as chaff; strict `FrameType` switch with error on unknown; server queues `InitialPayload` into `Conn` read buffer (`conn.go`, `inbound.go`). |
| **R-5** | `Multiplex` and `UDP` mutually broken; bare UDP misrouted to TCP (`outbound.go:62-75, 100-139`) | Full 3-mode UDP routing: `multiplexDialer.ListenPacket` -> `uotClient.ListenPacket` -> Native `CommandUDP` `PacketConn` (`outbound.go`, `inbound.go`). |
| **R-6** | Missing `Close()`, `InterfaceUpdated(ctx)`, `OutboundWithMultiplex`, and `rawConn` leak on header error (`outbound.go:26-93`, `conn.go:100-150`) | Full `OutboundWithMultiplex`, `InterfaceUpdated(ctx)`, `Close()`, `TCPInjectableInbound`, and leak-free error cleanup (`outbound.go`, `inbound.go`, `conn.go`). |
| **R-7** | 5 heap allocations per 16KB frame, 0% tests, missing `with_quic`, CI overwrites single release (`conn.go:246,304`, `build-linux-amd64.yml`) | `N.ExtendedConn` zero-copy `sing/common/buf` pools, KAT/Fuzz/`-race` test suite, full build tags, and `upstream-sync-release.yml` (`conn.go`, `*_test.go`, `.github/workflows/`). |

---

## 4. Underspecified Sub-Details Requiring Canonical Freezing in `PROJECT.md` (`U-1`..`U-15`)

While mining `AETHER_V2_DEVELOPMENT_PLAN.md` against the `sing-box` codebase, **15 sub-details** were found to be either underspecified or subtly inconsistent across sections. Freezing these canonical contracts in `PROJECT.md` before Phase 1 guarantees 100% deterministic interoperability across all agents:

### `U-1` — Config Field Naming (`password` vs `key`) & Base64 Disambiguation
- **Observation**: Plan § 2.1.1 (`line 57`) mentions `users: [{ "name": "node-gz", "key": "..." }]` and `單用戶簡寫 key / password`, whereas Plan § 三 (`lines 144-172`) defines `Password string json:"password"` in `AetherUser`, `AetherInboundOptions`, and `AetherOutboundOptions` without a `Key` field. Also Base64 vs passphrase precedence is not byte-specified.
- **Recommended Canonical Contract**:
  1. Keep `Password string json:"password,omitempty"` as primary field AND optionally add `Key string json:"key,omitempty"` alias on `AetherUser`, `AetherInboundOptions`, and `AetherOutboundOptions` (if `Password == ""` use `Key`; if both set and unequal, return config error; require at least one in single-user outbound, and either `Password`/`Key` or non-empty `Users` in inbound).
  2. Parse `uPSK`: try `base64.StdEncoding.DecodeString(secret)` (fallback `base64.RawStdEncoding` / `base64.RawURLEncoding` if 43 chars); if `err == nil && len(raw) == 32`, reject all-zero `[32]byte{}` and use `raw` directly as `uPSK`. Otherwise require `len(secret) >= 16` and derive `uPSK = argon2.IDKey([]byte(secret), []byte("AetherFlow-v2-KDF"), 3, 64*1024, 4, 32)`.

### `U-2` — Exact ChaCha20 Key & Nonce Derivation for `MaskedClientEPK` and `MaskedServerEPK`
- **Observation**: Plan § 2.1.2 (`line 61`) specifies `HKDF-SHA256(uPSK, Salt, "AetherFlow-v2-EPK-Mask")` to generate a ChaCha20 keystream, without specifying how the 32B key + 12B nonce for `chacha20.NewUnauthenticatedCipher` are sliced or which `Salt` masks `epk_s`.
- **Recommended Canonical Contract**:
  - Derive `44 bytes` from `hkdf.New(sha256.New, uPSK[:], salt[:], []byte("AetherFlow-v2-EPK-Mask"))`: `maskKey = out[0:32]`, `maskNonce = out[32:44]`.
  - For `MaskedClientEPK`: `salt = ClientSalt` (`32B`).
  - For `MaskedServerEPK`: `salt = ServerSalt` (`32B`).

### `U-3` — Client Handshake `initKey` HKDF Label & `EncryptedVarHeader` Nonce/AAD
- **Observation**: Plan § 2.1.2 (`line 63`) writes `initKey = HKDF(uPSK [|| X25519(ek_c, spk_s)], ClientSalt)` without quoting the `info` string, and § 2.2 (`lines 75-77`) specifies `ChaCha20-Poly1305` for `EncryptedFixedHeader` without stating the exact nonce/AAD for `EncryptedVarHeader`.
- **Recommended Canonical Contract**:
  - `initKey` (`32B`): `hkdf.New(sha256.New, ikm, ClientSalt[:], []byte("AetherFlow-v2-Client-Init"))` where `ikm = uPSK[:]` (`32B`) if no static key, or `uPSK[:] || ss_static[:]` (`64B`) if `public_key`/`private_key` is configured.
  - Use a single `initAEAD, _ := chacha20poly1305.New(initKey)`:
    - `EncryptedFixedHeader`: `nonce = encodeNonce(0)`, `AAD = ClientSalt || MaskedClientEPK [|| EIH]`.
    - `EncryptedVarHeader`: `nonce = encodeNonce(1)`, `AAD = FixedHeaderPlaintext` (`16B` raw `FixedHeader`, cryptographically binding `VarHeader` to `FixedHeader`).

### `U-4` — 12-Byte AEAD Nonce Byte Endianness
- **Observation**: Both `AES-256-GCM` and `ChaCha20-Poly1305` take 12-byte nonces (`NonceSize = 12`). Aether v1 (`cipher.go:117-126`) encoded `uint64` in Little-Endian `nonce[0:8]` with `nonce[8:12] = 0`, whereas `FixedHeader` uses Big-Endian.
- **Recommended Canonical Contract**:
  - Freeze `encodeNonce(seq uint64, nonce *[12]byte)`: `nonce[0..3] = 0`, `binary.BigEndian.PutUint64(nonce[4:12], seq)` (TLS 1.3 RFC 8446 standard Big-Endian 96-bit counter) OR `binary.LittleEndian.PutUint64(nonce[0:8], seq)` with `nonce[8..11] = 0` — either is cryptographically identical as long as one is frozen in `PROJECT.md` and covered by KAT tests.

### `U-5` — `masterSecret` Static-Key Mixing & Subkey HKDF Labels
- **Observation**: Plan § 2.1.2 (`line 64`) defines `masterSecret = HKDF-SHA256(uPSK || X25519(ek_c, epk_s), ClientSalt || ServerSalt, "AetherFlow-v2-Session")` (`32B`), and § 2.3.1 (`line 101`) splits directional `HeaderKey (32B)` and `PayloadKey (32B)` via `HKDF-SHA256` without listing exact subkey labels or which key/cipher encrypts `EncryptedRespHeader` (`20B`).
- **Recommended Canonical Contract**:
  - When optional `private_key`/`public_key` is configured, include `ss_static = X25519(ek_c, spk_s)` in session IKM (`uPSK || ss_eph || ss_static`, `96B`; otherwise `uPSK || ss_eph`, `64B`) so server static identity is also authenticated.
  - Derive `masterSecret` (`32B`) via `hkdf.New(sha256.New, ikmSession, append(ClientSalt, ServerSalt...), []byte("AetherFlow-v2-Session"))`.
  - Derive 5 distinct `32B` keys via `hkdf.Expand(sha256.New, masterSecret, []byte(label))` (since `masterSecret` is already a uniform 32B HKDF output):
    - `"AetherFlow-v2-Resp"` -> `respKey` (`32B`), encrypted with `ChaCha20-Poly1305` (or negotiated `CipherSuite`), `nonce = 0`, `AAD = ClientSalt || ServerSalt || MaskedServerEPK` (`96B`).
    - `"AetherFlow-v2-C2S-Header"` -> `c2sHeaderKey` (`32B`, negotiated `CipherSuite`)
    - `"AetherFlow-v2-C2S-Payload"` -> `c2sPayloadKey` (`32B`, negotiated `CipherSuite`)
    - `"AetherFlow-v2-S2C-Header"` -> `s2cHeaderKey` (`32B`, negotiated `CipherSuite`)
    - `"AetherFlow-v2-S2C-Payload"` -> `s2cPayloadKey` (`32B`, negotiated `CipherSuite`)

### `U-6` — CRITICAL: `EIH` Client-Server Wire Length & Multi-User Lookup Construction
- **Observation**:
  1. Plan § 2.2 (`lines 74, 88`) states `EIH` is `0 Bytes` (96B prefix) in single-user mode and `16 Bytes` (112B prefix) in multi-user mode, **HOWEVER** `AetherOutboundOptions` (§ 三 `lines 161-172`) has NO field (`user`, `multi_user`, or `server_password`) telling the client whether the remote server was configured with `password` (single-user) or `users` (multi-user)! If a client sends 96B to a multi-user server expecting 112B (or vice versa), the handshake will 100% fail!
  2. Furthermore, without a separate server-wide `iPSK` on `AetherOutboundOptions`, a static `EIH = H(uPSK)[0:16]` would create a linkable 16B static fingerprint on the wire (violating uniform randomness), whereas a salted `EIH = HMAC-SHA256(uPSK, ClientSalt)[0:16]` is 100% uniform random per connection!
- **Recommended Canonical Contract**:
  1. **Unify the wire prefix to ALWAYS include the `16-Byte EIH` (`112 Bytes` fixed client prefix in ALL modes: `ClientSalt(32B) || MaskedClientEPK(32B) || EIH(16B) || EncryptedFixedHeader(32B)`)**!
     - Single-user Inbound simply normalizes `Password` into a 1-element `users` table internally.
     - Zero wire mismatch between client and server — the client never needs to know whether the server has 1 user or 100 users!
  2. **EIH Construction**:
     - If `ServerPublicKey` (`spk_s`) is NOT configured: `EIH = HMAC-SHA256(key=uPSK, msg=ClientSalt || "AetherFlow-v2-EIH")[0:16]`. On the server, computing one 1-block `HMAC-SHA256` per configured user over `ClientSalt` (using precomputed SHA-256 `ipad`/`opad` state per user!) takes ~`80 ns`/user (`< 8 µs` for 100 dedicated-line users, constant-time across users) while keeping every single wire byte 100% indistinguishable from CSPRNG noise with zero extra config keys! (And if `iPSK` or `spk_s` IS additionally desired for `O(1)` map indexing at 100,000+ users, note that dedicated-line transit nodes have `1..100` users where precomputed-state HMAC scan is sub-microsecond and leaks zero timing/identity).

### `U-7` — `VarHeader` `TargetAddr` Encoding for `Sing-Mux` (`0x03`) & `UoT` (`0x04`)
- **Observation**: `mux.Client` dials `mux.Destination` (`sp.mux.sing-box.arpa:444`) and `uot.Client` dials `uot.RequestDestination(version)` (`sp.v2.udp-over-tcp.arpa:0` or `sp.v1.udp-over-tcp.arpa:0`), and `muxRouter` / `uotRouter` dispatch based on `metadata.Destination`.
- **Recommended Canonical Contract**:
  - Always serialize `destination` via `M.SocksaddrSerializer.WriteAddrPort` / `ReadAddrPort` in `VarHeader` for ALL 4 commands (`0x01 TCP`, `0x02 Native UDP`, `0x03 Sing-Mux`, `0x04 UoT`)!
  - On Outbound (`aetherDialer.DialContext`):
    - If `destination == mux.Destination`: set `Command = 0x03` (`CommandMux`).
    - Else if `destination.Fqdn == uot.MagicAddress || destination.Fqdn == uot.LegacyMagicAddress`: set `Command = 0x04` (`CommandUoT`).
    - Else if `N.NetworkName(network) == N.NetworkUDP`: set `Command = 0x02` (`CommandUDP`).
    - Else: set `Command = 0x01` (`CommandTCP`).
  - On Inbound:
    - For `0x01`, `0x03`, `0x04`: pass `ServerConn` (seeded with `InitialPayload`) + `metadata` (`metadata.Destination = parsedTargetAddr`) into `in.router.RouteConnectionEx(ctx, aetherConn, metadata, onClose)` (where `in.router` wraps `mux.NewRouterWithOptions(uot.NewRouter(router, logger), ...)`).
    - For `0x02` (`CommandUDP`): wrap `ServerConn` in `&PacketConn{conn: aetherConn}` and call `in.router.RoutePacketConnectionEx(ctx, packetConn, metadata, onClose)`.

### `U-8` — `RespHeader` 4-Byte Plaintext Layout
- **Observation**: Plan § 2.2 (`line 96`) specifies `EncryptedRespHeader` = `4 + 16(Tag) = 20 Bytes` without naming the 4 plaintext bytes.
- **Recommended Canonical Contract**:
  - `RespHeader [4]byte`:
    - `RespHeader[0]` = `0x02` (`Version`)
    - `RespHeader[1]` = `0x00` (`StatusOK`)
    - `RespHeader[2]` = `CipherSuite` echoed (`0x01` or `0x02`, confirming cipher binding)
    - `RespHeader[3]` = `0x00` (`Reserved`)
  - Client verifies `RespHeader[0] == 0x02 && RespHeader[1] == 0x00 && RespHeader[2] == expectedCipher && RespHeader[3] == 0x00`.

### `U-9` — `sing-box generate aether-keypair` CLI Output Format
- **Observation**: `wg-keypair` uses `base64.StdEncoding` (`44` chars with `=`), whereas `reality-keypair` uses `base64.RawURLEncoding` (`43` chars).
- **Recommended Canonical Contract**:
  - `sing-box generate aether-key`: prints `<base64.StdEncoding(32B)>\n` (`44` chars + `\n`).
  - `sing-box generate aether-keypair`: prints:
    ```text
    PrivateKey: <base64.StdEncoding(priv32B)>
    PublicKey: <base64.StdEncoding(pub32B)>
    ```
  - Key parser in `crypto.go` accepts `StdEncoding`, `RawStdEncoding`, `URLEncoding`, and `RawURLEncoding` for maximum operator ergonomics.

### `U-10` — `PlainFrameLen` Upper Bound (`16641` vs `16384`)
- **Observation**: Plan § 2.3.2 (`line 107`) specifies `16384B` max data payload with `36B` protocol overhead (`18B` header + `2B` `FrameType|PadLen` + `16B` tag). Thus a full `16384B` frame has `PlainFrameLen = 16386` (unpadded) or up to `16641` (with max `255B` padding).
- **Recommended Canonical Contract**:
  - `MaxPayloadSize = 16384`
  - `MaxPaddingSize = 255`
  - `FrameHeaderMetaSize = 2` (`FrameType` 1B + `PadLen` 1B)
  - `MaxPlainFrameLen = FrameHeaderMetaSize + MaxPaddingSize + MaxPayloadSize` = **`16641`**
  - Receiver validates `PlainFrameLen >= 2 && PlainFrameLen <= 16641`.

### `U-11` — Head-Only Shaping (`Frame 0..5`) Burst Split Range
- **Observation**: Plan § 2.3.2 (`line 106`) specifies that during `Frame 0..5` (when `!disable_shaping`), writes `> 1200B` are randomly split and given `16..255B` random padding, without specifying the split chunk range.
- **Recommended Canonical Contract**:
  - While `!disableShaping && sendFrameIdx < 6`:
    - If remaining write bytes `> 1200`, choose random chunk data size uniformly in **`512..1100` bytes** for the current frame, attach random `PadLen` in **`16..255` bytes**, and increment `sendFrameIdx`. Once `sendFrameIdx >= 6`, emit remaining bytes in chunks up to `16384B` with `PadLen = 0`.

### `U-12` — Native UDP (`CommandUDP = 0x02`) Stream Framing Layout
- **Observation**: Plan § 2.5.4 & Phase 2.1 require Native `CommandUDP` bidirectional UDP packet framing over the encrypted stream without specifying exact per-packet header bytes.
- **Recommended Canonical Contract**:
  - Per UDP packet inside `Conn`: `[Socksaddr via M.SocksaddrSerializer (7..259B)] || [PayloadLen uint16 BE (2B)] || [Payload (PayloadLen B)]`.
  - `PacketConn.FrontHeadroom()` returns `M.MaxSocksaddrLength + 2` (`261` bytes).

### `U-13` — `SlidingBloomFilter` Rotation Period & Seeded Hashing
- **Observation**: For `TimeWindow = 30s` (`±30s` = `60s` total validity span), a 2-generation (`current` + `previous`) Bloom filter rotating every `30s` only guarantees `[30s, 60s]` retention (allowing a `+29s`-skewed packet accepted at `t=29.9s` to be replayed at `t=60.1s`).
- **Recommended Canonical Contract**:
  - Rotate `current` -> `previous` every **`2 * TimeWindow`** (`60s` for default `30s` `TimeWindow`), guaranteeing `[60s, 120s]` retention across `±30s` clock skew!
  - Size: `2 * 4,194,304` bits (`2 * 65536` `uint64` = `1 MiB` total), `k = 6` bit indices derived from `HMAC-SHA256(bloomRandomSeed, ClientSalt)` (or keyed SipHash/SHA-256 over `bloomSeed || ClientSalt`), checked/inserted ONLY AFTER `EncryptedFixedHeader` AEAD authentication succeeds.

### `U-14` — Heartbeat Default, Disablement & `pong_timeout` Value
- **Observation**: Plan § 2.5.3 (`line 127`) references `pong_timeout`, and § 三 (`lines 156, 168`) sets `heartbeat_interval` default to `30s` (`badoption.Duration`), without specifying `pong_timeout`'s exact duration or how to disable heartbeats if needed.
- **Recommended Canonical Contract**:
  - Default `HeartbeatInterval` when `0`: `30 * time.Second` (negative duration `< 0` disables keepalive in tests if needed).
  - Idle Ping trigger: when both `since(lastWrite)` and `since(lastRead)` exceed `HeartbeatInterval * uniform(0.75, 1.25)`.
  - `PongTimeout`: `max(10 * time.Second, HeartbeatInterval / 2)` (`15s` when `HeartbeatInterval == 30s`); if no frame is read (`c.lastRead.Load() < pingSentAt`) before `pingSentAt + PongTimeout`, close `c.Conn` immediately.

### `U-15` — `Multiplex` vs `UDPOverTCP` Precedence & `upstream-sync-release.yml` Branch Target
- **Observation**:
  1. `AetherOutboundOptions` allows configuring both `multiplex` and `udp_over_tcp`.
  2. Phase 4.2 (`upstream-sync-release.yml`) normally syncs a release branch, while Sentinel dispatch forbids touching `main` during this task.
- **Recommended Canonical Contract**:
  1. Outbound UDP Precedence:
     - Always initialize `multiplexDialer` if `options.Multiplex != nil && options.Multiplex.Enabled` (NEVER silently disable `multiplex` when `udp_over_tcp` is also set!).
     - If `multiplexDialer != nil`: route both `DialContext` and `ListenPacket` (TCP & UDP) through `multiplexDialer`.
     - Else if `uotClient != nil` (`udp_over_tcp.enabled == true`): route UDP `DialContext` and `ListenPacket` through `uotClient`.
     - Else: route UDP `DialContext` (via `bufio.NewBindPacketConn`) and `ListenPacket` through Native `CommandUDP` (`0x02`) `PacketConn`.
  2. Workflow Branch Safety:
     - Write `.github/workflows/upstream-sync-release.yml` on branch `dev/aether-v2` (do NOT touch `main`), parameterized via `${{ github.ref_name }}` (defaulting to current branch on schedule/dispatch) so it operates cleanly without mutating `main`.
