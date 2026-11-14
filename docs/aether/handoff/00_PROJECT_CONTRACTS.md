# Project: AetherFlow-v2 (`dev/aether-v2`)

- **Repository**: `.` (`kofttlcc/Aether-sing-box`)
- **Active Branch**: `dev/aether-v2` (STRICT BRANCH ISOLATION: `main` at `fdaa4c455761bd6ca9d336d6dd09acb3639b34f1` MUST NEVER BE MODIFIED, MERGED INTO, OR PUSHED TO)
- **Target Upstream Baseline**: `SagerNet/sing-box` `v1.14.4` (`c005f35300ce76427dc285481ec5695f5b179cd2`)
- **Authoritative Sources**:
  - `.agents/teamwork/ORIGINAL_REQUEST.md`
  - `docs/aether/AETHER_V2_DEVELOPMENT_PLAN.md`
  - `docs/aether/AETHER_V1_SECURITY_AUDIT.md`
  - Step 0 Survey Artifacts:
    - `docs/aether/handoff/01_SPEC_INVENTORY.md`
    - `docs/aether/handoff/02_SINGBOX_V1144_API_SURVEY.md`
    - `docs/aether/handoff/03_CI_AND_UPSTREAM_SYNC_SURVEY.md`

---

## Architecture

Aether v2 (`AetherFlow-v2`) is a dedicated-line (IPLC/IEPL/cross-carrier transit) pure-binary proxy protocol built natively into `sing-box` (`v1.14.4`) **without outer TLS, certificates, SNI, or V2Ray transport wrappers** and **with zero new external Go module dependencies**:

1. **Configuration & CLI Layer (`option/aether.go`, `cmd/sing-box/cmd_generate_aether.go`)**:
   - Streamlined pure-binary `AetherInboundOptions`, `AetherOutboundOptions`, and `AetherUser` using `badoption.Duration`, `enum` schema tags, single-user & multi-user configuration, optional static X25519 0-RTT PFS keys, and CLI generators `sing-box generate aether-key` / `sing-box generate aether-keypair`.
2. **Cryptographic & Anti-Replay Core (`protocol/aether/crypto.go`, `protocol/aether/replay.go`)**:
   - Base64 32B CSPRNG master key fast-path or startup-only `Argon2id` (`time=3, mem=64MiB, threads=4`) passphrase strengthening (`>=16` chars enforced; weak/empty/all-zero keys rejected).
   - Per-connection ephemeral `X25519` ECDHE key exchange with ChaCha20 stream masking over `epk_c` / `epk_s` (eliminating Curve25519 bit-255 `== 0` statistical bias), optional static `X25519` 0-RTT PFS mixing, dual-salt (`ClientSalt || ServerSalt`) `HKDF-SHA256` session ratchet, and hardware-accelerated `AES-256-GCM` / `ChaCha20-Poly1305` auto-negotiation.
   - Multi-user authentication supporting both `O(1)` salted `EIH` (`16B`, 112B prefix when server `password` `iPSK` + `users` are configured) and `users`-only mode (96B prefix when inbound `password` is empty).
   - Constant-memory (~1 MiB) 2-generation `SlidingBloomFilter` over full `[32]byte` `ClientSalt` rotating every `2 * TimeWindow` (`60s` default) + NTP-aware `ntp.TimeFuncFromContext(ctx)` timestamp validation (`±30s`), checked strictly *after* AEAD fixed-header verification.
3. **Wire Framing, Head-Only Shaping & Zero-Copy Flow-Controlled Connection (`protocol/aether/wire.go`, `protocol/aether/conn.go`, `protocol/aether/packet.go`)**:
   - Oracle-free 96B (or 112B with EIH) authenticated fixed client prefix verified before reading `VarHeaderLen`; coalesced 0-RTT Client Initial Burst (`EarlyWriter`/`EarlyReader`) and coalesced 84B Server Response Prefix.
   - Two-block independent-key AEAD framing (`18B` encrypted length header + `PlainFrameLen+16B` encrypted payload body) serialized into a **single pooled `*buf.Buffer` `Write`** (zero 2-byte split TCP segments).
   - Head-only shaping on `Frame 0..5` (`16..255B` random padding + splitting writes `>1200B` into `512..1100B` chunks), switching to `PadLen=0` from `Frame 6+` (`36B` wire overhead = `0.2197%` per `16384B` payload).
   - Non-blocking cap-1 `pongCh` decoupling `Read` from `Write` (`R-1`), atomic write-error fusing & deadline isolation (`R-2`), idle jittered `FramePing` (`32..224B`) + `lastRead` Dead Peer Detection (`R-3`), chaff-skipping strict `FrameType` handling + `CloseWrite` (`R-4`), and Native Framed UDP `PacketConn` (`CommandUDP = 0x02`, `R-5`).
4. **Adapter & Stealth Anti-Probe Layer (`protocol/aether/drain.go`, `protocol/aether/inbound.go`, `protocol/aether/outbound.go`)**:
   - Bounded `handshakeSem` (`256`) + separate `drainSem` (`512`) + `6s` `HandshakeTimeout` + `3s..10s` per-connection uniform random `StealthDrain` closing via normal TCP `FIN` (never `SetLinger(0)` `RST` or `200ms` oracle) + rate-limited IP audit logs (`S-7`).
   - Full `sing-box v1.14.4` `adapter.Lifecycle` (`Start(stage, scope)`), `TCPInjectableInbound`, `OutboundWithMultiplex`, `InterfaceUpdateListener`, `IdleConnectionKeeper`, and seamless 3-mode UDP routing (`Multiplex` -> `UoT` -> Native `CommandUDP`).
5. **CI/CD & Upstream Sync Automation (`.github/workflows/`)**:
   - Fixed `docker.yml` and `linux.yml` (inherited `release: published` misfires disabled) and modernized `build-linux-amd64.yml`.
   - New `.github/workflows/upstream-sync-release.yml` (weekly `cron: '0 2 * * 1'` + `workflow_dispatch`) syncing official non-prerelease `SagerNet/sing-box` releases, preserving `.github/workflows/`, running `go test -race ./protocol/aether/...`, building full-tag binaries, and publishing releases in a single job.

---

## Feature Inventory

Every feature discovered in Step 0 Survey (`spec_inventory.md` F1–F27) is mapped below with zero unassigned items:

| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| F1 | Upstream `v1.14.4` Merge & Git Hygiene | Add `.agents/` to `.git/info/exclude`; fetch & merge `SagerNet/sing-box` `v1.14.4` (`c005f353...`) on `dev/aether-v2`; set `constant.Version = "1.14.4-Custom-Aether"`; adapt `inbound`/`outbound` to `v1.14.4` `Start(stage, scope)` | M1 | survey (`spec_miner_survey_1`, `explorer_survey_2`) |
| F2 | CI Workflow Fixes (`docker.yml`, `linux.yml`, `build-linux-amd64.yml`) | Disable `release: [published]` in both `docker.yml` and `linux.yml`; update `build-linux-amd64.yml` Go version, `with_quic,with_acme,badlinkname,tfogo_checklinkname0`, `release/LDFLAGS`, `-race` test gate, dynamic version/tag | M1 | survey (`explorer_survey_3`) |
| F3 | CLI `sing-box generate aether-key` | Generate 32-byte CSPRNG `base64.StdEncoding` master key (`44` chars + `\n`) | M1 | survey (`spec_miner_survey_1`) |
| F4 | CLI `sing-box generate aether-keypair` | Generate static X25519 keypair (`PrivateKey: ...\nPublicKey: ...\n` in `base64.StdEncoding`) | M1 | survey (`spec_miner_survey_1`) |
| F5 | `uPSK` Loading & Argon2id Hardening (`S-6`) | 32B Base64 fast path (rejecting all-zero key) or startup `Argon2id(pw, "AetherFlow-v2-KDF", 3, 64*1024, 4, 32)` enforcing `len >= 16` | M2 | survey (`spec_miner_survey_1`) |
| F6 | Stream-Masked Ephemeral X25519 (`S-6`) | Per-connection `crypto/ecdh.X25519()` with ChaCha20 keystream mask (`HKDF-SHA256(uPSK, Salt, "AetherFlow-v2-EPK-Mask")`), uniform byte distribution (no MSB=0 bias) | M2 | survey (`spec_miner_survey_1`) |
| F7 | Optional Static X25519 0-RTT PFS | Mix `ss_static = X25519(ek_c, spk_s)` into `initKey` and `masterSecret` when `private_key` / `public_key` are configured | M2 | survey (`spec_miner_survey_1`) |
| F8 | Dual-Salt X25519 Session Key Ratchet (`S-3`) | `masterSecret = HKDF-SHA256(ikmSession, ClientSalt \|\| ServerSalt, "AetherFlow-v2-Session")` -> 5 domain-separated 32B subkeys (`Resp`, `C2S-Header`, `C2S-Payload`, `S2C-Header`, `S2C-Payload`) | M2 | survey (`spec_miner_survey_1`) |
| F9 | Hardware AEAD Auto-Negotiation | Detect CPU AES+carryless-multiply (`golang.org/x/sys/cpu`) to auto-select `AES-256-GCM` (`0x01`) vs `ChaCha20-Poly1305` (`0x02`), or honor explicit `cipher` option | M2 | survey (`spec_miner_survey_1`, `explorer_survey_2`) |
| F10 | Multi-User `EIH` & `users` Authentication (`S-6`) | Support `O(1)` salted 16B `EIH` (`112B` prefix with `<iPSK>:<uPSK>`) AND `users`-only mode (`96B` prefix when server `password` is empty), populating `metadata.User` | M2, M4 | survey (`spec_miner_survey_1`) |
| F11 | Authenticated Fixed-Size Client Prefix (`S-1`) | Server reads exact 96B (or 112B EIH) fixed prefix and verifies ChaCha20-Poly1305 tag + timestamp + Bloom filter BEFORE reading `VarHeaderLen` | M3 | survey (`spec_miner_survey_1`) |
| F12 | Authenticated `VarHeader` & 0-RTT Payload (`R-4`) | Decrypt `VarHeaderLen + 16B` (`AAD = FixedHeaderPlaintext[16]`) containing `NoisePadding (32..384B)` + `M.SocksaddrSerializer` `TargetAddr` + 0-RTT `InitialPayload` | M3 | survey (`spec_miner_survey_1`) |
| F13 | Coalesced 84B Server Response Prefix | Prepend `ServerSalt(32B) \|\| MaskedServerEPK(32B) \|\| EncryptedRespHeader(20B)` (`RespHeader = [0x02, 0x00, CipherSuite, 0x00]`) to first downlink frame in single write | M3 | survey (`spec_miner_survey_1`) |
| F14 | Two-Block Independent-Key AEAD Data Frame (`S-2`, `S-4`) | `18B` AEAD length header + `PlainFrameLen+16B` AEAD body (`PlainFrameLen` in `2..16641`) written in a single `*buf.Buffer` `Write`; delete `noise.go` `MaskLength` | M3, M4 | survey (`spec_miner_survey_1`) |
| F15 | Head-Only First-6-Frames Shaping (`S-2`) | `Frame 0..5` (unless `disable_shaping`): `16..255B` random padding + split writes `>1200B` into `512..1100B`; `Frame 6+`: `PadLen=0`, max `16384B` data (`<0.22%` overhead) | M3 | survey (`spec_miner_survey_1`) |
| F16 | Strict Frame Types & TCP Half-Close (`R-4`) | `0x01=Data` (skip 0-len chaff without returning `(0, nil)`), `0x02=Ping` (`32..224B`), `0x03=Pong` (`32..224B`), `0x04=CloseWrite`; error on unknown byte | M3 | survey (`spec_miner_survey_1`) |
| F17 | Native Framed UDP (`CommandUDP = 0x02`) (`R-5`) | Stream-framed `[Socksaddr][uint16 BE Len][Payload]` `PacketConn` (`N.PacketConn` + `net.PacketConn`) supporting Full-Cone `ListenPacket` and bound `DialContext("udp")` | M3, M4 | survey (`spec_miner_survey_1`, `explorer_survey_2`) |
| F18 | Dual-Generation Sliding Bloom Anti-Replay (`S-5`) | ~1 MiB (`2 * 65536 uint64`, `k=6`) rotating Bloom filter over `[32]byte` `ClientSalt` (`2 * TimeWindow` = `60s` rotation) + `ntp.TimeFuncFromContext(ctx)` (`±30s`), zero full wipes | M2 | survey (`spec_miner_survey_1`) |
| F19 | Handshake Semaphore & `3s..10s` Stealth Drain (`S-7`) | `handshakeSem` (`256`) + `drainSem` (`512`) + `HandshakeTimeout` (`6s`) + uniform `3s..10s` silent drain closing with normal TCP `FIN` (never `RST` or `200ms`) + rate-limited IP logs | M4 | survey (`spec_miner_survey_1`, `explorer_survey_2`) |
| F20 | Non-Blocking `pongCh` Control Plane (`R-1`) | Cap-1 `pongCh` decouples `Read` from `FramePong` `Write`; `Read` never acquires `writeMu` or blocks on full TCP send window | M3 | survey (`spec_miner_survey_1`) |
| F21 | Atomic Write Error Fusing & Deadline Isolation (`R-2`) | Isolate app `SetWriteDeadline` from background control frames; atomically fuse `writeBroken` and close socket on any `Conn.Write` error/short write | M3 | survey (`spec_miner_survey_1`) |
| F22 | Idle Jittered Heartbeat & `lastRead` DPD (`R-3`) | Idle `FramePing` after `HeartbeatInterval * uniform(0.75, 1.25)` (`30s` default); close socket if `lastRead.Load()` fails to advance within `PongTimeout` | M3 | survey (`spec_miner_survey_1`) |
| F23 | Zero-Copy `N.ExtendedConn` & 0-RTT `DialEarlyConn` (`R-6`, `R-7`) | Pooled `*buf.Buffer` `ReadBuffer`/`WriteBuffer`, `EarlyWriter`+`EarlyReader`+`EarlyConn`, `FrontHeadroom`/`RearHeadroom`/`WriterMTU`, strict buffer release ownership | M3 | survey (`explorer_survey_2`) |
| F24 | Full `sing-box v1.14.4` Inbound & Outbound Integration (`R-5`, `R-6`) | `TCPInjectableInbound`, `Start(stage, scope)`, `OutboundWithMultiplex`, `InterfaceUpdated`, `IdleConnectionKeeper`, `Close`, and simultaneous `Multiplex` + `UoT` + `CommandUDP` | M4 | survey (`explorer_survey_2`) |
| F25 | Pure-Binary `option/aether.go` & JSON Schema | Streamlined v2 options (`AetherUser`, `AetherInboundOptions`, `AetherOutboundOptions`, `Key` alias, `Cipher` enum tag), validated by `sing-box check` and `sing-box schema` | M1 | survey (`spec_miner_survey_1`, `explorer_survey_3`) |
| F26 | Weekly Upstream `SagerNet/sing-box` Sync & Release Action | `.github/workflows/upstream-sync-release.yml` (`cron: '0 2 * * 1'` + `workflow_dispatch`), stable-only check, `.github/workflows/` preservation, `-race` test gate, single-job multi-arch release | M5 | survey (`explorer_survey_3`) |
| F27 | Unit/KAT, `-race` Stress, Go Fuzzing, PCAP & Tiers 1–5 E2E Verification | Full unit/KAT (`M2`,`M3`), `FuzzHandshake`/`FuzzFrameStream` + `-race` small-window saturation + PCAP wire-tap (`M4`), opaque-box Tiers 1–4 E2E (`E2E-Track` + `M6`), Tier 5 adversarial white-box hardening (`M6`) | M2, M3, M4, E2E-Track, M6 | survey (`spec_miner_survey_1`, `explorer_survey_3`) |

---

## Milestones

| # | Name | Scope | Dependencies | Status |
|---|------|-------|--------------|--------|
| **M1** | Phase 0 Baseline, `v1.14.4` Sync, Options, CLI Keygen & CI Fixes | `.git/info/exclude` (`.agents/`), merge `SagerNet/sing-box` `v1.14.4` on `dev/aether-v2`, `constant/version.go` (`1.14.4-Custom-Aether`), v2 `option/aether.go` + compile shim in `protocol/aether/{inbound,outbound}.go`, `cmd/sing-box/cmd_generate_aether.go` (+ tests), fix `docker.yml`, `linux.yml`, `build-linux-amd64.yml`, commit Phase 0 on `dev/aether-v2` | none | DONE (`786d20d` + `ea7a70b`, Gate PASS) |
| **M2** | Phase 1 PFS Crypto Core & Dual-Gen Sliding Bloom Filter | `protocol/aether/crypto.go` (+ `crypto_test.go` KATs, Argon2id/Base64, masked X25519, static 0-RTT PFS, dual-salt HKDF, AES/ChaCha auto-detect, EIH) and `protocol/aether/replay.go` (+ `replay_test.go` 1M-entry & skew/race tests) | M1 | IN_PROGRESS (Step 2B.a Explorers) |
| **M3** | Phase 2 Wire Framing, 6-Frame Shaping, Zero-Copy `Conn` & `EarlyConn` | `protocol/aether/wire.go`, `protocol/aether/conn.go`, `protocol/aether/packet.go` (+ `wire_test.go`, `conn_test.go`): 96B/112B prefix, 84B resp prefix, 18B AEAD length frame, single-`Write` `*buf.Buffer`, 6-frame shaping, `EarlyWriter`/`EarlyReader`, `pongCh`, atomic write fusing, jittered Ping/`lastRead` DPD, Native `CommandUDP` `PacketConn` | M2 | PLANNED |
| **M4** | Phase 3 Inbound/Outbound v2, Stealth Drain & Fuzz/Race/PCAP Suite | `protocol/aether/drain.go`, `protocol/aether/inbound.go`, `protocol/aether/outbound.go`, delete legacy v1 `{cipher,frame,noise,probe_guard}.go`, add `drain_test.go`, `fuzz_test.go` (`FuzzHandshake`, `FuzzFrameStream`), `stress_race_test.go`, and `pcap_test.go` (wire-tap `.pcap` verification) | M3 | PLANNED |
| **M5** | Phase 4 Weekly Upstream Sync & Release GitHub Action + Docs/Schema | Implement `.github/workflows/upstream-sync-release.yml` on `dev/aether-v2` (with YAML/script dry-run verification tests), regenerate/verify `sing-box schema`, update Aether v2 usage docs if needed (`main` strictly untouched) | M4 | PLANNED |
| **E2E-Track** | Opaque-Box Requirement-Driven E2E Suite (Tiers 1–4) | Parallel E2E Testing Track creating `.agents/teamwork/TEST_INFRA.md`, opaque-box harness & Tiers 1–4 test suite in `protocol/aether/e2e/*_test.go` (`package e2e_test`), publishing `.agents/teamwork/TEST_READY.md` | M1 | IN_PROGRESS (Step 2B.a Explorers) |
| **M6** | Final Milestone: 100% E2E Pass (Tiers 1–4) + Tier 5 Adversarial Hardening + Clean Git Push | Phase 1: Pass 100% of E2E Tiers 1–4 under `-race`. Phase 2: Tier 5 white-box adversarial coverage hardening (`2` Challengers -> Worker -> Reviewer/Auditor loop until 0 gaps). Final verification: clean commits on `dev/aether-v2`, push `origin/dev/aether-v2`, verify `main` (`fdaa4c4`) untouched & `.agents/` excluded | M4, M5, E2E-Track | PLANNED |

---

## Interface Contracts

All agents MUST adhere byte-for-byte to these canonical contracts (resolving `U-1`..`U-15` from Step 0 Survey):

### 1. Environment & Git Rules
- **Go Proxy in VM**: Always run Go commands that may inspect modules with `GOPROXY=direct GOSUMDB=off`.
- **Standard Full Build Command**:
  ```bash
  GOPROXY=direct GOSUMDB=off CGO_ENABLED=0 go build -trimpath \
    -tags "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,badlinkname,tfogo_checklinkname0" \
    -ldflags "-X 'github.com/sagernet/sing-box/constant.Version=1.14.4-Custom-Aether' $(cat release/LDFLAGS) -s -w -buildid=" \
    -o /tmp/sing-box-bin ./cmd/sing-box
  ```
- **Branch & Git Index Safety**:
  - Stay strictly on `dev/aether-v2`. **NEVER** checkout, modify, merge into, or push `main` (`fdaa4c455761bd6ca9d336d6dd09acb3639b34f1`).
  - `.agents/` MUST be in `.git/info/exclude` and MUST NEVER be staged or committed.
  - While `E2E-Track` (`protocol/aether/e2e/`) and `M2..M5` (`protocol/aether/*.go`, `.github/workflows/upstream-sync-release.yml`) execute in parallel after `M1`, workers MUST NOT run `git add` or `git commit` (avoiding `.git/index.lock` races); clean commits on `dev/aether-v2` are performed in `M1` (alone) and `M6` (after tracks synchronize).

### 2. Configuration Structs (`option/aether.go` — `U-1`, `U-9`)
```go
package option

import "github.com/sagernet/sing/common/json/badoption"

type AetherUser struct {
	Name     string `json:"name,omitempty"`
	Password string `json:"password,omitempty"`
	Key      string `json:"key,omitempty"` // Alias for Password if Password == ""
}

type AetherInboundOptions struct {
	ListenOptions
	Password          string                   `json:"password,omitempty"`
	Key               string                   `json:"key,omitempty"` // Alias for Password if Password == ""
	Users             []AetherUser             `json:"users,omitempty"`
	ServerPrivateKey  string                   `json:"private_key,omitempty"`
	TimeWindow        badoption.Duration       `json:"time_window,omitempty"`        // Default 30s
	HandshakeTimeout  badoption.Duration       `json:"handshake_timeout,omitempty"`  // Default 6s
	HeartbeatInterval badoption.Duration       `json:"heartbeat_interval,omitempty"` // Default 30s
	DisableShaping    bool                     `json:"disable_shaping,omitempty"`
	Multiplex         *InboundMultiplexOptions `json:"multiplex,omitempty"`
}

type AetherOutboundOptions struct {
	DialerOptions
	ServerOptions
	Network           NetworkList               `json:"network,omitempty"`
	Password          string                    `json:"password,omitempty"`
	Key               string                    `json:"key,omitempty"` // Alias for Password if Password == ""
	Cipher            string                    `json:"cipher,omitempty" enum:"auto,aes-256-gcm,chacha20-poly1305"`
	ServerPublicKey   string                    `json:"public_key,omitempty"`
	HeartbeatInterval badoption.Duration        `json:"heartbeat_interval,omitempty"` // Default 30s
	DisableShaping    bool                      `json:"disable_shaping,omitempty"`
	Multiplex         *OutboundMultiplexOptions `json:"multiplex,omitempty"`
	UDPOverTCP        *UDPOverTCPOptions        `json:"udp_over_tcp,omitempty"`
}
```
- **Secret Resolution (`ResolveSecret(password, key string) (string, error)`)**:
  - If `password != "" && key != "" && password != key`: return error (`conflicting password and key`).
  - Use whichever is non-empty; if both empty, return empty string.
- **CLI Output (`cmd/sing-box/cmd_generate_aether.go` — `U-9`)**:
  - `sing-box generate aether-key`: 32 CSPRNG bytes encoded with `base64.StdEncoding.EncodeToString` + `\n` (`44` chars + newline).
  - `sing-box generate aether-keypair`: X25519 keypair via `ecdh.X25519().GenerateKey(rand.Reader)` outputting:
    ```text
    PrivateKey: <base64.StdEncoding(priv32B)>
    PublicKey: <base64.StdEncoding(pub32B)>
    ```

### 3. Cryptographic Primitives & Key Schedule (`protocol/aether/crypto.go` — `U-1`..`U-6`)
- **`DerivePSK(secret string) ([32]byte, error)`**:
  1. If `len(secret) == 0`: return error (`empty password/key`).
  2. Try decoding `secret` with `base64.StdEncoding`, `base64.RawStdEncoding`, `base64.URLEncoding`, `base64.RawURLEncoding`: if `err == nil && len(decoded) == 32`:
     - If `decoded` is all zeros (`[32]byte{}`), return error (`all-zero key rejected`).
     - Return `[32]byte(decoded), nil`.
  3. Otherwise, require `len(secret) >= 16` (if `< 16`, return error `weak password: must be a 32-byte Base64 key or passphrase >= 16 characters`).
  4. Return `argon2.IDKey([]byte(secret), []byte("AetherFlow-v2-KDF"), 3, 64*1024, 4, 32)`.
- **12-Byte AEAD Nonce Encoding (`U-4`)**:
  - `nonce[0..3] = 0`, `binary.BigEndian.PutUint64(nonce[4:12], seq)`.
- **Ephemeral X25519 ChaCha20 Stream Mask (`U-2`)**:
  - `hkdfOut := HKDF-SHA256(ikm=uPSK[:], salt=salt32[:], info="AetherFlow-v2-EPK-Mask", len=44)`
  - `stream, _ := chacha20.NewUnauthenticatedCipher(hkdfOut[0:32], hkdfOut[32:44])`
  - `stream.XORKeyStream(dst32, src32)`
  - Client uses `salt32 = ClientSalt`; Server uses `salt32 = ServerSalt`.
- **Single-User vs Multi-User & `EIH` Wire Contract (`U-6`)**:
  - **Single-User Mode** (`len(Inbound.Users) == 0`, `Inbound` has `Password`/`Key`; `Outbound` has single `<uPSK>`):
    - Wire fixed prefix is **`96 Bytes`**: `ClientSalt(32B) || MaskedClientEPK(32B) || EncryptedFixedHeader(32B)` (`EIH` = `0B`, `AAD` = `64B`).
  - **Multi-User Mode WITH Server `iPSK` (`O(1)` EIH Mode)**:
    - Configured when `len(Inbound.Users) > 0` AND `Inbound` also sets server `Password`/`Key` (`iPSK`), while `Outbound` sets `"<server_secret>:<user_secret>"` (split on `:` when both sides are valid secrets: 32B Base64 or `>=16` chars).
    - Each user has `userID = SHA256("AetherFlow-v2-UID" || uPSK[:])[0:16]`, stored in a `map[[16]byte]*UserEntry` on Inbound (`O(1)` lookup).
    - Client computes `eihMask = HKDF-SHA256(ikm=iPSK[:], salt=ClientSalt[:], info="AetherFlow-v2-EIH", len=16)`, sets `EIH = userID XOR eihMask` (`16B`).
    - Wire fixed prefix is **`112 Bytes`**: `ClientSalt(32B) || MaskedClientEPK(32B) || EIH(16B) || EncryptedFixedHeader(32B)` (`AAD` = `80B`).
    - Server computes `eihMask` from `iPSK + ClientSalt`, recovers `userID = EIH XOR eihMask`, looks up `UserEntry` in `O(1)`, and verifies `EncryptedFixedHeader`!
  - **Multi-User Mode WITHOUT Server `iPSK` (`Users`-Only Convenience Mode)**:
    - Configured when `len(Inbound.Users) > 0` and `Inbound` leaves `Password`/`Key` empty (`""`), while `Outbound` sets simply `"<user_secret>"` (no `:`).
    - Wire fixed prefix is **`96 Bytes`** (`EIH` = `0B`, `AAD` = `64B`). Server reads `96B` and authenticates `EncryptedFixedHeader` against its configured `Users` slice.
- **Handshake `initKey` (`U-3`)**:
  - Without static server key: `ikmInit = uPSK[:]` (`32B`).
  - With static server key (`private_key` / `public_key`): `ss_static = ECDH(ek_c, spk_s)` (`32B`), `ikmInit = uPSK[:] || ss_static[:]` (`64B`).
  - `initKey = HKDF-SHA256(ikm=ikmInit, salt=ClientSalt[:], info="AetherFlow-v2-Client-Init", len=32)`.
  - `initAEAD, _ := chacha20poly1305.New(initKey)`:
    - `EncryptedFixedHeader`: `nonce = encodeNonce(0)`, `AAD = ClientSalt || MaskedClientEPK [|| EIH]` (`64B` or `80B`).
    - `EncryptedVarHeader`: `nonce = encodeNonce(1)`, `AAD = FixedHeaderPlaintext[0:16]` (`16B`).
- **Session Ratchet `masterSecret` & Directional Subkeys (`U-5`)**:
  - `ss_eph = ECDH(ek_c, epk_s)` (`32B`).
  - Without static server key: `ikmSession = uPSK[:] || ss_eph[:]` (`64B`).
  - With static server key: `ikmSession = uPSK[:] || ss_eph[:] || ss_static[:]` (`96B`).
  - `dualSalt = ClientSalt[:] || ServerSalt[:]` (`64B`).
  - `masterSecret = HKDF-SHA256(ikm=ikmSession, salt=dualSalt, info="AetherFlow-v2-Session", len=32)`.
  - Subkeys via `HKDF-Expand-SHA256(prk=masterSecret, info=label, len=32)`:
    - `"AetherFlow-v2-Resp"` -> `respKey` (`ChaCha20-Poly1305`, `nonce = encodeNonce(0)`, `AAD = ClientSalt || ServerSalt || MaskedServerEPK` = `96B`).
    - `"AetherFlow-v2-C2S-Header"` -> `c2sHeaderKey` (negotiated `CipherSuite`).
    - `"AetherFlow-v2-C2S-Payload"` -> `c2sPayloadKey` (negotiated `CipherSuite`).
    - `"AetherFlow-v2-S2C-Header"` -> `s2cHeaderKey` (negotiated `CipherSuite`).
    - `"AetherFlow-v2-S2C-Payload"` -> `s2cPayloadKey` (negotiated `CipherSuite`).

### 4. Wire Format, Shaping, UDP & Anti-Replay Contracts (`wire.go`, `replay.go`, `conn.go` — `U-7`..`U-15`)
- **`FixedHeader` (`16B` Big-Endian)**:
  - `[0] Version = 0x02`
  - `[1] Command`: `0x01 = CommandTCP`, `0x02 = CommandUDP`, `0x03 = CommandMux`, `0x04 = CommandUoT`
  - `[2] CipherSuite`: `0x01 = CipherAES256GCM`, `0x02 = CipherChaCha20Poly1305`
  - `[3] Reserved = 0x00`
  - `[4:12] TimestampSec` (`int64` BE)
  - `[12:14] NoiseLen` (`uint16` BE, valid `32 <= NoiseLen <= 384`)
  - `[14:16] VarHeaderLen` (`uint16` BE, valid `NoiseLen + minAddrLen <= VarHeaderLen <= 16384`)
- **`VarHeader` (`VarHeaderLen` Bytes)**:
  - `[0 : NoiseLen]` CSPRNG bytes + `M.SocksaddrSerializer` `TargetAddr` + `InitialPayload` (0-RTT data).
- **`RespHeader` (`4B` Plaintext inside `84B` Server Response Prefix — `U-8`)**:
  - `[0] = 0x02` (`Version`), `[1] = 0x00` (`StatusOK`), `[2] = CipherSuite` echoed, `[3] = 0x00` (`Reserved`).
- **Data/Control Frames (`U-10`, `U-11`)**:
  - Length Header (`18B`): `AEAD_Seal(HeaderKey, nonce=seq, [PlainFrameLen uint16 BE], nil)`, valid `2 <= PlainFrameLen <= 16641` (`MaxDataSize = 16384`, `MaxPadLen = 255`).
  - Body (`PlainFrameLen + 16B`): `AEAD_Seal(PayloadKey, nonce=seq, [FrameType 1B | PadLen 1B | Padding(PadLen) | Data], nil)`.
  - `FrameType`: `0x01 = FrameData` (0-len data = chaff, skip in read loop), `0x02 = FramePing` (`PadLen` in `32..224`), `0x03 = FramePong` (`PadLen` in `32..224`), `0x04 = FrameCloseWrite`; any other value is a fatal protocol error.
  - Head-Only Shaping (`!DisableShaping`): for `sendFrameIdx < 6` on `FrameData`, split writes `> 1200B` into random chunks in `512..1100B` and attach random `PadLen` in `16..255B`; for `sendFrameIdx >= 6`, `PadLen = 0`, chunk up to `16384B`.
- **Native UDP Datagram Stream Framing (`CommandUDP = 0x02` — `U-12`)**:
  - `[Socksaddr via M.SocksaddrSerializer] || [PayloadLen uint16 BE (2B)] || [Payload (PayloadLen B)]`.
- **Sliding Bloom Filter (`U-13`)**:
  - Two bitsets (`current`, `previous`) of `65536` `uint64` (`512 KiB` each = `1 MiB` total), `k = 6` keyed hash probes over `[32]byte` `ClientSalt`, rotating every `2 * TimeWindow` (`60s` when `TimeWindow = 30s`). Checked/inserted strictly AFTER `EncryptedFixedHeader` AEAD verification succeeds.
- **Heartbeat & Dead Peer Detection (`U-14`)**:
  - Default `HeartbeatInterval = 30s` (`< 0` disables keepalive); idle Ping fires after `HeartbeatInterval * uniform(0.75, 1.25)`; `PongTimeout = max(10s, HeartbeatInterval/2)` (or scaled proportionally when `HeartbeatInterval < 10s` in fast unit/E2E tests, e.g. `max(2*HeartbeatInterval, 500ms)` when `HeartbeatInterval < 5s` so sub-second DPD tests run fast without 10s waits!). Specifically: `PongTimeout = max(HeartbeatInterval/2, 500*time.Millisecond)` when `HeartbeatInterval < 20s`, and `HeartbeatInterval/2` (`>=10s`) when `HeartbeatInterval >= 20s`!
- **`sing-box v1.14.4` Adapter & Buffer Contracts (`explorer_survey_2`)**:
  - `Inbound.Start(stage adapter.StartStage, scope *adapter.Scope) error` and `Outbound.Start(stage adapter.StartStage, scope *adapter.Scope) error` (`IdleConnectionKeeper`, `OutboundWithMultiplex`, `InterfaceUpdateListener`, `TCPInjectableInbound`).
  - `WriteBuffer` and `WritePacket` MUST `defer buffer.Release()` on every path; `ReadBuffer` MUST NOT release `buffer`.
  - `ReaderReplaceable()` / `WriterReplaceable()` MUST NOT return `true`.
  - `StealthDrain` MUST drain with random `3s..10s` read deadline, call `conn.Close()` directly (sending TCP `FIN`, NOT `N.CloseOnHandshakeFailure`'s `SetLinger(0)` `RST`), and then invoke `onClose(err)`.

---

## Code Layout

Exclusive file ownership per milestone/track to guarantee zero concurrent write conflicts:

```

├── .git/info/exclude                          # M1: add .agents/
├── constant/version.go                        # M1: "1.14.4-Custom-Aether"
├── option/aether.go                           # M1: v2 pure-binary options
├── cmd/sing-box/
│   ├── cmd_generate_aether.go                 # M1: aether-key & aether-keypair CLI
│   └── cmd_generate_aether_test.go            # M1: CLI keygen unit tests
├── .github/workflows/
│   ├── docker.yml                             # M1: disable release trigger
│   ├── linux.yml                              # M1: disable release trigger
│   ├── build-linux-amd64.yml                  # M1: fix tags, Go version, LDFLAGS, -race
│   └── upstream-sync-release.yml              # M5: weekly upstream official sync & release
└── protocol/aether/
    ├── crypto.go, crypto_test.go              # M2: Argon2id/Base64, masked X25519, HKDF, AEAD, EIH
    ├── replay.go, replay_test.go              # M2: 1MiB SlidingBloomFilter + NTP TimeFunc
    ├── wire.go, wire_test.go                  # M3: 96B/112B prefix, 84B resp, 18B AEAD frame, shaping
    ├── conn.go, conn_test.go                  # M3: ExtendedConn, EarlyConn, pongCh, atomic fuse, DPD
    ├── packet.go                              # M3: Native CommandUDP PacketConn
    ├── drain.go, drain_test.go                # M4: handshakeSem, drainSem, 3s..10s StealthDrain, rate log
    ├── inbound.go                             # M1 (v1.14.4 shim) -> M4 (full v2 Inbound)
    ├── outbound.go                            # M1 (v1.14.4 shim) -> M4 (full v2 Outbound)
    ├── fuzz_test.go                           # M4: FuzzHandshake, FuzzFrameStream
    ├── stress_race_test.go                    # M4: -race bidirectional saturation + deadlines + pings
    ├── pcap_test.go                           # M4: wire-tap PCAP generation & DPI/split assertions
    └── e2e/                                   # E2E-Track (Tiers 1–4) + M6 (Tier 5 hardening)
        ├── harness_test.go
        ├── tier1_feature_test.go
        ├── tier2_boundary_test.go
        ├── tier3_combination_test.go
        ├── tier4_workload_test.go
        └── tier5_adversarial_test.go
```
