# Handoff Report — E2E Timing, Anti-Probe, Replay, Deadlock & CI Execution Budget Blueprint (`explorer_e2e_3`)

> **Core Findings Summary**: Empirical `-race` measurements on this 2-vCPU Xeon 8481C VM prove that `argon2.IDKey(t=3, m=64MiB, p=4)` costs **`332.7ms` per call** (`665ms`/pair) whereas a minimal `box.Box` pair (`local.RegisterTransport` + Base64 32B key) starts and stops in **`4.2ms`**, enabling **300+ Tiers 1–4 subtests to execute in `~13–16s` wall-clock (`< 36s` total `go test -race ./protocol/aether/...`)** by sharing 12 canonical `BoxPair` profiles, overlapping the single `~10.2s` 16-connection parallel `StealthDrain` epoll batch with all CPU/throughput tests via `t.Parallel()`, driving fast expiry/DPD via public JSON `"time_window": "2s"` / `"handshake_timeout": "800ms"` / `"heartbeat_interval": "600ms"` + `ntp.TimeService` context injection, and validating `.github/workflows/{docker,linux,build-linux-amd64,upstream-sync-release}.yml` via `gopkg.in/yaml.v3` + `t.TempDir()` `.gitconfig` `url...insteadOf` dry-run shims with zero repo mutation.

---

## Synthesis Across Codebase, Specs & Empirical VM Measurements

### Consensus
1. **Strict Opaque-Box & Cycle-Free Minimal Registry** (`PROJECT.md:87`, `ci_and_test_survey.md:184-210`, `worker_m1_1/handoff.md:48,117`): `protocol/aether/e2e` (`package e2e_test`) must interact strictly via public `box.Box`, JSON `option.*`, public `adapter.*` / `sing/service` / `sing/common/ntp` interfaces, and raw TCP/UDP loopback sockets — never importing `github.com/sagernet/sing-box/include` (avoiding both 40-protocol `-race` compile bloat and the verified `include/quic_stub.go:48` concurrent data race).
2. **Fast Public JSON Timers & Proportional Sub-20s `PongTimeout`** (`PROJECT.md:128-144, 228-230`, `option/aether.go:20-36`): `TimeWindow`, `HandshakeTimeout`, and `HeartbeatInterval` are exposed via `badoption.Duration` JSON strings, and `PongTimeout = max(HeartbeatInterval/2, 500ms)` when `HeartbeatInterval < 20s`, allowing deterministic sub-3s heartbeat/DPD and ~4.3s 2-generation Bloom rotation tests without sleeping 30–60s.
3. **Single-Job Workflow & `.github/workflows/` Preservation Contract** (`PROJECT.md:37-38, 49, 73`, `explorer_m1_3/handoff.md:10-20`, `ci_and_test_survey.md:94-140`): Both `docker.yml` and `linux.yml` must keep `release: [published]` disabled; `build-linux-amd64.yml` and `upstream-sync-release.yml` must run `go test -race ./protocol/aether/...`, compile all 9 tags + `$(cat release/LDFLAGS)`, use literal `permissions: contents: write`, and preserve `.github/workflows/` on upstream merges.

### Resolved Conflicts
1. **Empty `dns.NewTransportRegistry()` in Minimal `box.Context` (`ci_and_test_survey.md:204` vs `box.go:402-410`)**:
   - *Conflict*: `ci_and_test_survey.md:204` passed an empty `dns.NewTransportRegistry()` to `box.Context(...)`, whereas `box.go:402-410` registers a default `"local"` `DNSTransport` initialized during `Box.Start()`.
   - *Resolution*: Verified empirically under `go test -race`: `b.Start()` fails with `initialize dns-transport: default DNS server fallback: transport type not found: local` unless `local.RegisterTransport(dnsReg)` (`github.com/sagernet/sing-box/dns/transport/local`) is registered. Mandatory fix incorporated into the minimal E2E registry blueprint.
2. **`go.uber.org/goleak` (`test/box_test.go:25,29`) vs Root `go.mod` (`go.mod:5-200`)**:
   - *Conflict*: `test/box_test.go` (in the separate `test/go.mod` module) uses `goleak.VerifyTestMain(m)`, whereas root `go.mod` does **not** contain `go.uber.org/goleak` and `PROJECT.md:19` forbids adding external `go.mod` dependencies.
   - *Resolution*: Use a zero-dependency stdlib `runtime.Stack(buf, true)` + `/proc/self/fd` post-suite leak auditor in `TestMain` after closing shared `BoxPair` profiles.
3. **Server-Side Syscall-Exact Wire Tapping vs Raw Kernel Socket `RST` Detection (`ci_and_test_survey.md:217-223` vs `sing/common/network/handshake.go:47-51`)**:
   - *Conflict*: Wrapping server `net.Conn` in a custom struct without `SetLinger(int) error` prevents OS loopback coalescing of consecutive `ServerConn.Write()` syscalls, **but** would mask a `N.CloseOnHandshakeFailure` `SetLinger(0)` `TCP RST` bug because `common.Cast[interface{ SetLinger(int) error }]` in `handshake.go:47-51` would return `false`!
   - *Resolution*: Split wire inspection cleanly by purpose:
     - Use **raw unwrapped `net.Dial("tcp", realInboundAddr)`** against `AetherInbound`'s real `*net.TCPListener` for all `StealthDrain` / Anti-Probe / Replay / `RST`-vs-`FIN` assertions (preserving `*net.TCPConn.SetLinger(0)` detection!).
     - Use **`"detour": "wiretap"`** (client syscall tap) + **`"detour": "wiretap-dual"`** (`adapter.TCPInjectableInbound` dual-ended 8-method `net.Conn` tap over a real loopback TCP socket pair) for exact `Write(p)` syscall-count/length assertions (`0` `2B` segments, 0-RTT coalescing, 84B response coalescing, `Frame 0..5` shaping).

### Dissenting Views
- None.

### Gaps Closed
- Measured exact `-race` Argon2id (`332.7ms`), `box.New+Start+Close` (`4.2ms`), Linux 6.12 minimum `SO_SNDBUF=4608` / `SO_RCVBUF=2304` (`32,768B` TCP window saturation), and soft `RLIMIT_NOFILE=1024` vs hard `1,048,576` on this VM.
- Proved `gopkg.in/yaml.v3` (`v3.0.1`, YAML 1.2) and `github.com/google/gopacket/pcapgo` (`v1.1.19`) import cleanly in root-module subpackages without modifying `go.mod`.
- Designed an implementation-agnostic `t.TempDir()` + `.gitconfig` `url...insteadOf` sandbox runner for `upstream-sync-release.yml` (`F26`).

---

## 1. Observation

### 1.1 Empirical VM Hardware, Kernel & `-race` Benchmark Observations
1. **CPU, Memory & TCP Sysctls** (measured via read-only Python/procfs inspection on `/proc/sys/net/ipv4/tcp_{rmem,wmem}`, `/proc/meminfo`, `os.cpu_count()`):
   - `nproc`: `2` (Intel Xeon Platinum 8481C, hardware `aes`, `pclmulqdq`, `vaes`, `sha_ni` active).
   - `MemTotal`: `8,138,460 kB` (`MemAvailable`: `7,289,612 kB`).
   - `tcp_rmem`: `4096  131072  6291456`; `tcp_wmem`: `4096  16384  4194304`.
2. **File Descriptor Soft vs Hard Limit** (`bash -c 'ulimit -Sn; ulimit -Hn'`):
   - Soft `RLIMIT_NOFILE` (`ulimit -Sn`): **`1024`**.
   - Hard `RLIMIT_NOFILE` (`ulimit -Hn`): **`1048576`**.
   - *(Note: Go 1.19+ raises `RLIMIT_NOFILE.Cur` toward `Max` in `os` init, and `TestMain` can explicitly verify/assert `rlim.Cur >= 65536` before running 560-socket `drainSem` tests).*
3. **Empirical `-race` Cost Measurements** (executed in isolated `/tmp/e2e_bench_probe`, immediately deleted; repo untouched):
   - `argon2.IDKey([]byte("passphrase-at-least-16-chars"), []byte("AetherFlow-v2-KDF"), 3, 64*1024, 4, 32)` under `go test -race`: **`332.724ms`** per single call (`~665.4ms` per client+server pair, `128 MiB` allocation/pair).
   - Minimal Registry initialization (`inbound.NewRegistry` + `mixed` + `aether`, `outbound.NewRegistry` + `direct` + `aether`, `dns.NewTransportRegistry` + `local.RegisterTransport`): **`71.898µs`**.
   - `10x` full `box.New` + `b.Start()` + `b.Close()` cycle under `go test -race` (using 32B Base64 key): **`41.984ms` total (`4.198ms` average per `box.Box` lifecycle)**.
   - Omitting `local.RegisterTransport(dnsReg)` caused `b.Start()` to fail verbatim with:
     `initialize dns-transport: default DNS server fallback: transport type not found: local` (`box.go:402-410`).
4. **Empirical Linux 6.12 Loopback Small-Window Saturation**:
   - Calling `tcpConn.SetWriteBuffer(1024)` and `tcpConn.SetReadBuffer(1024)` clamped kernel socket buffers to **`SO_SNDBUF = 4608`** and **`SO_RCVBUF = 2304`**, causing `tcpConn.Write` on `127.0.0.1` to block (`os.ErrDeadlineExceeded`) deterministically after **`32,768 bytes` (`32 KiB` = 2 max-size Aether frames)**.
5. **Indirect Dependency Import Check in Root Module (`go.mod:66, 119, 197`)**:
   - Tested in `/tmp/modcheck/sub/sub_test.go` against verbatim copies of `{go.mod,go.sum}`: `GOPROXY=direct GOSUMDB=off go test -v ./sub/...` importing `gopkg.in/yaml.v3` and `github.com/google/gopacket/pcapgo` exited `0` in `0.008s` with zero `go.mod` changes. `yaml.v3` parsed unquoted `on:` as string key `"on"` (`map[on:map[workflow_dispatch:<nil>]]`).

### 1.2 Relevant `sing-box` & `sing` Public API Hook Observations
1. **Option Structs** (`option/aether.go:14-39`, `option/inbound.go:79-95`, `option/outbound.go:80-95`):
   - `AetherInboundOptions` embeds `ListenOptions` (`Listen`, `ListenPort`, `ReuseAddr`) and exposes `Password`, `Key`, `Users`, `ServerPrivateKey`, `TimeWindow`, `HandshakeTimeout`, `HeartbeatInterval`, `DisableShaping`, `Multiplex`.
   - `AetherOutboundOptions` embeds `DialerOptions` (`Detour string`, `ConnectTimeout`) + `ServerOptions` and exposes `Network`, `Password`, `Key`, `Cipher`, `ServerPublicKey`, `HeartbeatInterval`, `DisableShaping`, `Multiplex`, `UDPOverTCP`.
2. **Inbound Port & Injection Access** (`adapter/inbound.go:19-28`, `box.go:668-674`):
   - `adapter.Inbound` exposes only `Start`, `Type`, `Tag` (no public `ListenAddr()` getter), requiring pre-allocated unique `127.0.0.1` ports with `"reuse_addr": true`.
   - `box.Box.Inbound().Get(tag)` returns `adapter.Inbound` castable to `adapter.TCPInjectableInbound` (`NewConnection(ctx, conn, metadata, onClose)`).
   - `box.Box.Outbound().Outbound(tag)` returns `adapter.Outbound` (`DialContext`, `ListenPacket`, `adapter.OutboundWithMultiplex`, `adapter.InterfaceUpdateListener`, `adapter.IdleConnectionKeeper`).
3. **Detour Dialer Wiring** (`common/dialer/dialer.go:47-52`, `common/dialer/detour.go:57-94`):
   - Setting `"detour": "wiretap"` in `AetherOutboundOptions` JSON routes all `AetherOutbound` TCP dials through `outboundManager.Outbound("wiretap")` as long as the custom outbound does not implement `dialer.DirectDialer` with `IsEmpty() == true`.
4. **Controllable Clock Injection via `ntp.TimeService`** (`/home/antigravity/go/pkg/mod/github.com/sagernet/sing@v0.9.7-0.20261023115459-5dc452e537bf/service/context.go:13-18`, `common/ntp/context.go:10-16`, `common/ntp/service.go:19-21`, `box.go:116, 258-263`):
   - `service.ContextWithDefaultRegistry(ctx)` preserves an existing `service.Registry` on `ctx`. When `options.NTP` is disabled/omitted in JSON, `box.New` preserves any `ntp.TimeService` (`interface { TimeFunc() func() time.Time }`) pre-registered on `ctx` via `service.ContextWith[ntp.TimeService](ctx, mockClock)`, which `ntp.TimeFuncFromContext(ctx)` returns directly to both `Inbound` and `Outbound`.
   - Additionally, enabling `"ntp": {"enabled": true, "server": "127.0.0.1", "server_port": port}` in `option.Options` JSON runs `ntp.Exchange` (`common/ntp/ntp.go:13-51`) over UDP against a local RFC 5905 server.
5. **Log Capture Without Side Effects** (`log/log.go:32-60`, `log/factory.go:20`, `box.go:154, 688`):
   - Setting `"log": {"level": "warn", "output": "<tempFile>"}` or calling `instance.LogFactory().AttachPlatformWriter(memWriter)` *after* `box.New` (and *before* `instance.Start()`) captures rate-limited `S-7` warning logs cleanly without triggering `box.go:154`'s `needCacheFile = true` (`cache.db` creation).
6. **Current M1 Workflow Files** (`.github/workflows/{docker,linux,build-linux-amd64}.yml`):
   - `docker.yml:8-10` and `linux.yml:14-16` already have `#release:` commented out (`F2` done in M1).
   - `build-linux-amd64.yml:1-80` uses `go-version-file: 'go.mod'`, `CGO_ENABLED=1 go test -race ./cmd/sing-box/... ./protocol/aether/...`, all 9 build tags + `$(cat release/LDFLAGS)`, `if: startsWith(github.ref, 'refs/tags/v')` on `softprops/action-gh-release@v2`, and `continue-on-error: true` on `actions/upload-artifact@v4`.
   - `.github/workflows/upstream-sync-release.yml` (`F26`) does not exist yet (scheduled for M5).

---

## 2. Logic Chain & Actionable Blueprint

### 2.1 Pillar 1 — Execution Time Budget Blueprint (`< 45–60s` Total `go test -race ./protocol/aether/...` on 2 vCPUs)

1. **Why Naive E2E Suites Blow the 60s Budget (From Obs 1.1.3)**:
   - Spinning up 300 unshared `box.Box` pairs with passphrases under `-race` would spend `300 * 665ms = 199.6s` in `Argon2id` alone; running 16 `StealthDrain` (`3s..10s`) tests sequentially would add `16 * 6.5s = 104s`; importing `include` would add `~15s` to `-race` compilation/linking and trigger `include/quic_stub.go:48` races.
2. **Rule 1 — Mandatory Minimal Registry Helper (`72µs` init, `4.2ms` `Box` start)**:
   ```go
   func newBaseContext(parent context.Context, extraOutbounds ...func(*outbound.Registry)) context.Context {
       inReg := inbound.NewRegistry()
       mixed.RegisterInbound(inReg)
       aether.RegisterInbound(inReg)

       outReg := outbound.NewRegistry()
       direct.RegisterOutbound(outReg)
       aether.RegisterOutbound(outReg)
       for _, regFn := range extraOutbounds {
           regFn(outReg)
       }

       dnsReg := dns.NewTransportRegistry()
       local.RegisterTransport(dnsReg) // MANDATORY for Box.Start() (box.go:402-410)

       return box.Context(
           parent,
           inReg,
           outReg,
           endpoint.NewRegistry(),
           dnsReg,
           service.NewRegistry(),
           certificate.NewRegistry(),
       )
   }
   ```
3. **Rule 2 — Base64 Key Default + Single Shared `Argon2id` Profile**:
   - Generate 32-byte CSPRNG `base64.StdEncoding` keys (`< 1µs` `DerivePSK` fast-path) for **all** profiles except **one** shared `P07_PassphraseArgon2id` profile (`"correct-horse-battery-staple"`, `~665ms` once). Weak/empty/15-char/all-zero key rejection tests fail synchronously before `argon2.IDKey` executes (`< 1ms` each).
4. **Rule 3 — 12 Lazily-Initialized Shared `BoxPair` Profiles + Shared Backend Servers**:
   Start shared backend servers once (`tcpEchoServer` supporting half-close & deterministic SHA-256 streams, `serverSpeaksFirstBannerServer`, `immediateFINServer`, 2-port `udpEchoServer` for Full-Cone NAT verification, and `stalledTargetServer` for `R-1`/`R-2` window saturation), and share **12 canonical `BoxPair` profiles** across stateless functional/boundary/combination subtests (`sync.OnceValues`, torn down in `TestMain`):

   | Profile ID | Inbound / Outbound Configuration | Subtests Served | Startup Cost |
   |---|---|---|---|
   | `P01_DefaultAuto` | Base64 key, `cipher:"auto"` (AES-GCM on Xeon), shaping ON, `detour:"wiretap"` | Tier 1 TCP/UDP, 0-RTT, shaping, EPK stats | `~9ms` |
   | `P02_ChaCha20` | Base64 key, `cipher:"chacha20-poly1305"`, shaping ON, `detour:"wiretap"` | ChaCha20 negotiation, cross-cipher matrix | `~9ms` |
   | `P03_NoShaping` | Base64 key, `cipher:"aes-256-gcm"`, `disable_shaping:true`, `detour:"wiretap"` | `PadLen==0` proof, `<=0.22%` overhead, 16KB boundaries | `~9ms` |
   | `P04_Static0RTT` | Base64 key + X25519 `private_key`/`public_key`, shaping ON, `detour:"wiretap"` | Static 0-RTT PFS, key mismatch isolation | `~9ms` |
   | `P05_MultiUserEIH` | Server `key:<iPSK>` + 3 `users`, 3 outbounds `"<iPSK>:<u_i>"`, `detour:"wiretap"` | 112B EIH O(1) auth, multi-user isolation | `~11ms` |
   | `P06_UsersOnly` | Server `key:""` + 3 `users`, outbounds `"<u_i>"` (`96B` prefix), `detour:"wiretap"` | 96B multi-user convenience mode | `~10ms` |
   | `P07_Argon2id` | 20-char passphrase `"correct-horse-battery-staple"` (`t=3, m=64MiB`) | Passphrase KDF end-to-end + UTF-8 check | `~665ms` |
   | `P08_UoT` | `udp_over_tcp: {"enabled":true, "version":2}` (`CommandUoT = 0x04`) | UoT v2 connected & PacketConn UDP | `~9ms` |
   | `P09_MuxSmux` | `multiplex: {"enabled":true, "protocol":"smux", "max_connections":2}` | `smux` concurrent TCP + UDP streams | `~10ms` |
   | `P10_MuxYamuxPad` | `multiplex: {"enabled":true, "protocol":"yamux", "padding":true}` | `yamux` + mux padding + UDP | `~10ms` |
   | `P11_MuxH2Mux` | `multiplex: {"enabled":true, "protocol":"h2mux", "max_connections":2}` | `h2mux` HTTP/2 streams + UDP | `~10ms` |
   | `P12_DualWireTap` | Base64 key, shaping ON, `detour:"wiretap-dual"` (`TCPInjectableInbound`) | Exact S->C `Write()` syscall count & shaping | `~9ms` |

   *(Dedicated ephemeral `box.Box` instances are created ONLY for tests that mutate lifecycle/timers/clocks: `Close`/`InterfaceUpdated`, `ntp.TimeService` skew, `"time_window": "2s"`, `"handshake_timeout": "800ms"` / `"15s"`, `"heartbeat_interval": "600ms"`, and `handshakeSem`/`drainSem` floods — ~15 lightweight Base64 instances = `< 150ms` total).*

5. **Rule 4 — Overlapped Two-Track `t.Parallel()` Schedule & Wall-Clock Budget**:
   - On 2 vCPUs (`GOMAXPROCS=2`), epoll-sleeping timer tests consume **0% CPU** while waiting. Launching all timer-bound tests with `t.Parallel()` overlaps them completely with each other AND with CPU-bound tests:

   | Track / Component | Execution Strategy | CPU Time | Wall-Clock Time |
   |---|---|---|---|
   | `go test -race` Compile & Link (`aether` + `e2e`) | Minimal registry (zero `include` import) | ~7.0s | **~4.5s** |
   | Shared Profiles (`P01..P12`) + Echo Servers Init | `P07` Argon2id (`0.67s`) + 11 Base64 pairs (`0.11s`) | ~0.9s | **~0.8s** |
   | **I/O-Sleep Batch 1**: 16-Vector `StealthDrain` + `S-1` Oracle | 16 raw TCP probes in 1 `sync.WaitGroup` (`t.Parallel()`) | < 0.03s | **~10.2s** *(overlapped)* |
   | **I/O-Sleep Batch 2**: `"time_window": "2s"` Bloom Rotation | `t=0s`, `t=2.2s`, `t=3.5s`, `t=4.3s` checks (`t.Parallel()`) | < 0.02s | **~4.5s** *(inside 10.2s)* |
   | **I/O-Sleep Batch 3**: `"heartbeat_interval": "600ms"` Ping + DPD | `1.6s` idle Ping/Pong + `~1.8s` blackhole DPD (`t.Parallel()`) | < 0.03s | **~2.5s** *(inside 10.2s)* |
   | **I/O-Sleep Batch 4**: `"handshake_timeout": "800ms"` Slowloris | 10 incomplete-prefix connections (`t.Parallel()`) | < 0.02s | **~1.2s** *(inside 10.2s)* |
   | **CPU Track**: Tiers 1–4 (~280 subtests + 200 EPK + 560 `drainSem` + `R-1`/`R-2` + CI dry-run) | Parallel across 2 Xeon cores during the 10.2s I/O window (`560` `drainSem` sockets closed by client after 10 valid dials -> `< 0.5s`!) | ~13.0s | **~7.5s** *(inside 10.2s)* |
   | Post-Suite Goroutine & FD Leak Audit (`TestMain`) | Runs sequentially after `m.Run()` + `CloseAll()` | ~0.05s | **~0.1s** |
   | **Total `protocol/aether/e2e` Package** | | | **~12–16s** |
   | **Total `protocol/aether` Unit/KAT/Fuzz-Seed/Stress Package** | | | **~10–15s** |
   | **Grand Total `go test -race ./protocol/aether/...`** | **Target `< 45–60s` achieved with ~2x headroom** | | **~27–36s** |

---

### 2.2 Pillar 2 — Exact Mathematical Criteria for Opaque-Box Wire-Tap, Timing & Concurrency Assertions

#### A. Three-Mode Opaque-Box Wire-Tap Architecture (`harness_test.go`)
1. **Strict 8-Method `recordedConn` Wrapper**:
   - Wrap `*net.TCPConn` in a struct implementing **ONLY** the 8 `net.Conn` methods (`Read`, `Write`, `Close`, `LocalAddr`, `RemoteAddr`, `SetDeadline`, `SetReadDeadline`, `SetWriteDeadline`) — deliberately omitting `Upstream() any`, `io.WriterTo`, `syscall.Conn`, and `SetLinger(int) error` so neither `sing/common/bufio` nor Go stdlib can unwrap it or bypass `Write(p []byte)`.
   - Every `Write(p)` records `WriteRecord{Timestamp: time.Now(), Size: len(p), Prefix: copyUpTo(p, 512)}` under a mutex and increments `totalBytes`.
2. **Mode Dispatch**:
   - **`"detour": "wiretap"` (Client Syscall Tap -> Real Inbound TCP Socket)**: Captures exact `C->S` `Write(p)` syscalls and full `S->C` ciphertext stream over `AetherInbound`'s real `listener.Listener`.
   - **`"detour": "wiretap-dual"` (Client + Server Syscall Tap via `adapter.TCPInjectableInbound`)**: Creates a real loopback `*net.TCPConn` pair (`clientTCP <-> serverTCP`), wraps **both** ends in `recordedConn`, and hands `serverRecordedConn` to `serverBox.Inbound().Get("aether-in").(adapter.TCPInjectableInbound).NewConnection(...)` — capturing **100% exact `Write(p)` syscall boundaries on BOTH `C->S` and `S->C`** with zero kernel loopback coalescing!
   - **Raw Unwrapped `net.Dial("tcp", serverListenAddr)`**: Used for all `StealthDrain`, `S-1` length-oracle, replay, and `SetLinger(0)` `RST`-vs-`FIN` assertions.

#### B. Exact Mathematical Wire & Timing Criteria Table

| # | Requirement | Test Setup (100% Opaque-Box) | Exact Mathematical / Statistical Assertion | False-Positive Rate |
|---|---|---|---|---|
| **W1** | **Zero `2-Byte` (or `18-Byte`) Split TCP Segments** (`F14`, `S-2`) | Transfer 50 bidirectional writes (`1B`..`65536B`) + idle Ping/Pong + `CloseWrite` over `P12_DualWireTap` | For **every** recorded `Write(p)` on `C->S` (`i >= 0`) and `S->C` (`j >= 0`):<br>1. `len(p) != 2 && len(p) != 18`<br>2. `len(p) >= 36` (`18B` hdr + `>=2B` body + `16B` tag)<br>3. `len(c2s[0]) >= 151` (`96B` + `32B` noise + `7B` IPv4 + `16B` tag; `>= 167` in 112B EIH mode)<br>4. `len(s2c[0]) >= 120` (`84B` resp prefix + `>=36B` first frame) | `0` (Deterministic algebraic invariant) |
| **W2** | **0-RTT Client Initial Burst + 84B Server Response Coalescing** (`F12`, `F13`, `F23`) | Dial IPv4 target (`AddrLen=7B`) via `P12_DualWireTap`:<br>Step 1: `conn, _ := out.DialContext(...)` (before `Write`)<br>Step 2: `conn.Write(req600)` (`600B` payload) -> echo `600B` | 1. Immediately after `DialContext`: **`len(c2sWrites) == 0`** (proves lazy 0-RTT `EarlyConn`, zero bare handshake!)<br>2. After `conn.Write(req600)`: **`len(c2sWrites) == 1`** and:<br>`len(c2sWrites[0]) = 96 + NoiseLen + 7 + 600 + 16 = 719 + NoiseLen ∈ [751, 1103]` Bytes *(disjoint from max uncoalesced handshake `503B`!)*<br>3. After echo: **`len(s2cWrites) == 1`** and:<br>`len(s2cWrites[0]) = 84 + 36 + PadLen + 600 = 720 + PadLen ∈ [736, 975]` Bytes<br>4. Against `immediateFINServer` (`0B` downlink): `len(s2cWrites) == 1 && len(s2cWrites[0]) >= 120` | `0` (Deterministic disjoint intervals) |
| **W3** | **First-6-Frames Shaping (`517B` & `3500B`) vs `disable_shaping: true`** (`F15`, `S-2`, `U-11`) | Complete handshake with `16B` ping-pong, then:<br>(a) 10 paced `517B` (`ClientHello`) writes (across 2 connections, `Frame 1..5`) on `P12_DualWireTap` vs `P03_NoShaping`<br>(b) Single `3500B` (`Certificate` `>1200B`) write at `Frame 1` on `P12_DualWireTap` vs `P03_NoShaping` | **Shaping ON (`disable_shaping: false`)**:<br>- `517B` writes: `100%` satisfy `len(w) ∈ [569, 808]` (`517 + 36 + [16..255]`, strictly `> 553B`!) AND `len(unique(lens)) >= 5` across 10 samples<br>- `3500B` write: splits into **`K ∈ [4, 7]` `Write()` calls**, every call satisfying `53 <= len(w) <= 1491` (`maxChunk 1200 + 36 + 255`), and `sum(len(w)) >= 3500 + 4*52 = 3708`<br>**Shaping OFF (`disable_shaping: true`)**:<br>- `517B` write -> **1 `Write()` of exact `553B`** (`517 + 36`)<br>- `3500B` write -> **1 `Write()` of exact `3536B`** (`3500 + 36`) | `< 10^-11` on `unique >= 5`; `0` on all bounds |
| **W4** | **Frame 6+ Steady-State Overhead `<= 0.22%`** (`F15`, `S-2`) | On `P01_DefaultAuto` (`disable_shaping: false`!), send 6 paced `64B` writes to advance `sendFrameIdx` to `6`, snapshot `c2sBytes0`, then write `4 MiB` (`64 x 65,536B` = `4,194,304B`) | `deltaWire := c2sBytes1 - c2sBytes0`<br>`overhead := float64(deltaWire - 4194304) / 4194304.0`<br>Assert **`deltaWire == 4203520`** (`256 * 16420B`, i.e., `PadLen == 0` on 100% of frames `6..261`) and **`overhead <= 0.0022`** (exact theoretical value = `36 / 16384 = 0.219727%`). Also verify `0` frames on `S->C` after Frame 5 exceed `16420B`. | `0` (Exact byte count on `C->S`) |
| **W5** | **`MaskedClientEPK[32:64]` & `MaskedServerEPK[32:64]` Uniformity (`~50%` MSB=1)** (`F6`, `S-6`) | Run `N = 200` fresh handshakes over `P01_DefaultAuto` (`8` concurrent workers, `~90ms` total); extract `c2s[0][32:64]` and `s2cStream[32:64]` | Let $X_c = \sum_{i=1}^{200} \mathbb{1}[(\text{cEPK}_i[31] \ \& \ 0\text{x80}) \ne 0]$ and $X_s = \sum_{i=1}^{200} \mathbb{1}[(\text{sEPK}_i[31] \ \& \ 0\text{x80}) \ne 0]$:<br>1. **`60 <= X_c <= 140`** and **`60 <= X_s <= 140`** (`30%..70%`, `±5.66σ` around `100`; unmasked X25519 ALWAYS yields **`0`**!)<br>2. Total 1-bits across all `6,400` bytes (`51,200` bits) each in **`[24900, 26300]`** (`±6.18σ`)<br>3. All 200 `ClientSalt[0:32]` and `ServerSalt[0:32]` values are 100% unique (`len(set) == 200`) and Shannon entropy over `6,400B` **`>= 7.90` bits/byte**. | `< 1.2 x 10^-8` per direction (`< 1` in 40M runs) |
| **W6** | **StealthDrain `[3s, 10.5s]` Normal `FIN` + Zero `S-1` Length Oracle** (`F11`, `F19`, `S-1`, `S-7`) | Dedicated Inbound with `"handshake_timeout": "15s"`. Launch **1 parallel batch of `K = 16` raw `net.Dial("tcp", ...)` probes** (keeping client write-half open!):<br>- `8x` **exact `96B`** forged/bit-flipped prefixes (with garbage encrypted `VarHeaderLen` bytes, sending 0 bytes after byte 96!)<br>- `2x` `512B` random garbage<br>- `2x` HTTP GET (`99B`) + `2x` TLS ClientHello (`256B`)<br>- `2x` verbatim replayed `ClientInitialBurst` | For **all 16** probes concurrently:<br>1. `nRead == 0` (zero response oracle)<br>2. **`errors.Is(err, io.EOF) == true`** (`!errors.Is(err, syscall.ECONNRESET)` -> proves normal TCP `FIN`, NEVER `SetLinger(0)` `RST`!)<br>3. **`2.95s <= elapsed_i <= 10.50s`**:<br>   - `>= 2.95s` proves zero `<500ms` / `200ms` fast-close oracle.<br>   - `<= 10.50s` (strictly `< 15.0s` `HandshakeTimeout`!) on the `96B`-only probes mathematically proves the server **rejected AEAD at byte 96 WITHOUT trying to read `VarHeaderLen` (`S-1`)**!<br>4. Across the 16 probes: **`max(elapsed) - min(elapsed) >= 1.5s`** (proves per-connection random jitter, not a fixed timer!). | `< 2.6 x 10^-9` on `range >= 1.5s`; `0` on `FIN` & `S-1` disjoint bound |

#### C. Deterministic Replay, Clock-Skew, DPD & Concurrency/Deadlock Recipes (`< 5s` Budget)
1. **Zero-Sleep `±TimeWindow` Boundary Proof (`< 25ms`, `F18`)**:
   - Server `box.Box` uses `"time_window": "30s"` and `service.ContextWith[ntp.TimeService](ctx, fixedClock(T0))`.
   - Client `box.Box` uses atomic `adjustableClock`:
     - `T0 + 29s` and `T0 - 29s` -> Handshake & echo **PASS**.
     - `T0 + 31s` and `T0 - 31s` -> Handshake **REJECTED** (`0` hits on backend `tcpEchoServer`).
   - Also run 1 test with JSON `"ntp": {"enabled": true, "server": "127.0.0.1", "server_port": mockNTPPort}` where local UDP NTP responder serves `+120s` offset to both Client & Server `box.Box`, proving end-to-end JSON NTP sync!
2. **Bloom Filter Post-AEAD Non-Pollution Proof (`< 50ms`, `PROJECT.md:27, 228`)**:
   - Configure `"wiretap"` in `interceptOnly` mode on 1 dial to capture a genuine `ClientInitialBurst` (`validBurst`) without transmitting it to the server.
   - Send `tampered := slices.Clone(validBurst); tampered[80] ^= 0x01` (flipped bit in `EncryptedFixedHeader`, **identical `ClientSalt[0:32]`**) to the server -> fails AEAD tag check.
   - Immediately send untouched `validBurst` to the server -> **server responds with valid 84B `ServerResponsePrefix`**, proving unauthenticated probes NEVER insert `ClientSalt` into `SlidingBloomFilter`!
3. **Wall-Clock Expiry + `2 * TimeWindow` Bloom Rotation Survival (`~4.3s` overlapped via `t.Parallel()`, `U-13`)**:
   - Server `"time_window": "2s"` (rotation period `2 * 2s = 4s`), Client clock offset `+1900ms` (`TimestampSec ≈ t0 + 1.9s`):
     - `t = 0.0s`: Capture `burst` from valid connection #1.
     - `t = 2.2s` & `t = 3.5s` (past `1 * TimeWindow`, still within `TimestampSec ± 2.0s`): Replaying `burst` returns `0` bytes and `0` backend target hits (proving 2-generation Bloom filter retains `ClientSalt` across generation boundaries without full-map wipes!).
     - `t = 4.3s`: Replaying `burst` is rejected, while fresh connection #2 succeeds cleanly.
4. **Idle Jittered Ping/Pong (`68..260B`) & Blackhole `lastRead` DPD (`~2.5s` overlapped via `t.Parallel()`, `F22`, `R-3`)**:
   - Outbound `"heartbeat_interval": "600ms"`, Inbound `"heartbeat_interval": "60s"`.
   - **Idle Ping/Pong**: Open 4 streams, echo `32B`, hold idle for `1.6s`. Every idle write on `C->S` (`FramePing`) and `S->C` (`FramePong`) has wire length **`68 <= len(w) <= 260` Bytes** (`36 + PadLen[32..224]`, never `17B`), with `>= 3` distinct lengths across the 4 streams.
   - **Blackhole DPD**: Enable `tapConn.SetBlackhole(true)` (silently drop `C->S` and `S->C` reads/writes without TCP `FIN`/`RST`). Assert `aetherConn.Read` returns a non-nil error within **`[400ms, 3.5s]`** (`600ms * 1.25 + PongTimeout[500ms..1200ms] + race slack`), and if `multiplex` is enabled, subsequent stream dial auto-recovers onto a new TCP socket!
5. **`R-1` Small-Window Bidirectional Saturation + Rapid Ping Deadlock Proof (`< 1.0s`, `F20`)**:
   - Via `"wiretap"`, set `tcpConn.SetWriteBuffer(1024)` (`SO_SNDBUF=4608`) and `tcpConn.SetReadBuffer(1024)` (`SO_RCVBUF=2304`) on both sockets (verified to saturate TCP send window at `32 KiB`!).
   - Configure `"heartbeat_interval": "200ms"` on both Inbound and Outbound, and simultaneously pump `2 MiB` `C->S` and `2 MiB` `S->C` across 4 raw streams + 4 `sing-mux` streams under `context.WithTimeout(ctx, 8*time.Second)` -> `100%` SHA-256 match with zero deadlock.
6. **`R-2` `SetWriteDeadline` Atomic Write Error Fusing Proof (`< 200ms`, `F21`)**:
   - Shrink `SO_SNDBUF=4608` / `SO_RCVBUF=2304`, connect to `stalledTargetServer` (which pauses reading), call `aetherConn.SetWriteDeadline(time.Now().Add(30*time.Millisecond))`, and write deterministic pattern chunks until `os.ErrDeadlineExceeded` triggers.
   - Clear deadline (`SetWriteDeadline(time.Time{})`), resume `stalledTargetServer` reading, and call `aetherConn.Write([]byte("probe"))`:
     1. Second `Write` MUST return a **non-nil error** (connection atomically fused on first write failure).
     2. Bytes received by `stalledTargetServer` until `EOF` MUST equal `expectedStream[:len(received)]` byte-for-byte (**zero AEAD nonce desync or corrupted plaintext**).
7. **`drainSem` (`512`) & `handshakeSem` (`256`) Flood Non-Starvation + Rate-Limited Logs (`< 1.5s`, `F19`, `S-7`)**:
   - Open `560` raw TCP connections sending `128B` invalid garbage -> `~512` enter `StealthDrain`, excess `~48` close in `< 500ms`. While those `512` sockets are actively draining, dial **10 legitimate Aether connections** -> all 10 echo cleanly in `< 500ms`! Then close all `560` probe client sockets (`StealthDrain`'s `io.Copy` sees `EOF` and releases all `512` `drainSem` slots in `< 20ms`!).
   - Inspect captured `warn` logs: assert `>= 1` warning log mentioning probe/handshake failure AND `totalWarnLines < 100` (proving IP log rate-limiting suppresses log-flood amplification over 560 failures!).

---

### 2.3 Pillar 3 — Opaque-Box CI Workflow Validation (`F2`, `F26`) Without Mutating Git State

1. **Tier 1 Structural YAML Validation (`tier1_feature_test.go`, `< 15ms`, Read-Only)**:
   - Parse `.github/workflows/{docker,linux,build-linux-amd64,upstream-sync-release}.yml` from `filepath.Join("..", "..", "..", ".github", "workflows")` via `gopkg.in/yaml.v3`:
     - **`docker.yml` & `linux.yml` (`F2`)**: Assert `on` map has key `"workflow_dispatch"` and **lacks** `"release"`, `"push"`, and `"pull_request"`.
     - **`build-linux-amd64.yml` (`F2`)**: Assert `permissions` contains literal `contents: write` (zero `${{` expressions in `permissions:`); `setup-go` uses `go-version-file: go.mod` (or `>= 1.25`); a `run:` step executes `go test` with `-race` and `./protocol/aether/...` *before* `go build`; `go build` contains all 9 required tags (`with_gvisor`, `with_quic`, `with_dhcp`, `with_wireguard`, `with_utls`, `with_acme`, `with_clash_api`, `badlinkname`, `tfogo_checklinkname0`) + `release/LDFLAGS` + dynamic `${VERSION}` (no `1.14.2-Custom-Aether`); `softprops/action-gh-release` is gated by `if:` containing `refs/tags/v`; `upload-artifact` sets `continue-on-error: true`.
     - **`upstream-sync-release.yml` (`F26`)**: Assert valid YAML; `on.schedule` contains `cron: '0 2 * * 1'` AND `on` contains `workflow_dispatch` (and no `release:`); literal `permissions: contents: write`; single-job release flow (no unguarded inter-job `upload-artifact`); steps reference `SagerNet/sing-box` release check, `.github/workflows` preservation, `go test -race` on `./protocol/aether/...`, all 9 build tags + `release/LDFLAGS`, and GitHub Release publishing.
   - **`bash -n` Syntax Gate**: For every `run:` block across all 4 workflows, replace `${{ ... }}` expressions with `"GHA_PLACEHOLDER"` via regex and execute `bash -n -c <script>`, failing immediately on any shell syntax error.

2. **Tier 4 Implementation-Agnostic Sandboxed Dry-Run of `upstream-sync-release.yml` (`tier4_workload_test.go`, `< 300ms`, Zero Repo Mutation)**:
   - Create `sandbox := t.TempDir()` containing:
     - `sandbox/upstream.git` (bare git repo with initial commit + tag `v1.14.4`, plus a newer commit `v1.14.5` that modifies both `constant/foo.go` AND `.github/workflows/docker.yml`, plus prerelease tag `v1.15.0-alpha.1` and `v1.15.0-rc.1`).
     - `sandbox/origin.git` (bare git repo cloned from `v1.14.4` with custom `.github/workflows/{docker,linux,build-linux-amd64,upstream-sync-release}.yml` and `constant/version.go`).
     - `sandbox/work` (working clone of `sandbox/origin.git`).
     - `sandbox/home/.gitconfig` (`HOME=sandbox/home`, `GIT_CONFIG_NOSYSTEM=1`) configured with:
       ```ini
       [user]
           name = Test Bot
           email = bot@example.com
       [url "file://<sandbox>/upstream.git"]
           insteadOf = https://github.com/SagerNet/sing-box.git
           insteadOf = https://github.com/SagerNet/sing-box
       [url "file://<sandbox>/origin.git"]
           insteadOf = https://github.com/kofttlcc/Aether-sing-box.git
           insteadOf = https://github.com/kofttlcc/Aether-sing-box
       ```
     - `sandbox/bin/{curl,gh,go}` prepended to `PATH`:
       - `curl` & `gh`: intercept `/repos/SagerNet/sing-box/releases/latest` (returning `$MOCK_LATEST_RELEASE_JSON`), `gh release view` (checking `sandbox/published_tags.txt`), and `gh release create` (recording created release tags/files to `sandbox/published_tags.txt`).
       - `go`: logs exact `go test` / `go build` invocations to `sandbox/go_calls.log` and writes a dummy executable on `go build ... -o <out>` (or exits `1` when `$MOCK_GO_TEST_FAIL=1`).
   - Walk the parsed `steps` of `upstream-sync-release.yml`, evaluating `if:` conditions against `$GITHUB_OUTPUT` / `$GITHUB_ENV` and executing each `run:` block in `sandbox/work` across **4 deterministic scenarios**:
     1. **Prerelease (`v1.15.0-alpha.1` with `prerelease: true`, and `v1.15.0-rc.1` tag-pattern filter)**: `origin.git` HEAD unchanged, `published_tags.txt` empty.
     2. **Draft (`v1.14.5` with `draft: true`)**: `origin.git` HEAD unchanged, `published_tags.txt` empty.
     3. **Idempotent Already-Merged (`v1.14.4`)**: `origin.git` HEAD unchanged, `published_tags.txt` empty.
     4. **New Official Stable Release (`v1.14.5`)**:
        - Sub-case 4a (`MOCK_GO_TEST_FAIL=1`): Workflow step exits non-zero and **zero** release is published!
        - Sub-case 4b (`MOCK_GO_TEST_FAIL=0`): `v1.14.5` merges cleanly, `go_calls.log` contains `-race` + `./protocol/aether/...` and all 9 build tags, **`.github/workflows/` in `sandbox/work` `HEAD` matches initial fork workflows byte-for-byte** (`git diff <init_sha> HEAD -- .github/workflows/` is empty!), and real repo `.` `git status --porcelain` remains empty!

---

## 3. Caveats

1. **Open-Half vs Half-Closed (`CloseWrite`) Probe Behavior (`PROJECT.md:235`)**:
   - `PROJECT.md:235` specifies that `StealthDrain` drains with a random `3s..10s` **read deadline** (`io.Copy(io.Discard, conn)`). Therefore, standard active probes in Tiers 1–4 MUST keep their TCP write-half open (`Dial -> Write(probe) -> Read()`), matching real scanners (Nmap/FOFA/curl/TLS). If a probe calls `CloseWrite()` (`FIN`) immediately after sending garbage, `io.Copy` on a pure read-deadline implementation receives `EOF` immediately unless `drain.go` also sleeps until the random deadline on early `EOF`; reserve `CloseWrite()` probe timing for Tier 5 adversarial review (`M6`) rather than Tier 1–4 gating unless `drain.go` explicitly sleeps on early `EOF`.
2. **Sub-20s `PongTimeout` Scaling Window (`PROJECT.md:230`)**:
   - `PROJECT.md:230` mentions both `max(2*HeartbeatInterval, 500ms)` (as an example) and `Specifically: PongTimeout = max(HeartbeatInterval/2, 500*time.Millisecond) when HeartbeatInterval < 20s`. Using `"heartbeat_interval": "600ms"` and asserting blackhole DPD socket closure within **`[400ms, 3.5s]`** accommodates **both** formulas (`500ms` and `1200ms`) cleanly with zero flakiness while still failing v1's infinite hang (`R-3`).
3. **Parallel Track Readiness of `upstream-sync-release.yml` (`M5` vs `E2E-Track`)**:
   - Because `E2E-Track` develops `protocol/aether/e2e/` in parallel with `M2..M5`, `.github/workflows/upstream-sync-release.yml` (`F26`) will not exist on disk until `M5` completes (prior to `M6` full-suite gate). The `F26` E2E test MUST call `t.Fatalf("missing .github/workflows/upstream-sync-release.yml (F26)")` (NOT `t.Skip`!), because per `E2E-Track` opaque-box TDD rules, tests assert the final specification and are gated for 100% pass at **M6** after M2–M5 land.
4. **Sequential Post-Suite Leak Check Ordering**:
   - Never assert `runtime.NumGoroutine()` or `/proc/self/fd` counts inside a `t.Parallel()` subtest while sibling `StealthDrain` goroutines are legitimately mid-drain; execute the leak check in `TestMain` (or after the top-level parallel `t.Run` group completes and `ProfilePool.CloseAll()` finishes).

---

## 4. Conclusion

The timing, wire-assertion, concurrency, and CI validation design above makes **300+ opaque-box E2E subtests in `protocol/aether/e2e/` (`package e2e_test`) completely deterministic under `go test -race` on a 2-vCPU VM within `~12–16s` (`~27–36s` total for `./protocol/aether/...`, well inside the `< 45–60s` budget)**:
1. **Budget & Harness (`harness_test.go`)**: Register minimal cycle-free `sing-box` registries (`aether`, `mixed`, `direct`, `dns/transport/local`, plus `"wiretap"` and `"wiretap-dual"` outbounds), verify `RLIMIT_NOFILE >= 65536` in `TestMain`, use Base64 32B keys everywhere except 1 shared `Argon2id` profile, share 12 lazy `BoxPair` profiles + shared backend servers, and overlap all epoll-waiting tests (`StealthDrain` 10.2s batch, `"time_window": "2s"` 4.3s rotation, `"heartbeat_interval": "600ms"` 2.5s DPD) via `t.Parallel()`.
2. **Exact Wire & Timing Proofs (`tier1`–`tier4`)**: Enforce exact algebraic bounds (`0` `2B`/`18B` writes, `[751, 1103]B` 0-RTT coalesced `600B` burst, `[736, 975]B` coalesced 84B server response, `[569, 808]B` shaped `517B` & `4..7` split writes `<= 1491B` on `3500B` vs exact `553B`/`3536B` unshaped, `0.2197% <= 0.22%` Frame 6+ overhead, `60..140` / `200` (`±5.66σ`) EPK MSB=1 uniformity, `[2.95s, 10.50s]` `io.EOF` `StealthDrain` + `"handshake_timeout": "15s"` `S-1` zero-length-oracle proof, `4608B/2304B` small-window `R-1` saturation, and `R-2` `SetWriteDeadline` atomic write fusing).
3. **Zero-Mutation CI Validation (`tier1` + `tier4`)**: Validate `docker.yml`, `linux.yml`, `build-linux-amd64.yml`, and `upstream-sync-release.yml` via `gopkg.in/yaml.v3` + `bash -n` + `t.TempDir()` `.gitconfig` `url...insteadOf` sandbox execution.

---

## 5. Verification Method

Run from `.` to independently verify all observations and repository cleanliness:

```bash
# 1. Verify repository & branch remain 100% clean and untouched
test "$(git symbolic-ref --short HEAD)" = "dev/aether-v2"
test "$(git rev-parse main)" = "fdaa4c455761bd6ca9d336d6dd09acb3639b34f1"
test -z "$(git status --porcelain)"

# 2. Verify M1 workflow files, option/aether.go, box.go DNS local requirement, and go.mod yaml.v3 entry
grep -n 'local' box.go | grep 'DNSTypeLocal'
grep -n 'yaml.v3' go.mod
grep -n '#release:' .github/workflows/docker.yml .github/workflows/linux.yml

# 3. Once protocol/aether/e2e/ and M2-M5 are implemented, verify the E2E budget & determinism gate:
time GOPROXY=direct GOSUMDB=off CGO_ENABLED=1 go test -count=1 -race -timeout 60s ./protocol/aether/...
```

**Invalidation Conditions**:
- Invalidated if `option/aether.go` field names/types (`time_window`, `handshake_timeout`, `heartbeat_interval`, `disable_shaping`, `detour`) or `PROJECT.md § Interface Contracts` wire header sizes (`96B`/`112B` client prefix, `84B` server prefix, `18B` frame length header, `Frame 0..5` shaping) are modified.
- Invalidated if `box.go` removes `ntp.TimeService` context propagation or `adapter.TCPInjectableInbound` support on `aether.Inbound`.
