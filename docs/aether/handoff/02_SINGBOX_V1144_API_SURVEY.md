# AetherFlow-v2 Codebase, Git Upstream & `sing-box` Internal API Survey

**Survey Agent**: `explorer_survey_2`  
**Date**: 2026-11-14T02:47:00Z  
**Repository**: `.` (`kofttlcc/Aether-sing-box`)  
**Checked-Out Branch**: `dev/aether-v2` (`c11bd0e897042f9b6ddf3e5d3d0380fcce98feb1`)

---

## Executive Summary (Critical Findings for Implementers)

1. **Clean Textual Merge from Upstream `v1.14.4`, BUT Breaking Compile-Time `adapter.Lifecycle` Change**:
   - Local `main` (`fdaa4c455761bd6ca9d336d6dd09acb3639b34f1`) is built linearly on top of official `SagerNet/sing-box` `v1.14.2` (`af6e64c3b69e6132ebaee0e1a3d24e93903f6709`). Upstream `v1.14.4` (`c005f35300ce76427dc285481ec5695f5b179cd2`, latest official stable release, 97 commits / 300 files ahead of `v1.14.2`) is reachable via `https://github.com/SagerNet/sing-box.git` (not yet fetched into `.git/objects` and no `upstream` remote configured yet) and touches **zero** files modified by Aether (`constant/proxy.go`, `constant/version.go`, `include/registry.go`, `option/aether.go`, `protocol/aether/*`, `.github/workflows/build-linux-amd64.yml`).
   - **CRITICAL**: In `v1.14.4`, `adapter.Lifecycle` changed from `Start(stage StartStage) error; Close() error` to **`Start(stage StartStage, scope *Scope) error`** and `adapter/lifecycle_legacy.go` was deleted. Immediately after merging `v1.14.4` in Phase 0.1, existing `protocol/aether/inbound.go` **will fail to compile** until `Start` is updated to `Start(stage adapter.StartStage, scope *adapter.Scope) error` using `scope.Add(...)`. Furthermore, `OutboundManager` in `v1.14.4` no longer calls `io.Closer.Close()` on outbounds — `Outbound` **must** implement `Start(stage adapter.StartStage, scope *adapter.Scope) error` (at `adapter.StartStateInitialize`) and register `scope.Add(h.multiplexDialer.Close)` (plus implement the new `v1.14.4` `adapter.IdleConnectionKeeper` interface).
2. **Exact Zero-Copy Buffer & Stealth-Drain Traps Identified**:
   - `N.ExtendedWriter.WriteBuffer(buffer *buf.Buffer) error` and `N.PacketWriter.WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error` **take ownership** of `buffer` and **must `defer buffer.Release()`** on all paths; `N.ExtendedReader.ReadBuffer(buffer *buf.Buffer) error` **must NOT release** `buffer`.
   - `N.EarlyConn` (`NeedHandshake() bool`) is deprecated in `sing/common/network`; `bufio.Copy` checks `N.EarlyReader` (`NeedHandshakeForRead() bool`) and `N.EarlyWriter` (`NeedHandshakeForWrite() bool`). Implementing both enables automatic `HandshakeState` headroom recalculation after handshake completion.
   - `N.CloseOnHandshakeFailure(conn, onClose, err)` calls `tcpConn.SetLinger(0)` (emitting an immediate **`TCP RST`**) before `conn.Close()` if `conn` is still open. For `StealthDrain` (`3s..10s` silent read drain mimicking standard read timeout), `drain.go` must close `conn` normally (`conn.Close()` -> TCP `FIN`) after the random drain deadline expires, and invoke `onClose(err)` without triggering `SetLinger(0)` on an open socket.

---

## 1. Git Repository, Upstream `SagerNet/sing-box`, `.git/info/exclude`, and CI State

### 1.1 Local Git State & Branch Topology
- **Current branch**: `dev/aether-v2` (tracks/matches `origin/dev/aether-v2` at `c11bd0e897042f9b6ddf3e5d3d0380fcce98feb1`).
- **`HEAD` (`dev/aether-v2`)**: `c11bd0e897042f9b6ddf3e5d3d0380fcce98feb1` — `docs(aether): refine Aether v2 plan for dedicated-line transit without outer TLS`
  - Parent `d1795f5`: `docs(aether): add v1 security/reliability audit and Aether v2 development plan`
  - Parent `fdaa4c4`: `main`
- **`main` (`origin/main`)**: `fdaa4c455761bd6ca9d336d6dd09acb3639b34f1` (tagged `v1.14.2-Custom-Aether`) — `feat: integrate official upstream sing-box v1.14.2 into Custom-Aether`.
- **`git status --short --branch`**:
  ```
  ## dev/aether-v2
  ?? .agents/
  ```
  Working tree is completely clean except for untracked `.agents/`.
- **Configured git remotes (`git remote -v`)**:
  ```
  origin  https://github.com/kofttlcc/Aether-sing-box.git (fetch)
  origin  https://github.com/kofttlcc/Aether-sing-box.git (push)
  ```
  **Note**: No `upstream` remote (`https://github.com/SagerNet/sing-box.git`) is currently configured in `.git/config`.
- **`.git/info/exclude` (`.git/info/exclude`, lines 1–7)**:
  Currently contains only default git template comments (`# *.[oa]`, `# *~`). `.agents/` is **not** yet listed in `.git/info/exclude` (nor `.gitignore`), which is why `?? .agents/` appears in `git status`. Adding `.agents/` to `.git/info/exclude` in Phase 0 will keep `git status` clean without modifying tracked `.gitignore`.

### 1.2 Upstream `SagerNet/sing-box` Reachability & Commit Comparison (`v1.14.2` vs `v1.14.4`)
- **Network reachability (`git ls-remote https://github.com/SagerNet/sing-box.git`)**: Reachable directly over HTTPS:
  - `refs/tags/v1.14.2` -> `af6e64c3b69e6132ebaee0e1a3d24e93903f6709` (**present** in local git history as the exact base commit beneath `55f0f80..fdaa4c4`, though the tag ref `v1.14.2` itself is not locally created).
  - `refs/tags/v1.14.3` -> `7054cac5124465ffdb145870d7c01885566711b1` (not yet fetched locally).
  - `refs/tags/v1.14.4` -> `c005f35300ce76427dc285481ec5695f5b179cd2` (not yet fetched locally: `git cat-file -t c005f35...` fails).
  - Verified via `gh api repos/SagerNet/sing-box/releases/latest`: `v1.14.4` (`prerelease: false`, `draft: false`, published `2026-10-24T01:04:25Z`) is the latest official stable release (`v1.15.0-alpha.1`..`alpha.13` are pre-releases).
- **Custom commits in `af6e64c..fdaa4c4` (`main` over `v1.14.2`)**:
  12 linear commits touching **13 files** (`+1074/-1`):
  - `.github/workflows/build-linux-amd64.yml` (added, 53 lines)
  - `constant/proxy.go` (`+3`: `TypeAether = "aether"` + `ProxyDisplayName` case)
  - `constant/version.go` (`+1/-1`: `var Version = "1.14.2-Custom-Aether"`, whereas upstream `v1.14.2` and `v1.14.4` both keep `var Version = "unknown"`)
  - `include/registry.go` (`+3`: import `protocol/aether`, `aether.RegisterInbound(registry)`, `aether.RegisterOutbound(registry)`)
  - `option/aether.go` (added, 19 lines)
  - `protocol/aether/{cipher,conn,frame,inbound,noise,outbound,probe_guard,replay}.go` (8 files added)
  - Plus on `dev/aether-v2` (`fdaa4c4..c11bd0e`): `docs/aether/AETHER_V1_SECURITY_AUDIT.md` and `docs/aether/AETHER_V2_DEVELOPMENT_PLAN.md`.
- **Upstream diff `v1.14.2...v1.14.4`**:
  - **97 commits, 300 changed files**, status `ahead` (`behind_by: 0`).
  - **Zero textual file overlap** with any of the 15 files added/edited in `af6e64c..c11bd0e`.
  - **Dependency updates in `go.mod` (`v1.14.2` -> `v1.14.4`)**:
    - `github.com/sagernet/sing`: `v0.9.6-0.20260922013354-87c33f17688f` -> `v0.9.7-0.20261023115459-5dc452e537bf`
    - `github.com/sagernet/sing-mux`: `v0.3.8` -> `v0.3.10-0.20260929204512-caf09fe32475` (adds `SetKeepIdleConnections(bool)` and `CloseIdleConnections()` on `*mux.Client`)
    - `github.com/sagernet/quic-go`: `mod.7` -> `mod.12`
    - `github.com/sagernet/sing-quic`: `v0.7.1-...` -> `v0.7.2-...`
    - `github.com/sagernet/sing-tun`: `v0.9.6-...` -> `v0.9.7-...`
    - `golang.org/x/crypto` (`v0.54.0`) and `golang.org/x/sys` (`v0.47.0`) unchanged.
  - **Go toolchain**: `go.mod` specifies `go 1.25.5`; local VM has **`go1.27.3 linux/amd64`**; upstream `.github/workflows/build.yml` & `docker.yml` use `go-version: 1.26.10` in `v1.14.4` (note `.github/workflows/build-linux-amd64.yml:23` currently hardcodes `go-version: '1.24.x'`, which is older than `go.mod`'s `go 1.25.5` and relies on Go toolchain auto-download unless updated to `1.25.x` / `1.26.x`).

### 1.3 Build Tags & Inherited Workflow Pitfalls (`.github/workflows/`)
- **Upstream canonical Linux build tags** (`release/DEFAULT_BUILD_TAGS_OTHERS:1`):
  ```
  with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale,with_ccm,with_ocm,with_cloudflared,with_usbip,with_openvpn,with_openconnect,badlinkname,tfogo_checklinkname0
  ```
  And `release/LDFLAGS:1`:
  ```
  -X runtime.godebugDefault=multipathtcp=0,tlssha1=1 -checklinkname=0
  ```
  Note: With Go 1.23+, `tfo-go/v2` and `badlinkname` require `-tags "...,badlinkname,tfogo_checklinkname0"` or `-ldflags "-checklinkname=0"` when building full tags (see `Makefile:9-11`). In Phase 0.2, verify `go build` with the target tag set (`with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api` — and check if `-ldflags "-checklinkname=0"` or `badlinkname,tfogo_checklinkname0` is needed on `go1.27.3`!).
- **`.github/workflows/docker.yml` lines 8–10**:
  Has `on: release: types: [published]` with `REGISTRY_IMAGE: ghcr.io/sagernet/sing-box`, which fails on every GitHub Release published in this fork unless disabled (e.g., limiting strictly to `workflow_dispatch` or `if: github.repository == 'SagerNet/sing-box'`).
- **`.github/workflows/build-linux-amd64.yml` lines 32–44**:
  Hardcodes `constant.Version=1.14.2-Custom-Aether`, omits `with_quic,with_acme`, and overwrites release `v1.14.2-Custom-Aether` on every push to `main`.

---

## 2. Protocol Registration Architecture in `sing-box`

Registering a protocol in `sing-box` requires **4 exact touchpoints** (no hardcoded switch statements exist in `option/inbound.go` or `option/outbound.go` — `sing-box` uses generic reflection-based `InboundOptionsRegistry` / `OutboundOptionsRegistry` + `schema` reflection!):

| Layer | File & Lines | Current `aether` Wiring & Notes |
| :--- | :--- | :--- |
| **1. Constant** | `constant/proxy.go:16, 80-81` | `TypeAether = "aether"` and `case TypeAether: return "Aether"` in `ProxyDisplayName`. Already registered. |
| **2. Options & JSON Schema** | `option/aether.go:1-20`<br>(`option/inbound.go:33-68`, `option/outbound.go:34-73`) | `AetherInboundOptions` (embeds `ListenOptions`, which implements `ListenOptionsWrapper`) and `AetherOutboundOptions` (embeds `DialerOptions` + `ServerOptions`, implementing `DialerOptionsWrapper` + `ServerOptionsWrapper`).<br>**Bonus tip**: `sing-box` `schema` generator (`option/shadowsocks.go:6`) supports struct tag `enum:"auto,aes-256-gcm,chacha20-poly1305"` on `Cipher string`! Also note `badoption.Duration` (`github.com/sagernet/sing/common/json/badoption`) parses JSON strings like `"30s"` and converts via `time.Duration(opt)`. |
| **3. Protocol Constructors** | `protocol/aether/inbound.go:21-23`<br>`protocol/aether/outbound.go:22-24` | `inbound.Register[option.AetherInboundOptions](registry, C.TypeAether, NewInbound)`<br>`outbound.Register[option.AetherOutboundOptions](registry, C.TypeAether, NewOutbound)` |
| **4. Global Registry** | `include/registry.go:22, 67, 97` | Imports `"github.com/sagernet/sing-box/protocol/aether"` and calls `aether.RegisterInbound(registry)` in `InboundRegistry()` and `aether.RegisterOutbound(registry)` in `OutboundRegistry()`. Already registered. |

---

## 3. Exact `sing-box` & `sing` Go Signatures (`v1.14.2` vs `v1.14.4`)

### 3.1 Lifecycle & Inbound Interfaces (`adapter/`)

#### CRITICAL CHANGE IN `v1.14.4` (`adapter/lifecycle.go`)
- **In `v1.14.2` (current local tree prior to Phase 0.1 merge)**:
  ```go
  type Lifecycle interface {
      Start(stage StartStage) error
      Close() error
  }
  ```
- **In `v1.14.4` (target baseline after Phase 0.1 merge)**:
  `adapter/lifecycle_legacy.go` is **deleted**, and `Lifecycle` is:
  ```go
  // package adapter ("github.com/sagernet/sing-box/adapter")
  const (
      StartStateInitialize StartStage = iota
      StartStateStart
      StartStatePostStart
      StartStateStarted
  )

  type Lifecycle interface {
      Start(stage StartStage, scope *Scope) error
  }

  // Scope methods:
  func (s *Scope) Context() context.Context
  func (s *Scope) Add(cleanup func() error)
  func (s *Scope) Start(name string, component Lifecycle, stage StartStage) error
  func (s *Scope) Close() error
  ```
  - **Pattern for `Inbound` in `v1.14.4`** (verified from `v1.14.4` `protocol/shadowsocks/inbound.go:98-108` & `protocol/anytls/inbound.go:82-99`):
    ```go
    func (in *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
        if stage != adapter.StartStateStart {
            return nil
        }
        err := in.listener.Start()
        if err != nil {
            return err
        }
        scope.Add(in.listener.Close)
        // If replayFilter has a background rotation goroutine, register scope.Add(in.replayFilter.Close) too!
        return nil
    }
    ```

#### `adapter.Inbound` & `adapter.TCPInjectableInbound` (`adapter/inbound.go:18-27`, `adapter/handler.go:12-14`)
```go
type Inbound interface {
    Lifecycle
    Type() string
    Tag() string
}

type ConnectionHandler interface {
    NewConnection(ctx context.Context, conn net.Conn, metadata InboundContext, onClose N.CloseHandlerFunc)
}

type TCPInjectableInbound interface {
    Inbound
    ConnectionHandler
}
```
- Embedding `inbound.Adapter` (`inbound.NewAdapter(C.TypeAether, tag)`) provides `Type() string` and `Tag() string`.
- Implementing `NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc)` satisfies both `listener.Options.ConnectionHandler` AND `adapter.TCPInjectableInbound` (`var _ adapter.TCPInjectableInbound = (*Inbound)(nil)`).
- Note: `NewConnectionEx` in v1 `inbound.go:94-103` is only needed if passing `Inbound` directly as an `N.TCPConnectionHandlerEx`; `listener.New(listener.Options{ConnectionHandler: in, ...})` takes `adapter.ConnectionHandler` (`NewConnection`).

### 3.2 Outbound Interfaces (`adapter/outbound.go` & `adapter/network.go`)

```go
// package adapter
type Outbound interface {
    Type() string
    Tag() string
    Network() []string
    Dependencies() []string
    N.Dialer
}

type OutboundWithMultiplex interface {
    Outbound
    MultiplexEnabled() bool
}

// adapter/network.go:52-54
type InterfaceUpdateListener interface {
    InterfaceUpdated(ctx context.Context)
}

// NEW in v1.14.4 (adapter/outbound.go:53-56):
type IdleConnectionKeeper interface {
    SetKeepIdleConnections(keep bool)
    CloseIdleConnections()
}
```
- Embedding `outbound.Adapter` via `outbound.NewAdapterWithDialerOptions(C.TypeAether, tag, options.Network.Build(), options.DialerOptions)` provides `Type()`, `Tag()`, `Network()`, and `Dependencies()`.
- **Reference `v1.14.4` `Outbound` compile-time assertions & lifecycle methods** (verified from `v1.14.4` `protocol/shadowsocks/outbound.go` & `protocol/trojan/outbound.go`):
  ```go
  var (
      _ adapter.Outbound                = (*Outbound)(nil)
      _ adapter.Lifecycle               = (*Outbound)(nil)
      _ adapter.OutboundWithMultiplex   = (*Outbound)(nil)
      _ adapter.InterfaceUpdateListener = (*Outbound)(nil)
      _ adapter.IdleConnectionKeeper    = (*Outbound)(nil)
  )

  func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
      if stage != adapter.StartStateInitialize {
          return nil
      }
      if h.multiplexDialer != nil {
          scope.Add(h.multiplexDialer.Close)
      }
      return nil
  }

  func (h *Outbound) MultiplexEnabled() bool {
      return h.multiplexDialer != nil
  }

  func (h *Outbound) InterfaceUpdated(ctx context.Context) {
      if h.multiplexDialer != nil {
          h.multiplexDialer.Reset()
      }
  }

  func (h *Outbound) SetKeepIdleConnections(keep bool) {
      if h.multiplexDialer != nil {
          h.multiplexDialer.SetKeepIdleConnections(keep)
      }
  }

  func (h *Outbound) CloseIdleConnections() {
      if h.multiplexDialer != nil {
          h.multiplexDialer.CloseIdleConnections()
      }
  }

  // Optional convenience method for direct unit test cleanup:
  func (h *Outbound) Close() error {
      return common.Close(common.PtrOrNil(h.multiplexDialer))
  }
  ```

### 3.3 `sing/common/network` (`N`) & `sing/common/buf` Zero-Copy Contracts

#### Core Connection Interfaces (`github.com/sagernet/sing/common/network`)
```go
type ExtendedReader interface {
    io.Reader
    ReadBuffer(buffer *buf.Buffer) error
}

type ExtendedWriter interface {
    io.Writer
    WriteBuffer(buffer *buf.Buffer) error
}

type ExtendedConn interface {
    ExtendedReader
    ExtendedWriter
    net.Conn
}

// Early 0-RTT Handshake interfaces (early.go):
// Note: EarlyConn is deprecated; implement EarlyWriter + EarlyReader (and optionally NeedHandshake() bool):
type EarlyWriter interface {
    NeedHandshakeForWrite() bool
}
type EarlyReader interface {
    NeedHandshakeForRead() bool
}
type EarlyConn interface { // Deprecated
    NeedHandshake() bool
}

// Half-close interface:
type WriteCloser interface {
    CloseWrite() error
}

// Headroom & MTU interfaces (used by N.NewReadWaitOptions in bufio.Copy):
type FrontHeadroom interface {
    FrontHeadroom() int
}
type RearHeadroom interface {
    RearHeadroom() int
}
type ReaderWithMTU interface {
    ReaderMTU() int
}
type WriterWithMTU interface {
    WriterMTU() int
}

// PacketConn interfaces (for CommandUDP Native UDP over Aether stream):
type PacketReader interface {
    ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error)
}
type PacketWriter interface {
    WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error
}
type PacketConn interface {
    PacketReader
    PacketWriter
    Close() error
    LocalAddr() net.Addr
    SetDeadline(t time.Time) error
    SetReadDeadline(t time.Time) error
    SetWriteDeadline(t time.Time) error
}
// Wrapping an N.PacketConn into a net.Conn + net.PacketConn for DialContext("udp"):
// bufio.NewBindPacketConn(packetConn, destination) -> N.BindPacketConn (implements net.Conn & net.PacketConn)
// Or implement ReadFrom / WriteTo (see transport/trojan/protocol.go:132-158) so ClientPacketConn directly satisfies net.PacketConn!
```

#### MANDATORY Buffer Ownership & Upstream Unwrap Rules (`sing/common/bufio/conn.go` & `network/conn.go`)
1. **`WriteBuffer(buffer *buf.Buffer) error`**:
   - **Caller transfers ownership of `buffer` to `WriteBuffer`.**
   - `WriteBuffer` **MUST** call `defer buffer.Release()` on **every** return path (including early validation/closed errors and `NeedHandshakeForWrite` 0-RTT path).
2. **`WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error`**:
   - **Caller transfers ownership of `buffer` to `WritePacket`.**
   - `WritePacket` **MUST** call `defer buffer.Release()` on **every** return path.
3. **`ReadBuffer(buffer *buf.Buffer) error`**:
   - **Caller retains ownership of `buffer`.** `ReadBuffer` **MUST NOT** call `buffer.Release()`.
   - Write decrypted payload bytes into `buffer` (e.g. via `buffer.Write(data)` or decrypting directly into `buffer.FreeBytes()` + `buffer.Extend(n)` / `buffer.Truncate(n)`). Note: if `n > 0` bytes were placed in `buffer`, return `nil` (not `io.EOF`).
4. **`Upstream() any` vs `ReaderReplaceable()` / `WriterReplaceable()`**:
   - Implement `Upstream() any { return c.Conn }` (`common.WithUpstream`) so `sing` can inspect the underlying `net.Conn` for metadata/addresses.
   - **NEVER return `true` from `ReaderReplaceable()` or `WriterReplaceable()`** on Aether `Conn`! If `ReaderReplaceable()`/`WriterReplaceable()` returns `true`, `N.UnwrapReader` / Linux `splice` will unwrap `c.Conn` and bypass Aether AEAD encryption/decryption!
5. **`ReadWaiter` (`N.ReadWaiter`) Assessment**:
   - `ReadWaiter` (`InitializeReadWaiter(options N.ReadWaitOptions) bool` + `WaitReadBuffer() (*buf.Buffer, error)`) is optional. In `sing/common/bufio`, if `Conn` implements `N.ExtendedConn` (`ReadBuffer` + `WriteBuffer`) plus `FrontHeadroom()`, `RearHeadroom()`, and `WriterMTU()`, `bufio.CopyExtended` allocates pooled `*buf.Buffer` with exact `FrontHeadroom` + `RearHeadroom` and calls `source.ReadBuffer(buf)` -> `dest.WriteBuffer(buf)` without extra copies. Implementing `ReadWaiter` is only needed if `Conn` wants to allocate the output `*buf.Buffer` *after* reading the 18B encrypted length header; if implemented, remember `WaitReadBuffer` must allocate via `c.readWaitOptions.NewBufferSize(plainDataLen)` and call `c.readWaitOptions.PostReturn(buffer)` before returning `buffer`.

#### Key `buf.Buffer` Methods (`github.com/sagernet/sing/common/buf`)
- Allocation: `buf.New()`, `buf.NewSize(size int) *buf.Buffer`, `buf.NewPacket() *buf.Buffer`, `buf.With(data []byte) *buf.Buffer` (unowned wrapper around slice), `buf.As(data []byte) *buf.Buffer`.
- Lifecycle: `b.Release()` (returns pooled backing slice).
- Slicing & Headroom:
  - `b.Start() int` — available front headroom bytes before `start`.
  - `b.Len() int` — active payload length (`end - start`).
  - `b.FreeLen() int` — available tail capacity (`cap - end`).
  - `b.FreeBytes() []byte` — `data[end:cap]`.
  - `b.Bytes() []byte` — `data[start:end]`.
  - `b.ExtendHeader(n int) []byte` — prepends `n` bytes into front headroom (`start -= n`) and returns `data[start : start+n]` (panics if `Start() < n`, so always check `b.Start() >= n` first!).
  - `b.Extend(n int) []byte` — appends `n` uninitialized bytes at tail (`end += n`) and returns `data[end-n : end]` (panics if `FreeLen() < n`, so check `b.FreeLen() >= n`!).
  - `b.Advance(from int)` — `start += from`.
  - `b.Truncate(to int)` — `end = start + to`.
  - `b.Resize(start, end int)` — sets `start` and `end = start + end` (length).
  - `b.ReadFullFrom(r io.Reader, size int) (int, error)` — reads exact `size` bytes from `r` into `FreeBytes()` and advances `end`.

---

## 4. Multiplex (`sing-mux`), UoT, and Native UDP (`CommandUDP`) Routing Architecture

### 4.1 How `common/mux`, `common/uot`, and Native `CommandUDP` Compose Cleanly
In `sing-box`:
1. **Inbound Router Stack** (`protocol/aether/inbound.go` — compare `protocol/shadowsocks/inbound_multi.go:51-58`):
   ```go
   var routerEx adapter.ConnectionRouterEx = uot.NewRouter(router, logger) // "github.com/sagernet/sing-box/common/uot"
   routerEx, err = mux.NewRouterWithOptions(routerEx, logger, common.PtrValueOrDefault(options.Multiplex)) // "github.com/sagernet/sing-box/common/mux"
   ```
   - When `Command == CommandMux (0x03)` or `metadata.Destination == singmux.Destination` (`Fqdn: "sp.mux.sing-box.arpa", Port: 444`):
     Setting `metadata.Destination = singmux.Destination` and calling `in.router.RouteConnectionEx(ctx, aetherConn, metadata, onClose)` causes `mux.Router` (`common/mux/router.go:70-75`) to intercept the stream and hand it to `mux.Service.NewConnectionEx`! (Note: if `options.Multiplex` is not enabled on inbound, `mux.NewRouterWithOptions` returns `uot.Router` unwrapped — so inbound should reject `CommandMux` early if `!in.muxEnabled` rather than letting `sp.mux.sing-box.arpa:444` route to DNS/outbound!).
   - When `Command == CommandUoT (0x04)` or `metadata.Destination.Fqdn` is `uot.MagicAddress` (`"sp.v2.udp-over-tcp.arpa"`) or `uot.LegacyMagicAddress` (`"sp.udp-over-tcp.arpa"`):
     `in.router.RouteConnectionEx(ctx, aetherConn, metadata, onClose)` passes through `mux.Router` to `uot.Router` (`common/uot/router.go:55-82`), which reads the UoT request and calls `router.RoutePacketConnectionEx(ctx, uot.NewConn(aetherConn, *request), metadata, onClose)`!
   - When `Command == CommandTCP (0x01)`:
     `in.router.RouteConnectionEx(ctx, aetherConn, metadata, onClose)` routes normal TCP connections.
   - When `Command == CommandUDP (0x02)` (Native Framed UDP over Aether stream):
     Wrap `aetherConn` in Aether's server `PacketConn` (`N.PacketConn` reading/writing `[AddrPort (M.SocksaddrSerializer) | uint16 Len | Payload]` packets over Aether frames, just like `transport/trojan/service.go:108-109, 126-149`) and call:
     ```go
     in.router.RoutePacketConnectionEx(ctx, NewServerPacketConn(aetherConn), metadata, onClose)
     ```
2. **Outbound Routing Stack** (fixing v1 `R-5` completely):
   - In `NewOutbound`: **Initialize BOTH `multiplexDialer` and `uotClient` independently** (do NOT gate `multiplexDialer` behind `if !uotOptions.Enabled`!):
     ```go
     uotOptions := common.PtrValueOrDefault(options.UDPOverTCP)
     if uotOptions.Enabled {
         out.uotClient = &uot.Client{
             Dialer:  (*aetherDialer)(out),
             Version: uotOptions.Version,
         }
     }
     out.multiplexDialer, err = mux.NewClientWithOptions((*aetherDialer)(out), logger, common.PtrValueOrDefault(options.Multiplex))
     ```
   - In `Outbound.DialContext(ctx, network, destination)`:
     1. If `out.multiplexDialer != nil`: `return out.multiplexDialer.DialContext(ctx, network, destination)` (handles both TCP and UDP over `sing-mux`; `sing-mux` dials `aetherDialer.DialContext(ctx, "tcp", singmux.Destination)` -> `CommandMux`).
     2. Else if `N.NetworkName(network) == N.NetworkUDP`:
        - If `out.uotClient != nil`: `return out.uotClient.DialContext(ctx, network, destination)` (`uot.Client` dials `aetherDialer.DialContext(ctx, "tcp", uot.RequestDestination(version))` -> `CommandUoT`).
        - Else: `return (*aetherDialer)(out).DialContext(ctx, N.NetworkUDP, destination)` -> dials TCP to `serverAddr` with `CommandUDP (0x02)` and returns `bufio.NewBindPacketConn(NewClientPacketConn(aetherConn), destination)`.
     3. Else (`N.NetworkTCP`): `return (*aetherDialer)(out).DialContext(ctx, N.NetworkTCP, destination)` -> `CommandTCP (0x01)` returning 0-RTT `EarlyConn`.
   - In `Outbound.ListenPacket(ctx, destination)`:
     1. If `out.multiplexDialer != nil`: `return out.multiplexDialer.ListenPacket(ctx, destination)`
     2. Else if `out.uotClient != nil`: `return out.uotClient.ListenPacket(ctx, destination)`
     3. Else: `return (*aetherDialer)(out).ListenPacket(ctx, destination)` -> dials TCP to `serverAddr` with `CommandUDP (0x02)` and returns `NewClientPacketConn(aetherConn)` (implementing `net.PacketConn` + `N.PacketConn`).

### 4.2 Exact `M.SocksaddrSerializer` & `ntp.TimeFuncFromContext` Signatures
- **`M.SocksaddrSerializer`** (`github.com/sagernet/sing/common/metadata`):
  Uses standard SOCKS5 address family bytes (`0x01` IPv4, `0x04` IPv6, `0x03` FQDN):
  ```go
  M.SocksaddrSerializer.AddrPortLen(destination M.Socksaddr) int
  M.SocksaddrSerializer.WriteAddrPort(writer io.Writer, destination M.Socksaddr) error
  M.SocksaddrSerializer.ReadAddrPort(reader io.Reader) (destination M.Socksaddr, err error)
  ```
  Replacing v1's custom `EncodeAddress(string)`/`DecodeAddress([]byte)` (`frame.go:26-102`) with `M.SocksaddrSerializer` eliminates string formatting/parsing allocations and preserves `M.Socksaddr` directly!
- **`ntp.TimeFuncFromContext`** (`github.com/sagernet/sing/common/ntp`):
  ```go
  timeFunc := ntp.TimeFuncFromContext(ctx) // returns func() time.Time (may be nil if no NTP service in ctx!)
  if timeFunc == nil {
      timeFunc = time.Now
  }
  ```
  **Important Caveat**: Verified from `sing-shadowsocks/shadowaead_2022/protocol.go:226-232`: `TimeFuncFromContext(ctx)` can return `nil` when no NTP service is configured in `ctx` (e.g. in unit tests or minimal configs)! Always nil-guard `if timeFunc == nil { timeFunc = time.Now }`.

---

## 5. Cryptography, Key Derivation & CPU Hardware AES Detection APIs

All required cryptographic packages are already in Go stdlib or direct `go.mod` dependencies (**zero `go.mod` additions required**):

| Component | Import Path | Exact Function / Signature | Notes |
| :--- | :--- | :--- | :--- |
| **Argon2id** | `golang.org/x/crypto/argon2` (`v0.54.0`) | `argon2.IDKey(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte` | Note: `memory` is in **KiB**! For `64 MB`, pass `memory = 64 * 1024` (`65536`), `time = 3`, `threads = 4`, `keyLen = 32`, `salt = []byte("AetherFlow-v2-KDF")`. |
| **X25519 ECDHE** | `crypto/ecdh` (stdlib) | `curve := ecdh.X25519()`<br>`priv, err := curve.GenerateKey(rand.Reader)`<br>`pubBytes := priv.PublicKey().Bytes()` (32B)<br>`peerPub, err := curve.NewPublicKey(b)`<br>`shared, err := priv.ECDH(peerPub)` (32B) | `priv.ECDH(peerPub)` automatically rejects all-zero low-order shared secrets per RFC 7748 and returns an error. |
| **HKDF-SHA256** | `crypto/hkdf` (stdlib Go 1.24+) **or** `golang.org/x/crypto/hkdf` | Stdlib: `hkdf.Key(sha256.New, secret, salt, infoString, keyLen)` / `hkdf.Extract` + `hkdf.Expand`<br>`x/crypto`: `hkdf.New(sha256.New, secret, salt, []byte(info))` | Both are available (`go.mod` is `go 1.25.5`, VM is `go1.27.3`, `x/crypto` is `v0.54.0`). `crypto/hkdf.Extract` + `crypto/hkdf.Expand` is super clean and zero-extra-import. |
| **EPK Stream Mask** | `golang.org/x/crypto/chacha20` | `c, err := chacha20.NewUnauthenticatedCipher(key32, nonce12)`<br>`c.XORKeyStream(dst32, src32)` | Or simply XOR with 32 bytes directly output from `hkdf.Key(sha256.New, uPSK, clientSalt, "AetherFlow-v2-EPK-Mask", 32)` (or ChaCha20 keystream with zero nonce from that derived key). Both are involutions (`mask(mask(epk)) == epk`) and 100% uniform! |
| **ChaCha20-Poly1305** | `golang.org/x/crypto/chacha20poly1305` | `chacha20poly1305.New(key []byte) (cipher.AEAD, error)` (`KeySize=32, NonceSize=12, Overhead=16`) | Direct dependency in `go.mod`. |
| **AES-256-GCM** | `crypto/aes` + `crypto/cipher` (stdlib) | `block, err := aes.NewCipher(key32)`<br>`aead, err := cipher.NewGCM(block)` (`NonceSize=12, Overhead=16`) | Hardware-accelerated via AES-NI+PCLMULQDQ / ARMv8 Crypto Extensions. |
| **Hardware AES-GCM Detection** | `golang.org/x/sys/cpu` (`v0.47.0`) + `runtime` | Exact match to Go stdlib `crypto/tls/cipher_suites.go:363-368`:<br>`hasGCMAsmAMD64 := cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ && cpu.X86.HasSSE41 && cpu.X86.HasSSSE3`<br>`hasGCMAsmARM64 := cpu.ARM64.HasAES && cpu.ARM64.HasPMULL`<br>`hasGCMAsmARM := cpu.ARM.HasAES && cpu.ARM.HasPMULL`<br>`hasGCMAsmS390X := cpu.S390X.HasAES && cpu.S390X.HasAESCTR && cpu.S390X.HasGHASH`<br>`hasGCMAsmPPC64 := runtime.GOARCH == "ppc64" \|\| runtime.GOARCH == "ppc64le"` | `golang.org/x/sys` is already a direct dependency in `go.mod:76`! Checking both `HasAES` AND `HasPCLMULQDQ` / `HasPMULL` matches Go stdlib's exact constant-time GCM assembly threshold. |

---

## 6. CLI `generate` Subcommand Wiring (`cmd/sing-box/`)

- **Root generate command (`cmd/sing-box/cmd_generate.go:16-26`)**:
  ```go
  var commandGenerate = &cobra.Command{
      Use:   "generate",
      Short: "Generate things",
  }
  ```
- **Modular registration convention (`cmd/sing-box/cmd_generate_*.go`)**:
  `sing-box` places protocol-specific generators in dedicated files in `package main` (`cmd_generate_wireguard.go`, `cmd_generate_tls.go`, `cmd_generate_vapid.go`, `cmd_generate_ech.go`) and registers them in `func init()` via `commandGenerate.AddCommand(...)` (or directly in `cmd_generate.go`, as specified in `AETHER_V2_DEVELOPMENT_PLAN.md` line 182 & 229).
  - Example from `cmd/sing-box/cmd_generate_vapid.go:31-40` & `cmd_generate_wireguard.go:52-61`:
    - Uses `crypto/ecdh` + `crypto/rand` + `encoding/base64` + `os.Stdout.WriteString(...)`, calling `log.Fatal(err)` on error in `Run`.
  - **Encoding Consistency Note for `aether-key` & `aether-keypair`**:
    - `cmd_generate.go:63` (`sing-box generate rand 32 --base64`) uses `base64.StdEncoding.EncodeToString(...)` (44 chars with `=`).
    - `cmd_generate_wireguard.go:58-59` (`reality-keypair`) uses `base64.RawURLEncoding` while `wg-keypair` uses `base64.StdEncoding`.
    - Recommendation for `crypto.go` key parser: emit `base64.StdEncoding` in `sing-box generate aether-key` / `aether-keypair` (matching `generate rand 32 --base64` and Shadowsocks-2022), and in `crypto.go` accept `base64.StdEncoding`, `base64.RawStdEncoding`, `base64.URLEncoding`, or `base64.RawURLEncoding` when decoding 32-byte keys so users never hit padding/URL-alphabet mismatches!
