# CI/CD, Build Toolchain, Documentation & Test Infrastructure Survey (`explorer_survey_3`)

> **Executive Summary**: Local environment runs `go1.27.3 linux/amd64` on 2-core Intel Xeon Platinum 8481C (with hardware `aes`, `pclmulqdq`, `vaes`, `sha_ni`), `gcc 12.2.0` (`CGO_ENABLED=1`, `go test -race` verified working), and authenticated `gh 2.103.3`, with **all** Aether v2 crypto/runtime/PCAP dependencies (`crypto/ecdh`, `x/crypto/{argon2,hkdf,chacha20,chacha20poly1305}`, `x/sys/cpu`, `sing/common/{buf,ntp}`, `gopacket/pcapgo`) already cached locally; however, sandbox egress blocks `proxy.golang.org` (`403 Forbidden`) while allowing `GOPROXY=direct GOSUMDB=off`, and lacks `tcpdump`/`CAP_NET_RAW`/Docker. In `.github/workflows/`, **both** `docker.yml` AND `linux.yml` carry inherited `release: types: [published]` triggers that misfired and failed on past releases, `build-linux-amd64.yml` lacks `with_quic,with_acme`, `release/LDFLAGS`, and modern Go version while hardcoding `v1.14.2-Custom-Aether`, and Phase 4.2 (`upstream-sync-release.yml`) must handle `default_workflow_permissions: "read"`, GitHub's `GITHUB_TOKEN` restriction on `.github/workflows/*` pushes during upstream merges, and historical Actions Artifact quota exhaustion.

---

## 1. Local Environment, Go Toolchain & Sandbox Quirks

### 1.1 Toolchain & Hardware Capabilities
| Component | Observed Value | Impact on Aether v2 Implementation |
| :--- | :--- | :--- |
| **OS / Kernel** | `Linux sandbox 6.12.105+ x86_64` (Debian 12 userland) | Full Linux TCP/UDP loopback stack (`127.0.0.1`, `[::1]`) |
| **CPU** | `Intel(R) Xeon(R) Platinum 8481C` (2 cores) | Flags include `aes`, `pclmulqdq`, `vaes`, `vpclmulqdq`, `avx2`, `avx512*`, `sha_ni`. `golang.org/x/sys/cpu` (`cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ`) evaluates to `true`. Unit tests in `protocol/aether/crypto_test.go` must explicitly test **both** auto-detected `AES-256-GCM` and forced `ChaCha20-Poly1305` modes. |
| **Go Toolchain** | `go1.27.3 linux/amd64` (`GOROOT=/usr/local/go`, `CGO_ENABLED=1`) | Root `go.mod:3` and `test/go.mod:3` declare `go 1.25.5`. Repo already includes Go 1.27 compatibility (`transport/v2rayhttp/force_close_go127.go`). Native `go test -race` and `go test -fuzz=...` work out-of-the-box. |
| **C Compilers** | `gcc 12.2.0`, `clang 14.0.6`, `make 4.3` | Required by `-race` detector (`CGO_ENABLED=1`); verified passing on `./common/badversion` and `./common/sniff`. |
| **GitHub CLI & Utils** | `gh 2.103.3` (`/opt/antigravity/bin/gh`, logged into `kofttlcc`), `git 2.39.5`, `python3 3.11.2`, `jq 1.6` | Can fetch upstream `SagerNet/sing-box` tags/releases and push/PR to `kofttlcc/Aether-sing-box`. |
| **Missing / Unprivileged** | `tcpdump`: NOT FOUND; `tshark`: NOT FOUND; `golangci-lint`: NOT FOUND; `goreleaser`: NOT FOUND; `dockerd`: NOT RUNNING; `CapEff=0000000000000000` (`!cap_net_raw`, `no-new-privs=1`, no passwordless `sudo`) | Kernel `AF_PACKET` raw socket capture and Docker-based `test/` cases cannot run in-container. Loopback `net.Conn` wire-tap + `gopacket/pcapgo` replaces `tcpdump` cleanly (see Section 5.3). |
| **Git Branch State** | Checked out on local `dev/aether-v2` (`c11bd0e`), 2 doc commits ahead of `main` (`fdaa4c4`, tag `v1.14.2-Custom-Aether`). Note: `remotes/origin/dev/aether-v2` was not listed in `git branch -a` (only `remotes/origin/main` fetched locally). | Verify/push `origin/dev/aether-v2` tracking ref when pushing commits on `dev/aether-v2`. |

### 1.2 Critical Sandbox Go Module Proxy Quirk (`GOPROXY=direct GOSUMDB=off`)
- **Direct Observation**: Default `GOPROXY=https://proxy.golang.org,direct` fails with `HTTP 403 Forbidden` when any uncached module is fetched in this VM (`reading https://proxy.golang.org/...: 403 Forbidden`).
- **Verified Workaround**: Prefixing Go commands with **`GOPROXY=direct GOSUMDB=off`** fetches directly from GitHub over HTTPS and succeeded in compiling `cmd/sing-box` with all target tags.
- **Secondary `with_tailscale` Quirk on `v1.14.2`**: Under `GOPROXY=direct` on `v1.14.2`, enabling `with_tailscale` fails (`github.com/sagernet/gliderssh@v0.3.4-0.20260531100337-2194faca5648: unknown revision 2194faca5648`). Avoiding `with_tailscale` locally (or after syncing `v1.14.4` in Phase 0.1) and using the target 7+2 tags builds cleanly.
- **Pre-Cached Aether v2 Packages (Verified via `go list`)**:
  - `crypto/ecdh` (`/usr/local/go/src/crypto/ecdh`)
  - `golang.org/x/crypto@v0.54.0/{argon2,hkdf,chacha20,chacha20poly1305}`
  - `golang.org/x/sys@v0.47.0/cpu`
  - `github.com/sagernet/sing@v0.9.6-0.20260922013354-87c33f17688f/common/{buf,ntp,network,uot,metadata,bufio}`
  - `github.com/sagernet/sing-mux@v0.3.8`
  - `github.com/google/gopacket@v1.1.19/pcapgo`

---

## 2. Build System, Build Tags & Linker Flags (`Makefile`, `release/*`, `.golangci.yml`)

### 2.1 Official Upstream Tag & Linker Files (`release/`)
1. **`release/LDFLAGS`** (`release/LDFLAGS:1`):
   ```text
   -X runtime.godebugDefault=multipathtcp=0,tlssha1=1 -checklinkname=0
   ```
   - Per `docs/installation/build-from-source.md:65-76`, `-checklinkname=0` is **mandatory** whenever `badlinkname` is enabled on Go 1.23+, and sets `runtime.godebugDefault` defaults expected by `sing-box`.
2. **`release/DEFAULT_BUILD_TAGS_OTHERS`** (`release/DEFAULT_BUILD_TAGS_OTHERS:1`):
   ```text
   with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale,with_ccm,with_ocm,with_cloudflared,with_usbip,with_openvpn,with_openconnect,badlinkname,tfogo_checklinkname0
   ```
3. **`Makefile` Caveat (`Makefile:7`)**:
   - Line 7 runs `go run github.com/sagernet/sing-box/cmd/internal/read_tag@latest` (with `@latest`, which queries `proxy.golang.org`!). Locally and in custom CI workflows, prefer `go run ./cmd/internal/read_tag` or explicit `-X 'github.com/sagernet/sing-box/constant.Version=...'` instead of `Makefile`'s `@latest` invocation.
4. **Build Tag Comparison & Verification**:
   - Current `.github/workflows/build-linux-amd64.yml:33`:
     `with_gvisor,with_dhcp,with_wireguard,with_utls,with_clash_api`
     *(Missing `with_quic` -> breaks Hysteria/Hysteria2/TUIC/QUIC-DNS/HTTP3-DNS; missing `with_acme` -> breaks ACME TLS provider; missing `badlinkname,tfogo_checklinkname0` -> disables kTLS and `tfo-go` optimizations; missing `release/LDFLAGS`!)*.
   - **Verified Recommended Build Command (Phase 0.2 & Phase 4.2)**:
     ```bash
     LDFLAGS_SHARED=$(cat release/LDFLAGS)
     CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
       go build -v -trimpath \
       -tags "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,badlinkname,tfogo_checklinkname0" \
       -ldflags "-X 'github.com/sagernet/sing-box/constant.Version=${VERSION}' ${LDFLAGS_SHARED} -s -w -buildid=" \
       -o build/sing-box-linux-amd64 ./cmd/sing-box
     ```
     *(Tested in this container with `go1.27.3`: exit code `0`, binary `version` output confirmed all 9 tags active).*

### 2.2 Linter & Formatter Rules (`.golangci.yml`)
Even though `golangci-lint` is not installed locally, `.golangci.yml:17-57` defines strict upstream rules that all new Go files in `protocol/aether/`, `option/aether.go`, and `cmd/sing-box/` should obey:
- Enabled linters: `ineffassign`, `staticcheck` (`all`, `-QF1008`, `-ST1003`, `-QF1001`, `-SA4023`), `unused`, `modernize` (with `omitzero` disabled!).
- **Import order (`gci` + `gofumpt`, `.golangci.yml:51-56`)**:
  1. Standard library (`context`, `crypto/...`, `io`, `net`, ...)
  2. `github.com/sagernet/...` (`sing-box/...`, `sing/...`)
  3. Third-party (`github.com/spf13/cobra`, `golang.org/x/crypto/...`, `golang.org/x/sys/cpu`, ...)

---

## 3. Complete GitHub Actions Workflow Audit (`.github/workflows/*.yml`)

### 3.1 Inventory of All 7 Workflow Files
| Workflow File | Triggers (`on:`) | Current Status & Exact Issues Found |
| :--- | :--- | :--- |
| **`build-linux-amd64.yml`** (lines 1–54) | `push` (`main,master,testing`, tags `v*`), `pull_request` (`main,master,testing`), `workflow_dispatch` | 1. **Outdated Go**: `go-version: '1.24.x'` (line 23) vs `go 1.25.5` in `go.mod:3`.<br>2. **Missing Tags**: Line 33 lacks `with_quic,with_acme` (and `badlinkname,tfogo_checklinkname0`).<br>3. **Missing `LDFLAGS`**: Line 32 lacks `$(cat release/LDFLAGS)`.<br>4. **Hardcoded Version & Release Overwrite**: Lines 32, 38–41 hardcode `1.14.2-Custom-Aether` / `tag_name: v1.14.2-Custom-Aether` and run `softprops/action-gh-release@v2` on **every push to `main`**, which will overwrite `v1.14.2-Custom-Aether` when `dev/aether-v2` merges to `main` or conflict with `upstream-sync-release.yml`!<br>5. **No Test Gate**: Does not run `go test -race ./protocol/aether/...` before building/releasing. |
| **`docker.yml`** (lines 1–297) | `release: types: [published]` (lines 8–10), `workflow_dispatch` | **Misfire Confirmed**: Triggered and **FAILED** on past releases (`30641275172`, `30207812494`, `30188360115`, `30140133787`). Compiles 10-arch Chromium/naive matrix, fails `.github/detect_track.sh` (which requires `origin/stable`), and targets `ghcr.io/sagernet/sing-box` (line 17). **Must comment out/remove `release:` trigger in Phase 0.2.** |
| **`linux.yml`** (lines 1–244) | `release: types: [published]` (lines 14–16), `workflow_dispatch` | **CRITICAL EXTRA FINDING**: Just like `docker.yml`, `linux.yml` ALSO has `release: types: [published]` and **ALSO misfired and FAILED** on every manual release (`30641275225`, `30207812476`, `30188360098`, `30140133764`)! Compiles 11-arch matrix, attempts GPG signing with missing `secrets.GPG_KEY` (lines 187–190), and pushes to `push.fury.io/sagernet/` (line 243). **Phase 0.2 MUST disable `release:` trigger in `linux.yml` as well as `docker.yml`!** |
| **`build.yml`** (lines 1–1802) | `workflow_dispatch`, `push` (`stable,testing,unstable`) | Safe: never triggers on `main`, `dev/aether-v2`, tags, or `release`. |
| **`test.yml`** (lines 1–58) | `push` & `pull_request` (`oldstable,stable,testing,unstable`) | Safe (inactive on `main`/`dev/aether-v2`). Uses `go ~1.25` / `~1.26` and `release/DEFAULT_BUILD_TAGS_OTHERS` + `release/LDFLAGS`. |
| **`lint.yml`** (lines 1–80) | `push` & `pull_request` (`oldstable,stable,testing,unstable`) | Safe (inactive on `main`/`dev/aether-v2`). Uses `go ^1.26` and `golangci/golangci-lint-action@v8`. |
| **`stale.yml`** (lines 1–17) | `schedule: cron: "30 1 * * *"` | Currently runs every day at 01:30 UTC on `main` (15 recent runs observed). Harmless, or can optionally be made `workflow_dispatch`-only if unwanted. |

### 3.2 Critical Architectural Constraints for Phase 0.1/0.2 & Phase 4.2 (`upstream-sync-release.yml`)

1. **Phase 0.1 -> Phase 0.2 Ordering Constraint (Upstream `v1.14.2...v1.14.4` Diff Verified)**:
   - Querying `gh api repos/SagerNet/sing-box/compare/v1.14.2...v1.14.4` confirmed **97 commits** touching:
     - `Makefile`, `go.mod`
     - `.github/workflows/build.yml`, `.github/workflows/docker.yml`, `.github/workflows/linux.yml`
   - **Recommendation**: Execute **Phase 0.1 (`git merge v1.14.4`) FIRST**, then apply **Phase 0.2** edits to `.github/workflows/docker.yml`, `.github/workflows/linux.yml`, and `.github/workflows/build-linux-amd64.yml` so there are zero merge conflicts in `.github/workflows/`!

2. **Repository Actions Permissions (`default_workflow_permissions: "read"`)**:
   - Verified via `gh api repos/kofttlcc/Aether-sing-box/actions/permissions/workflow`:
     `{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}`
   - Branch `main` has `protected: false`.
   - Therefore `upstream-sync-release.yml` **MUST** explicitly declare:
     ```yaml
     permissions:
       contents: write
     ```

3. **The `GITHUB_TOKEN` `.github/workflows/*` Push Rejection Trap (CRITICAL)**:
   - GitHub's git receive hook **rejects any `git push` authenticated with `secrets.GITHUB_TOKEN` if the pushed commits modify any file under `.github/workflows/`** (`refusing to allow a GitHub App to create or update workflow ... without 'workflows' permission`), even when `permissions: contents: write` is set!
   - Since upstream `SagerNet/sing-box` modifies `.github/workflows/{build,docker,linux,test,lint}.yml` in nearly every release (confirmed in `v1.14.2...v1.14.4`), a naive `git merge upstream/$TAG && git push origin main` in `upstream-sync-release.yml` **will fail both on merge conflicts (`docker.yml`/`linux.yml`) AND on `git push` rejection**!
   - **Verified Solution for `upstream-sync-release.yml`**:
     - Support `TOKEN: ${{ secrets.WORKFLOW_PAT || secrets.GITHUB_TOKEN }}`, **AND** during automated upstream merge run:
       ```bash
       git merge --no-commit --no-ff "refs/tags/${UPSTREAM_TAG}" || true
       # Always keep our repository's .github/workflows/ intact (avoids upstream CI conflicts AND GITHUB_TOKEN workflow-scope push rejection!)
       git checkout HEAD -- .github/workflows/
       # Check if any unmerged source-code conflicts remain:
       if [ -n "$(git diff --name-only --diff-filter=U)" ]; then
         echo "::error::Merge conflict in source files:"
         git diff --name-only --diff-filter=U
         git merge --abort
         exit 1
       fi
       ```
     - Also update `constant/version.go` (`var Version = "${UPSTREAM_VER}-Custom-Aether"` or `-Aether-v2`) inside that merge commit before running `go test -race ./protocol/aether/...`, committing, pushing `main`, and publishing the release!

4. **Actions Artifact Storage Quota Trap**:
   - Historical failed run `33057035664` (`2026-08-27`) failed on `actions/upload-artifact@v4` with:
     `Failed to CreateArtifact: Artifact storage quota has been hit. Unable to upload any new artifacts.`
   - **Recommendation**: In `upstream-sync-release.yml`, perform checkout -> upstream sync -> `go test -race ./protocol/aether/...` -> cross-compile (`linux-amd64` + `linux-arm64`, `CGO_ENABLED=0`) -> `sha256sum` -> `softprops/action-gh-release@v2` (or `gh release create`) **inside a single job** without inter-job `actions/upload-artifact` transfers. If `upload-artifact` is kept anywhere, always set `continue-on-error: true`.

5. **Coordinating `build-linux-amd64.yml` and `upstream-sync-release.yml`**:
   - Note that pushes/tags created with `secrets.GITHUB_TOKEN` do not recursively trigger other workflows, whereas manual pushes to `main` DO trigger `build-linux-amd64.yml`.
   - Therefore in Phase 0.2:
     - Update `build-linux-amd64.yml` to use `go-version-file: 'go.mod'` (or `'1.25.x'`/`'^1.26'`), add `go test -race ./protocol/aether/...`, add `with_quic,with_acme,badlinkname,tfogo_checklinkname0` and `$(cat release/LDFLAGS)`, read `VERSION` dynamically from `constant/version.go` (or tag name) instead of hardcoding `1.14.2-Custom-Aether`, and restrict its `softprops/action-gh-release@v2` step to **`if: startsWith(github.ref, 'refs/tags/v')`** (not every `refs/heads/main` commit, or match tag dynamically) so merging commits to `main` never overwrites an older release tag!

6. **Upstream Official Stable Release Detection (`SagerNet/sing-box/releases/latest`)**:
   - Tested live via `gh api repos/SagerNet/sing-box/releases/latest`:
     `{"draft":false,"name":"1.14.4","prerelease":false,"published_at":"2026-10-24T01:04:25Z","tag_name":"v1.14.4"}`
   - GitHub's `/releases/latest` endpoint strictly returns the latest non-draft, non-prerelease release. For defense-in-depth, `upstream-sync-release.yml` should also verify:
     - `.prerelease == false` and `.draft == false`
     - `tag_name` matches `^v[0-9]+\.[0-9]+\.[0-9]+$` (strictly excluding `-alpha`, `-beta`, `-rc`)
     - Check whether target release tag (e.g. `${UPSTREAM_TAG}-Custom-Aether` or `${UPSTREAM_TAG}-aether-v2`) already exists via `gh release view` / `git ls-remote --tags origin`, and check `git merge-base --is-ancestor "refs/tags/${UPSTREAM_TAG}" HEAD` so weekly cron runs are 100% idempotent no-ops when already up-to-date.

---

## 4. CLI Keygen, Option Registry, JSON Schema & Documentation Survey

### 4.1 CLI `sing-box generate` Architecture (`cmd/sing-box/cmd_generate*.go`)
- `cmd/sing-box/cmd_generate.go:16-26` defines `var commandGenerate = &cobra.Command{Use: "generate", Short: "Generate things"}`.
- Subcommands are modularized into separate files in `package main` using `func init() { commandGenerate.AddCommand(...) }`:
  - `cmd/sing-box/cmd_generate_wireguard.go` (`wg-keypair`, `reality-keypair`)
  - `cmd/sing-box/cmd_generate_tls.go` (`tls-keypair`)
  - `cmd/sing-box/cmd_generate_ech.go` (`ech-keypair`)
  - `cmd/sing-box/cmd_generate_vapid.go` (`vapid-keypair`)
- **Actionable Recommendation for Phase 0.3**:
  - Implement `aether-key` (32B CSPRNG `base64.StdEncoding`) and `aether-keypair` (`crypto/ecdh.X25519().GenerateKey(rand.Reader)` outputting `PrivateKey: ...` and `PublicKey: ...`) in a dedicated file **`cmd/sing-box/cmd_generate_aether.go`** (or alongside `cmd_generate.go`). Using `cmd_generate_aether.go` follows upstream's exact convention and guarantees zero future upstream merge conflicts in `cmd_generate.go`!

### 4.2 Config Option Registration & JSON Schema (`option/`, `include/`, `schema/`)
- **Dynamic Registry**:
  - `constant/proxy.go:16,80-81` already defines `TypeAether = "aether"` and `ProxyDisplayName(TypeAether) == "Aether"`.
  - `include/registry.go:67,97` already calls `aether.RegisterInbound(registry)` and `aether.RegisterOutbound(registry)`.
  - `option/inbound.go:38-56` and `option/outbound.go:39-61` unmarshal `Inbound` / `Outbound` polymorphically via `InboundOptionsRegistry` / `OutboundOptionsRegistry` in `context.Context`. **No changes to `option/inbound.go` or `option/outbound.go` are required when refactoring `option/aether.go`!**
- **JSON Schema Compatibility (`schema/generator.go`)**:
  - All types in planned `option/aether.go` (`ListenOptions`, `DialerOptions`, `ServerOptions`, `NetworkList`, `[]AetherUser`, `badoption.Duration`, `*InboundMultiplexOptions`, `*OutboundMultiplexOptions`, `*UDPOverTCPOptions`, `string`, `bool`) are natively supported by `schema/generator.go`.
  - Adding struct tag ``enum:"auto,aes-256-gcm,chacha20-poly1305"`` on `AetherOutboundOptions.Cipher` integrates automatically with `schema/generator.go:224-268`.
  - Note: `docs/schema.json` currently has 0 `aether` entries (regenerated via `sing-box schema -o docs/schema.json`).

### 4.3 Documentation Layout (`README.md`, `docs/**`, `mkdocs.yml`)
- `README.md` is unmodified upstream `sing-box` README (`31` lines).
- `docs/aether/` contains `AETHER_V1_SECURITY_AUDIT.md` and `AETHER_V2_DEVELOPMENT_PLAN.md`.
- `docs/configuration/inbound/` and `docs/configuration/outbound/` follow Markdown structure (`shadowsocks.md` / `shadowsocks.zh.md`), indexed in `mkdocs.yml:161-206`. Currently no `aether.md` exists under `docs/configuration/{inbound,outbound}/`.

---

## 5. Test Infrastructure, Loopback E2E & PCAP Verification Capabilities

### 5.1 Root Module Tests vs `test/` Module (`test/go.mod`)
1. **Two Separate Go Modules**:
   - Root module (`github.com/sagernet/sing-box`, `go.mod`) contains unit/integration tests across `adapter/`, `common/`, `dns/`, `option/`, `route/`, and (to be created) `protocol/aether/*_test.go`.
   - `test/` directory is a **separate Go module** (`module test`, `test/go.mod`) with `replace github.com/sagernet/sing-box => ../`.
2. **Important `test/` Module Caveats**:
   - `test/go.mod` is currently out-of-sync (`go test` in `test/` fails with `updates to go.mod needed; to update it: go mod tidy` unless `GOPROXY=direct GOSUMDB=off go mod tidy` is run).
   - `test/clash_test.go:64-101` runs a package-level `func init()` that connects to Docker daemon (logs a warning if absent), and `test/box_test.go:28-30` enforces `goleak.VerifyTestMain(m)`.
   - Crucially, **`.github/workflows/test.yml` and Phase 4.2 (`go test -race ./protocol/aether/...`) run in the ROOT module, NOT `cd test`!**

### 5.2 Cycle-Free Full-Stack `box.Box` E2E Pattern Inside `protocol/aether/*_test.go`
- **Import Cycle Trap Warning**:
  - `include/registry.go:22` imports `github.com/sagernet/sing-box/protocol/aether`.
  - Therefore, tests inside `protocol/aether/*_test.go` (even in `package aether_test`) **MUST NOT import `github.com/sagernet/sing-box/include`**, or Go will reject compilation with `import cycle not allowed in test`!
- **Verified Cycle-Free Full-Stack `box.Box` Helper for `protocol/aether/e2e_test.go` (`package aether_test`)**:
  - Verified in `box.go:1-42`: root package `box` (`github.com/sagernet/sing-box`) does **NOT** import `protocol/aether` or `include`! Neither do `protocol/socks`, `protocol/mixed`, or `protocol/direct`.
  - Therefore, `package aether_test` in `protocol/aether/` can build a complete, real `box.Box` instance (testing JSON config unmarshaling, `Inbound`, `Outbound`, `Multiplex` [`smux`, `yamux`, `h2mux`], `UDPOverTCP`, Native `CommandUDP`, `EarlyConn` 0-RTT, multi-user `EIH`, `InterfaceUpdated`, and `Close` lifecycle!) with **zero import cycles**:
    ```go
    inRegistry := inbound.NewRegistry()
    mixed.RegisterInbound(inRegistry)
    aether.RegisterInbound(inRegistry)

    outRegistry := outbound.NewRegistry()
    direct.RegisterOutbound(outRegistry)
    aether.RegisterOutbound(outRegistry)

    ctx := box.Context(
        context.Background(),
        inRegistry,
        outRegistry,
        endpoint.NewRegistry(),
        dns.NewTransportRegistry(),
        service.NewRegistry(),
        certificate.NewRegistry(),
    )
    instance, err := box.New(box.Options{Context: ctx, Options: opts})
    ```
  - Loopback TCP (`net.Listen("tcp", "127.0.0.1:0")`) and UDP (`net.ListenPacket("udp", "127.0.0.1:0")`) sockets bind cleanly and pass `-race` tests in this container (verified via `TestSniffQUICInitialFromQuicGo`). Using port `0` (`127.0.0.1:0`) or dynamically allocated loopback ports prevents port collisions during parallel `-race` runs.

### 5.3 Go Fuzzing & Wire-Level PCAP Capture Without `tcpdump` / `CAP_NET_RAW`
1. **Go Native Fuzzing (Phase 3.2)**:
   - `FuzzHandshake(f *testing.F)` and `FuzzFrameStream(f *testing.F)` in `protocol/aether/fuzz_test.go` work natively with `go test -fuzz=FuzzHandshake -fuzztime=15s ./protocol/aether` and run their seed corpus automatically during `go test -race ./protocol/aether/...`.
   - For `FuzzHandshake` oracle/timing verification: use an in-memory `net.Pipe()` or mock `Conn` with custom deadline tracking to assert that **every** unauthenticated/mutated byte stream reads **at most fixed prefix (96B single-user / 112B multi-user)** before entering stealth drain, independent of flipped bytes in `EncryptedFixedHeader`!
2. **Wire-Level PCAP & TCP Write-Boundary Verification (Phase 3.2)**:
   - Because `tcpdump` is unavailable and `CapEff=0` blocks `AF_PACKET`, wire-level inspection and `.pcap` generation should use a **`pcapTapConn` (`net.Conn` / `N.Dialer` wrapper)** interposed directly over the real loopback `net.TCPConn` (where Go enables `TCP_NODELAY` by default, so 1 `Write()` syscall == 1 TCP PSH segment):
     - **Already Cached Library**: `github.com/google/gopacket/pcapgo` (`v1.1.19`) is already in `go.mod:119` and cached at `/home/antigravity/go/pkg/mod/github.com/google/gopacket@v1.1.19/pcapgo` (or a 25-line standard-library PCAP binary writer can write standard `0xa1b2c3d4` `.pcap` files to `t.TempDir()` / test artifacts with zero extra imports in `go.mod`!).
     - **Exact Automated Assertions Enabled by `pcapTapConn`**:
       1. **Zero 2-Byte Split Packets**: Assert **0** `Write()` calls have `len(p) == 2` (or `len(p) < 36` on data/control frames).
       2. **0-RTT Coalesced Initial Burst**: Assert Client Write `#0` is a single `Write()` of `>= 96 + NoiseLen + TargetAddr + InitialPayload + 16` bytes containing handshake + first application payload together.
       3. **Zero Plaintext / Uniform Ephemeral Key Distribution**: Assert wire bytes never contain plaintext target host/SNI bytes (`"example.com"`, TLS `0x16 0x03 0x01`), Shannon entropy `> 7.8 bits/byte` on large frames, and across `N >= 500` handshakes bit 255 (`epk[31] & 0x80`) of `MaskedClientEPK` and `MaskedServerEPK` is ~50% `1` (proving Curve25519 MSB bias is eliminated).
       4. **Head-Only Shaping (`Frame 0..5` vs `Frame 6+`)**: Assert inner TLS-like bursts (`517B` ClientHello, `3500B` Certificate) in frames `0..5` have randomized wire lengths and `>1200B` splitting, while from frame `6` onward `PadLen == 0` (`wire_len == chunk_len + 36`, overhead `<= 0.22%` for `16384B` frames).
