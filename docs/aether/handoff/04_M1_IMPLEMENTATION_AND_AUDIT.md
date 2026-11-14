# Milestone M1 Hard Handoff Report — `worker_m1_1`

**Milestone**: M1 (Phase 0 Baseline, `v1.14.4` Sync, Options, CLI Keygen & CI Fixes)
**Branch**: `dev/aether-v2` (`main` untouched at `fdaa4c455761bd6ca9d336d6dd09acb3639b34f1`, not pushed)
**Commits Created on `dev/aether-v2`**:
1. `786d20d4287304cb24ac48bf37ba07fdb035e624` — `chore: merge upstream SagerNet/sing-box v1.14.4` (merges `refs/tags/v1.14.4` = `c005f35300ce76427dc285481ec5695f5b179cd2` onto `c11bd0e897042f9b6ddf3e5d3d0380fcce98feb1` with zero conflicts)
2. `ea7a70b6be9f40a66188a626df5654729d1dc743` — `feat(aether): Phase 0 v1.14.4 adaptation, v2 options, CLI keygen & CI fixes` (touches exclusively the 9 owned M1 files)

---

## 1. Observation

### 1.1 Pre-Modification Repository & Git Hygiene State
1. **Initial Branch & Commit Verification**:
   - Command: `git status --short --branch && git rev-parse HEAD main && git remote -v`
   - Verbatim result prior to edits:
     ```text
     ## dev/aether-v2
     ?? .agents/
     c11bd0e897042f9b6ddf3e5d3d0380fcce98feb1
     fdaa4c455761bd6ca9d336d6dd09acb3639b34f1
     origin	https://github.com/kofttlcc/Aether-sing-box.git (fetch)
     origin	https://github.com/kofttlcc/Aether-sing-box.git (push)
     ```
2. **`.git/info/exclude` Update (`.git/info/exclude:1-8`)**:
   - Appended `.agents/` at line 7 without touching `.gitignore`.
   - Verified `git status --short --branch` immediately reported `## dev/aether-v2` with zero `?? .agents/` untracked output.
3. **Conflict-Free Upstream `v1.14.4` Merge**:
   - Added remote `upstream` (`https://github.com/SagerNet/sing-box.git`), fetched `refs/tags/v1.14.4`, verified `git rev-parse refs/tags/v1.14.4` == `c005f35300ce76427dc285481ec5695f5b179cd2`, and merged onto `dev/aether-v2` (`786d20d4287304cb24ac48bf37ba07fdb035e624`: `330 files changed, 7426 insertions(+), 6116 deletions(-)`), with zero unmerged paths (`git diff --name-only --diff-filter=U` empty).

### 1.2 Exact Files Modified / Created in Commit `ea7a70b6be9f40a66188a626df5654729d1dc743`
1. **`constant/version.go:1-4`**:
   - Updated `var Version = "1.14.2-Custom-Aether"` -> `var Version = "1.14.4-Custom-Aether"`.
2. **`option/aether.go:1-54`**:
   - Replaced legacy v1 structs (`TimeLimitMs`, `HeartbeatIntervalSec`) with canonical `PROJECT.md § Interface Contracts § 2` definitions: `AetherUser`, `AetherInboundOptions` (`Password`, `Key`, `Users`, `ServerPrivateKey`, `TimeWindow`, `HandshakeTimeout`, `HeartbeatInterval`, `DisableShaping`, `Multiplex`), `AetherOutboundOptions` (`Network`, `Password`, `Key`, `Cipher` with `enum:"auto,aes-256-gcm,chacha20-poly1305"`, `ServerPublicKey`, `HeartbeatInterval`, `DisableShaping`, `Multiplex`, `UDPOverTCP`), and `ResolveSecret(password, key string) (string, error)`.
3. **`protocol/aether/inbound.go:1-123`**:
   - Added `var _ adapter.TCPInjectableInbound = (*Inbound)(nil)`.
   - Updated `NewInbound` (`lines 38-60`) to validate and resolve `options.Password`/`options.Key` and all `options.Users[i]` entries via `option.ResolveSecret`, convert `options.TimeWindow.Build().Milliseconds()` (defaulting to `MaxTimeDiffMs` when `<= 0`), and convert `int(options.HeartbeatInterval.Build() / time.Second)`.
   - Updated `Start(stage adapter.StartStage, scope *adapter.Scope) error` (`lines 85-95`) for `sing-box v1.14.4` `adapter.Lifecycle`, registering `scope.Add(in.listener.Close)`, and updated `Close()` (`lines 97-99`) to `common.Close(common.PtrOrNil(in.listener))`.
4. **`protocol/aether/outbound.go:1-186`**:
   - Added compile-time interface assertions (`lines 27-33`) for `adapter.Outbound`, `adapter.Lifecycle`, `adapter.OutboundWithMultiplex`, `adapter.InterfaceUpdateListener`, and `adapter.IdleConnectionKeeper`.
   - Updated `NewOutbound` (`lines 56-68`) to validate `option.ResolveSecret(options.Password, options.Key)` and enforce runtime `options.Cipher` validation (`""`, `"auto"`, `"aes-256-gcm"`, `"chacha20-poly1305"`, returning `unsupported aether cipher: <val>` otherwise), and convert `options.HeartbeatInterval.Build() / time.Second`.
   - Implemented `Start(stage adapter.StartStage, scope *adapter.Scope) error` (at `adapter.StartStateInitialize`, registering `scope.Add(out.multiplexDialer.Close)`), `MultiplexEnabled()`, `InterfaceUpdated(ctx)`, `SetKeepIdleConnections(keep)`, `CloseIdleConnections()`, and `Close()` (`lines 98-132`).
5. **`cmd/sing-box/cmd_generate_aether.go:1-65`**:
   - Registered `aether-key` (32 CSPRNG bytes in `base64.StdEncoding` + `\n`, 45 bytes) and `aether-keypair` (`ecdh.X25519().GenerateKey(rand.Reader)` formatted as `PrivateKey: <b64>\nPublicKey: <b64>\n`, 113 bytes) onto `commandGenerate` in `func init()` with `Args: cobra.NoArgs` and `cmd.OutOrStdout()`.
6. **`cmd/sing-box/cmd_generate_aether_test.go:1-268`**:
   - Added 7 unit/integration tests covering Cobra CLI execution, 32-key CSPRNG uniqueness, X25519 keypair derivation & symmetric ECDH agreement, extra-arg rejection, `io.Writer` error propagation, `option.ResolveSecret` edge cases, runtime `box.New` cipher & conflicting-secret rejection, and `schema.Generate` JSON schema reflection.
   - **Important Upstream Race Discovery**: During initial `-race` execution, running `TestAetherConfigCipherAndSecretValidation` and `TestAetherSchemaReflection` concurrently via `t.Parallel()` triggered a data race inside upstream `include/quic_stub.go:48` (`naive.ConfigureHTTP3ListenerFunc = func(...)` written unsynchronized every time `include.Context(...)` -> `include.InboundRegistry()` is called without `with_quic`). Running `include.Context(...)`-calling tests without `t.Parallel()` resolved the race cleanly.
7. **Workflow Files (`.github/workflows/{docker,linux,build-linux-amd64}.yml`)**:
   - `.github/workflows/docker.yml:8-10`: Commented out `release: types: [published]` after the `v1.14.4` merge (which bumped upstream `go-version` to `1.26.10` cleanly).
   - `.github/workflows/linux.yml:14-16`: Commented out `release: types: [published]` after the `v1.14.4` merge.
   - `.github/workflows/build-linux-amd64.yml:1-79`: Updated to `go-version-file: 'go.mod'`, dynamic `VERSION` resolution (`${GITHUB_REF_NAME#v}` on `refs/tags/v*`, else `constant/version.go`), `CGO_ENABLED=1 go test -race ./cmd/sing-box/... ./protocol/aether/...` gate, full 9-tag static build (`with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,badlinkname,tfogo_checklinkname0` + `$(cat release/LDFLAGS)`), `if: startsWith(github.ref, 'refs/tags/v')` on `softprops/action-gh-release@v2`, and `continue-on-error: true` on `actions/upload-artifact@v4`.

### 1.3 Verbatim Verification Command Outputs
1. **Formatting & `go vet`**:
   - `gofmt -s -d constant/version.go option/aether.go protocol/aether/inbound.go protocol/aether/outbound.go cmd/sing-box/cmd_generate_aether.go cmd/sing-box/cmd_generate_aether_test.go` -> empty diff (`GOFMT_CLEAN`).
   - `GOPROXY=direct GOSUMDB=off go vet ./cmd/sing-box/... ./option/... ./schema/... ./protocol/aether/...` -> exit code `0`.
2. **Default & Full 9-Tag `-race` Test Suites**:
   - `GOPROXY=direct GOSUMDB=off CGO_ENABLED=1 go test -count=1 -v -race -tags "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,badlinkname,tfogo_checklinkname0" -ldflags "$(cat release/LDFLAGS)" ./cmd/sing-box/... ./option/... ./schema/... ./protocol/aether/...`:
     ```text
     --- PASS: TestGenerateAetherKeyCLIAndUniqueness (0.00s)
     --- PASS: TestGenerateAetherKeyPairCLIAndECDH (0.00s)
     --- PASS: TestGenerateAetherCommandsRejectExtraArgs (0.00s)
     --- PASS: TestAetherConfigCipherAndSecretValidation (0.01s)
     --- PASS: TestAetherSchemaReflection (0.16s)
     --- PASS: TestGenerateAetherWriterError (0.00s)
     --- PASS: TestResolveSecretBehavior (0.00s)
     PASS
     ok  	github.com/sagernet/sing-box/cmd/sing-box	1.444s
     ok  	github.com/sagernet/sing-box/option	1.015s
     ?   	github.com/sagernet/sing-box/schema	[no test files]
     ?   	github.com/sagernet/sing-box/protocol/aether	[no test files]
     ```
3. **Full 9-Tag Static Binary Smoke Check (`/tmp/sing-box-m1`, subsequently deleted)**:
   ```text
   === VERSION ===
   sing-box version 1.14.4-Custom-Aether

   Environment: go1.27.3 linux/amd64
   Tags: with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,badlinkname,tfogo_checklinkname0
   Revision: 786d20d4287304cb24ac48bf37ba07fdb035e624
   CGO: disabled
   === GENERATE AETHER-KEY ===
   I+kceYpTKz4I80PNPTHcrWmdqDgXs8bKVjZUEgI0Igs=
   === GENERATE AETHER-KEYPAIR ===
   PrivateKey: gRfye4dDTiHX9HExpHcwIPTuhc4ENqs+HWi3ty+1t7I=
   PublicKey: ZbdxYA/fIFSV1D4b2wDqWef4REpV1nXh+agwWxA7OVg=
   === CHECK ===
   CHECK_OK
   TMP_CLEAN_OK
   ```
4. **Workflow YAML Validation (`explorer_m1_3` Python suite)**:
   - Printed `YAML_VERIFICATION_PASSED` (exit code `0`).
5. **Final Git & Branch Isolation Check**:
   - `git status --short --branch` -> `## dev/aether-v2`
   - `git rev-parse HEAD HEAD~1 refs/tags/v1.14.4 main`:
     - `HEAD`: `ea7a70b6be9f40a66188a626df5654729d1dc743`
     - `HEAD~1`: `786d20d4287304cb24ac48bf37ba07fdb035e624`
     - `refs/tags/v1.14.4`: `c005f35300ce76427dc285481ec5695f5b179cd2`
     - `main`: `fdaa4c455761bd6ca9d336d6dd09acb3639b34f1`
   - `git log -n 3 --stat` contains zero `.agents/` files.

---

## 2. Logic Chain

1. **Conflict-Free Upstream Sync (Obs 1.1)**: Excluding `.agents/` in `.git/info/exclude` and merging `refs/tags/v1.14.4` (`c005f353...`) *before* editing `docker.yml` and `linux.yml` allowed upstream's 330-file diff (`v1.14.2..v1.14.4`) to merge cleanly as dedicated commit `786d20d4287304cb24ac48bf37ba07fdb035e624`, keeping `ea7a70b6be9f40a66188a626df5654729d1dc743` scoped strictly to the 9 M1 files.
2. **Runtime + Schema Option Parity (Obs 1.2 #2–#4)**: Because `schema/generator.go` reads `enum:"auto,aes-256-gcm,chacha20-poly1305"` for JSON Schema generation while `badjson` unmarshaling does not enforce `enum` struct tags at runtime, adding explicit `options.Cipher` validation in `NewOutbound` and `option.ResolveSecret` checks in both `NewInbound` (including `options.Users`) and `NewOutbound` guarantees both `sing-box schema` and `sing-box check` enforce the canonical `PROJECT.md` contract.
3. **Eliminating `os.Exit` & Global Registry Races in CLI Tests (Obs 1.2 #5–#6)**: Delegating `aether-key` and `aether-keypair` to `io.Writer`-accepting helpers via `cmd.OutOrStdout()` and executing `include.Context`-dependent tests without concurrent `t.Parallel()` calls ensures 100% deterministic `-race` test execution across both untagged and 9-tag builds.
4. **CI Reliability & Release Safety (Obs 1.2 #7)**: Disabling `release: [published]` in `docker.yml` and `linux.yml` while gating `softprops/action-gh-release@v2` on `refs/tags/v*` in a single `contents: write` job prevents accidental release overwrites and upstream workflow failures.

---

## 3. Caveats

1. **M1 Protocol Data-Plane Scope**: Per `PROJECT.md` Code Layout, `protocol/aether/{cipher,conn,frame,noise,probe_guard,replay}.go` were left untouched in M1; `inbound.go` and `outbound.go` provide the `v1.14.4` adapter/options compile shim over v1 data-plane primitives until M2–M4 replace them with full AetherFlow-v2 PFS crypto, framing, stealth drain, and native UDP.
2. **Note for Downstream `E2E-Track` & `M4` Test Authors**: Do **not** call `include.Context(...)` concurrently from multiple `t.Parallel()` goroutines when running `go test -race` without `with_quic`, because upstream `include/quic_stub.go:48` writes package-global `naive.ConfigureHTTP3ListenerFunc` without synchronization. Either initialize a shared base `include.Context(context.Background())` once before spawning parallel subtests or run `include.Context(...)` setup sequentially.
3. **VM Sandbox Note on Bare `go mod download`**: Running bare `go mod download` attempts to fetch unused Windows/cronet modules (`golang.zx2c4.com/wintun`, `cronet-go`) blocked in the VM; always run targeted `GOPROXY=direct GOSUMDB=off go build ...` / `go test ...` (all Linux `v1.14.4` modules are now cached in `/home/antigravity/go/pkg/mod`).

---

## 4. Conclusion

Milestone **M1** is 100% complete and committed cleanly on `dev/aether-v2` (`ea7a70b6be9f40a66188a626df5654729d1dc743` atop `v1.14.4` merge `786d20d4287304cb24ac48bf37ba07fdb035e624`, unpushed, `main` untouched at `fdaa4c455761bd6ca9d336d6dd09acb3639b34f1`). The workspace is ready for parallel execution of **M2** (`protocol/aether/{crypto,replay}.go`) and **E2E-Track** (`protocol/aether/e2e/`).

---

## 5. Verification Method

Run from `.`:

```bash
# 1. Verify branch isolation, v1.14.4 ancestor, clean working tree, and zero .agents/ in commits
test "$(git symbolic-ref --short HEAD)" = "dev/aether-v2"
test "$(git rev-parse main)" = "fdaa4c455761bd6ca9d336d6dd09acb3639b34f1"
git merge-base --is-ancestor c005f35300ce76427dc285481ec5695f5b179cd2 HEAD
test -z "$(git status --porcelain)"
test -z "$(git log af6e64c3b69e6132ebaee0e1a3d24e93903f6709..HEAD --name-only -- '.agents*')"

# 2. Verify formatting and -race tests (default & 9-tag builds)
test -z "$(gofmt -s -d constant/version.go option/aether.go protocol/aether/inbound.go protocol/aether/outbound.go cmd/sing-box/cmd_generate_aether.go cmd/sing-box/cmd_generate_aether_test.go)"
GOPROXY=direct GOSUMDB=off CGO_ENABLED=1 go test -count=1 -v -race ./cmd/sing-box/... ./option/... ./schema/... ./protocol/aether/...
GOPROXY=direct GOSUMDB=off CGO_ENABLED=1 go test -count=1 -v -race \
  -tags "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,badlinkname,tfogo_checklinkname0" \
  -ldflags "$(cat release/LDFLAGS)" \
  ./cmd/sing-box/... ./option/... ./schema/... ./protocol/aether/...

# 3. Verify 9-tag static build & CLI commands (cleaning up /tmp afterward)
GOPROXY=direct GOSUMDB=off CGO_ENABLED=0 go build -trimpath \
  -tags "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,badlinkname,tfogo_checklinkname0" \
  -ldflags "-X 'github.com/sagernet/sing-box/constant.Version=1.14.4-Custom-Aether' $(cat release/LDFLAGS) -s -w -buildid=" \
  -o /tmp/sing-box-verify ./cmd/sing-box
/tmp/sing-box-verify version
/tmp/sing-box-verify generate aether-key
/tmp/sing-box-verify generate aether-keypair
rm -f /tmp/sing-box-verify
```

**Invalidation Conditions**: Invalidated if `main` moves from `fdaa4c455761bd6ca9d336d6dd09acb3639b34f1`, if `.agents/` is staged/committed, or if `PROJECT.md § Interface Contracts § 2` option tags/CLI formats are altered.


---

# Gate Status — Project AetherFlow-v2 (`teamwork_preview_orchestrator_r1_1_gen2`)

## Milestone M1 — Iteration 1 (COMPLETED)
| Agent | Role | Verdict | Source |
|-------|------|---------|--------|
| `explorer_m1_1` (`768b08e3dc1dcc4a092e824c63525c2b`) | `teamwork_preview_explorer` | DONE | `explorer_m1_1/handoff.md` |
| `explorer_m1_2` (`985a8bb023b68227e47538bc74f86453`) | `teamwork_preview_explorer` | DONE | `explorer_m1_2/handoff.md` |
| `explorer_m1_3` (`a185c2c7ab4be20c0737e6e9e61864a3`) | `teamwork_preview_explorer` | DONE | `explorer_m1_3/handoff.md` |
| `worker_m1_1` (`43a7ed0f83205ee69bc388650d304d40`) | `teamwork_preview_worker` | DONE (`786d20d` + `ea7a70b`, build & `-race` passed) | `worker_m1_1/handoff.md` |
| `reviewer_m1_1` (`e401600d1f90db19941755f03069aba8`) | `teamwork_preview_reviewer` | APPROVE | `reviewer_m1_1/handoff.md` |
| `reviewer_m1_2` (`abb9fb3fc01e985152b91cf18b074c17`) | `teamwork_preview_reviewer` | APPROVE | `reviewer_m1_2/handoff.md` |
| `challenger_m1_1` (`6a1d382bf0ff68fe767dd4decd7601e9`) | `teamwork_preview_challenger` | APPROVE | `challenger_m1_1/handoff.md` |
| `challenger_m1_2` (`f583c36b776368d062af7d601a68a812`) | `teamwork_preview_challenger` | APPROVE | `challenger_m1_2/handoff.md` |
| `auditor_m1_1` (`2665fc664536b7f2676cacdba058eda8`) | `teamwork_preview_auditor` | CLEAN | `auditor_m1_1/handoff.md` |

Gate Result: **PASS**

---

## Milestone M2 — Iteration 1 (IN_PROGRESS: Step 2B.a Explorers)
| Agent | Role | Verdict | Source |
|-------|------|---------|--------|
| `explorer_m2_1` (`fed243db01e9de87b207c328d69f8016`) | `teamwork_preview_explorer` | DONE | `explorer_m2_1/handoff.md` |
| `explorer_m2_2` (`eec9e0392f9cd99e6e57929762f1afe5`) | `teamwork_preview_explorer` | DONE | `explorer_m2_2/handoff.md` |
| `explorer_m2_3` (`5eaf638154910fbcc56141405c2e8c2b`) | `teamwork_preview_explorer` | DONE | `explorer_m2_3/handoff.md` |
| `worker_m2_1` (`29c76851fdf067f185aceadf4c6fb7fc`) | `teamwork_preview_worker` | IN_PROGRESS | `worker_m2_1/handoff.md` |

Gate Result: **PENDING** (Step 2B.b Worker implementing M2 `crypto.go` & `replay.go`)

---

## E2E-Track (Tiers 1–4 Opaque-Box Suite) — Iteration 1 (IN_PROGRESS: Step 2B.a Explorers)
| Agent | Role | Verdict | Source |
|-------|------|---------|--------|
| `spec_miner_e2e_1` (`ddddcd1afdad778bddfa667ed0be02a0`) | `teamwork_preview_spec_miner` | DONE | `spec_miner_e2e_1/handoff.md` |
| `explorer_e2e_2` (`04df16730c78c6f1799141ad5a1c6537`) | `teamwork_preview_explorer` | IN_PROGRESS | `explorer_e2e_2/handoff.md` |
| `explorer_e2e_3` (`349b693d66e6088cd950d7a97e1cf53f`) | `teamwork_preview_explorer` | DONE | `explorer_e2e_3/handoff.md` |

Gate Result: **PENDING**
