# Downstream M3/M4 Crypto & Anti-Replay Interface Integration & Edge-Case Audit (`explorer_m2_3`)

**Core Summary**: Across `S-1`, `S-3`, `S-4`, `S-5`, `S-6` and `PROJECT.md § Interface Contracts § 3–4`, we verified Go 1.27.3 (`go1.27.3`) stdlib internals (`crypto/ecdh`, `crypto/hkdf`, `encoding/base64`) and `sing v0.9.7` (`common/ntp`, `common/buf`), uncovering **9 non-obvious security, allocation, compatibility, and CI-flakiness traps** at the M2 → M3/M4 boundary (including a `1 alloc/frame` `cipher.AEAD` interface escape, `NewPublicKey` accepting all 14 low-order X25519 points at startup, `MultiUserEIH`/`MultiUserDirect` timing side-channels, expired-packet Bloom pollution, NTP backward-jump rotation stalls, Base64 `\r\n`/trailing-bit collisions, `<valid>:<all-zero-b64>` colon-split bypass, and `64`-column `χ²` FWER flakiness). Exact zero-allocation Go types, helper signatures, ordering invariants, and statistical test formulas for `crypto.go`, `crypto_test.go`, `replay.go`, and `replay_test.go` are specified below.

---

## 1. Observation

### 1.1 Existing Repository State & Coexistence Boundaries (`M1` → `M2` → `M3` → `M4`)
1. **`option/aether.go:8-49` & `cmd/sing-box/cmd_generate_aether_test.go:190-210`**:
   - `option.ResolveSecret(password, key string) (string, error)` (`option/aether.go:41-49`) returns `E.New("conflicting password and key")` when both are non-empty and unequal, and `""` when both are empty.
   - `cmd/sing-box/cmd_generate_aether_test.go:195-202` runs full `box.New(...)` initialization against `aether` inbound/outbound and **explicitly asserts**:
     - `"key":"0123456789abcdef0123456789abcdef"` (32 ASCII hex chars; valid Base64 of **24 bytes**, NOT 32 bytes!) succeeds at startup.
     - `"cipher":"aes-128-gcm"` fails startup with `require.ErrorContains(t, err, "unsupported aether cipher")` (`line 201`, matching `protocol/aether/outbound.go:64`).
2. **Existing `package aether` symbols that MUST NOT collide in M2 (`protocol/aether/{cipher,replay,inbound,outbound,conn}.go`)**:
   - `protocol/aether/cipher.go:15-50, 117` declares `SaltSize = 32`, `KeySize = 32`, `TagSize = 16`, `NonceSize = 12`, `HKDFInfoString`, `ErrInvalidTag`, `ErrShortBuffer`, `ErrReplayDetected`, `ErrInvalidHeader`, `CipherSession`, `GenerateSalt()`, `KeyFromPassword()`, `NewCipherSession()`, and `encodeNonce(seq uint64, dst []byte)`.
   - `protocol/aether/replay.go:8-34` declares `MaxTimeDiffMs = 30000`, `LRUWindowSize = 10000`, `ReplayFilter`, `NewReplayFilter(maxSize int, timeLimitMs int64) *ReplayFilter`, and `(*ReplayFilter).CheckAndAdd(timestampMs int64, nonce uint64) bool` (called by `inbound.go:55,70` and `conn.go:156,212` until M3/M4 replace them).
   - Per `PROJECT.md:85, 257-264`, M2 owns ONLY `protocol/aether/{crypto,crypto_test,replay,replay_test}.go`, while legacy `{cipher,frame,noise,probe_guard}.go` are deleted in M4.
3. **Go 1.27.3 `crypto/ecdh` X25519 Exact Implementation (`/usr/local/go/src/crypto/ecdh/{ecdh.go,x25519.go}`, `edwards25519/field/fe.go`)**:
   - `(*x25519Curve).NewPublicKey(key []byte)` (`/usr/local/go/src/crypto/ecdh/x25519.go:69-80`) **ONLY checks `len(key) == 32`** (and `!fips140only.Enforced()`). As documented at `ecdh.go:43-45` (`"For X25519, this only checks the u-coordinate length"`), `NewPublicKey` returns `(pub, nil)` for `[32]byte{}` and for all RFC 7748 small-order points.
   - `(*x25519Curve).NewPrivateKey(key []byte)` (`x25519.go:49-67`) **ONLY checks `len(key) == 32`**. It accepts all-zero `[32]byte{}` (clamping `e[0] &= 248; e[31] &= 127; e[31] |= 64` at `x25519.go:95-97` into scalar `2^254`).
   - `(*PrivateKey).ECDH(remote *PublicKey)` (`ecdh.go:131-136`, `x25519.go:82-89`):
     - Dereferences `k.curve != remote.curve` at `ecdh.go:132` (panics if `k == nil` or `remote == nil`).
     - Runs `x25519ScalarMult(out, local.privateKey, remote.publicKey)` (`field.Element.SetBytes` at `fe.go:170-193` masks bit 255 and reduces non-canonical `2^255-19 .. 2^255-1` modulo `p = 2^255 - 19`), then checks constant-time `isZero(out)` (`x25519.go:85-87, 144-150`) and returns `(nil, errors.New("crypto/ecdh: bad X25519 remote ECDH input: low order point"))`.
   - Empirical verification across all **14** `[32]byte` encodings in `[0, 2^256)` whose Montgomery `u`-coordinate satisfies `[8]P = O` on Curve25519 (`order = 8*l`) or its quadratic twist (`order = 4*l'`) confirmed: `NewPublicKey` returned `err == nil` on all 14, and `priv.ECDH(pub)` (both random `priv` and clamped zero-input `priv`) returned `"crypto/ecdh: bad X25519 remote ECDH input: low order point"` with zero panics on all 14:
     - `u = 0`: `0000...0000`, `0000...0080`, `edff...ff7f` (`p`), `edff...ffff` (`p + 2^255`)
     - `u = 1` (order 4): `0100...0000`, `0100...0080`, `eeff...ff7f` (`p + 1`), `eeff...ffff` (`p + 1 + 2^255`)
     - `u` order 8 #1: `e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800` and `...b880`
     - `u` order 8 #2: `5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157` and `...11d7`
     - `u = p - 1` (twist order 4): `ecff...ff7f` and `ecff...ffff`
4. **Go 1.27.3 `encoding/base64` Exact Implementation (`/usr/local/go/src/encoding/base64/base64.go:335-399`)**:
   - `decodeQuantum` (`base64.go:335-338`) **silently skips `\n` and `\r` anywhere in the input string** (`if in == '\n' || in == '\r' { j--; continue }`), whereas `' '` and `'\t'` fail with `CorruptInputError`.
   - For a 32-byte payload (`dlen == 3` in final quantum, 43 Base64 data chars = `258` bits for `256` payload bits), `base64.go:389-391` only checks trailing 2-bit canonical zero padding (`dbuf[2] != 0`) when `enc.strict == true` (`.Strict()`). Without `.Strict()`, 4 distinct 43-char/44-char strings differing in the final data character (`'E'`, `'F'`, `'G'`, `'H'`, or `'A='`, `'B='`, `'C='`, `'D='`) decode to the **exact same `[32]byte`**.
5. **Go 1.27.3 `cipher.AEAD` Escape Analysis Benchmark**:
   - Running `testing.AllocsPerRun` on `go1.27.3 linux/amd64` confirmed that passing a stack-local `var localNonce [12]byte` (`localNonce[:]`) to `cipher.AEAD.Seal` escapes to the heap (**`1 alloc/op`** per frame), whereas embedding `nonceScratch [12]byte`, `lenPlain [2]byte`, and `lenCipher [18]byte` inside a directional cipher struct achieves **`0 allocs/op`**.
6. **`sing/common/ntp` Exact Implementation (`sing@v0.9.7/common/ntp/{context.go:10-16, service.go:118-121}`)**:
   - `ntp.TimeFuncFromContext(ctx)` returns `nil` when no `TimeService` is registered in `ctx` (and panics if `ctx == nil`).
   - `(*Service).TimeFunc()` returns `func() time.Time { return time.Now().Add(s.clockOffset) }` (`service.go:120`), where `s.clockOffset` starts at `0` during `NewInbound`/`NewOutbound` and jumps (positively or **negatively**) when `ntp.Service.Start()` completes its first UDP exchange.

---

## 2. Logic Chain

### 2.1 Coexistence & M4 Deletion Safety (`S-4`, `PROJECT.md § Code Layout`)
1. Because M2 cannot modify or delete `cipher.go` (`PROJECT.md:257-264`), `crypto.go` must not redeclare `KeySize`, `SaltSize`, `TagSize`, `NonceSize`, `ErrInvalidTag`, `ErrShortBuffer`, `ErrReplayDetected`, `ErrInvalidHeader`, `GenerateSalt`, or `encodeNonce`.
2. Conversely, because M4 **deletes `cipher.go`**, `crypto.go` and `replay.go` MUST NOT reference any symbol declared in `cipher.go`! Instead, `crypto.go` must define self-contained v2 constants (`ProtocolVersion = 0x02`, `PSKSize = 32`, `SaltLen = 32`, `EPKSize = 32`, `EIHSize = 16`, `AEADNonceSize = 12`, `AEADTagSize = 16`, `ClientPrefixNoEIHSize = 96`, `ClientPrefixEIHSize = 112`, `ServerRespPrefixSize = 84`, `CipherAES256GCM = 0x01`, `CipherChaCha20Poly1305 = 0x02`) and v2 sentinel errors (`ErrEmptySecret`, `ErrWeakSecret`, `ErrZeroKey`, `ErrAmbiguousCredentials`, `ErrInvalidStaticKey`, `ErrLowOrderPoint`, `ErrDuplicateUser`, `ErrAuthenticationFailed`, `ErrUnknownCipherSuite`, `ErrNonceExhausted`).
3. In `replay.go`, M2 should implement `SlidingBloomFilter` (`ErrTimestampOutOfWindow`, `ErrReplaySalt`) while retaining the 30-line `ReplayFilter` / `NewReplayFilter` / `MaxTimeDiffMs` v1 shim at the bottom of `replay.go` until M4 rewrites `inbound.go` and deletes `conn.go`'s v1 `NewServerConn`.
4. In `SelectCipherSuite(cipherOpt string) (uint8, error)`, invalid strings MUST return an error containing `"unsupported aether cipher"` (`E.New("unsupported aether cipher: ", cipherOpt)`) so M1's `cmd/sing-box/cmd_generate_aether_test.go:201` continues passing without modification when M4 wires `SelectCipherSuite` into `NewOutbound`.

### 2.2 Three Inbound Authentication Modes — Zero Timing Leaks & Zero Bloom Pollution (`S-1`, `S-5`, `S-6`)

| Mode | Inbound Config | Client Prefix | `AAD` | Lookup / Scan Strategy | Timing-Leak Countermeasure |
|------|---------------|---------------|-------|------------------------|----------------------------|
| **`AuthModeSingleUser`** | `serverSecret != ""` & `len(Users) == 0` | **`96B`**: `Salt(32) \|\| MaskedEPK(32) \|\| EncFixedHdr(32)` | `prefix[0:64]` (`64B`) | Direct single `uPSK` | If `staticPriv != nil` and `UnmaskEPK` yields a low-order point, run dummy `staticPriv.ECDH(dummyPub)` before returning error so scalar-mult CPU time (`~45 µs`) is constant. |
| **`AuthModeMultiUserEIH`** | `serverSecret != ""` (`iPSK`) & `len(Users) > 0` | **`112B`**: `Salt(32) \|\| MaskedEPK(32) \|\| EIH(16) \|\| EncFixedHdr(32)` | `prefix[0:80]` (`80B`) | `uid = EIH ^ HKDF(iPSK, Salt, "AetherFlow-v2-EIH")[0:16]` → `O(1)` `map[[16]byte]*UserRecord` | **Dummy-User Fallback**: If `uid` is not in `usersByID` (e.g., random probe, or a **revoked user who still knows shared `iPSK`** probing whether other `userID`s exist!), substitute pre-generated CSPRNG `&auth.dummyUser` (`found = false`) and run the exact same `initKey` (+ `staticPriv.ECDH` if configured) + `initAEAD.Open` path before returning `ErrAuthenticationFailed`. Zero `~45 µs` user-existence oracle! |
| **`AuthModeMultiUserDirect`** | `serverSecret == ""` & `len(Users) > 0` | **`96B`**: `Salt(32) \|\| MaskedEPK(32) \|\| EncFixedHdr(32)` | `prefix[0:64]` (`64B`) | Check against `users[0..M-1]` | **Constant-Work Full Scan + Deferred `UnmaskEPK`**: Iterate through **all `M` users without early `break`** so `users[0]` and `users[M-1]` exhibit identical Server Response RTT (preventing user-index timing leak). Furthermore, when `staticPriv == nil`, `initKey` (`HKDF(uPSK_i, ClientSalt, "AetherFlow-v2-Client-Init")`) and `AAD` (`ClientSalt \|\| MaskedClientEPK`) do **NOT** depend on `epk_c`, so skip `UnmaskEPK` inside the loop and unmask `epk_c` only ONCE after the loop for the matched user (`~500 ns/user` = `10 µs` for 20 users)! When `staticPriv != nil`, each iteration runs `UnmaskEPK` + `staticPriv.ECDH` (using `dummyPub` if `epk_c_i` is low-order so non-matching low-order unmasks neither abort the scan nor leak timing). |

#### Mandatory Inbound Anti-Replay Verification Pipeline (Zero Bloom Pollution):
```text
[Step 1] io.ReadFull(conn, prefix[:auth.ClientPrefixSize()])   // Exact 96B or 112B under 6s HandshakeTimeout
   │     (EOF / timeout -> M4 StealthDrain 3s..10s; Bloom untouched)
   ▼
[Step 2] hs, rawFixedHdr, err := auth.OpenClientFixedPrefix(prefix)
   │     Verifies ChaCha20-Poly1305 tag over EncryptedFixedHeader (nonce=0, AAD=64B/80B).
   │     (Tag mismatch / unknown EIH / static ECDH low-order -> StealthDrain; Bloom NEVER touched!)
   ▼
[Step 3] Validate FixedHeader structural invariants BEFORE Bloom:
   │     Version == 0x02, Command ∈ {0x01..0x04}, CipherSuite ∈ {0x01, 0x02},
   │     Reserved == 0x00, 32 <= NoiseLen <= 384, NoiseLen + 7 <= VarHeaderLen <= 16384.
   ▼
[Step 4] replayFilter.ValidateAndRecord(hs.ClientSalt, fixedHdr.TimestampSec):
   │     4a. FIRST check |nowSec - TimestampSec| <= windowSec (overflow-safe uint64 diff!).
   │         If expired -> return ErrTimestampOutOfWindow BEFORE touching Bloom!
   │         (Prevents an attacker replaying 500,000 captured day-old valid-AEAD packets
   │          from polluting the current Bloom generation and causing false-positive DoS!)
   │     4b. THEN lock Bloom mutex, advance generation if needed, probe current & previous
   │         (k = 6 bits); if absent, insert into current; if present, return ErrReplaySalt!
   ▼
[Step 5] io.ReadFull(conn, varCipher[:VarHeaderLen+16]) -> hs.OpenVarHeader(nonce=1, AAD=rawFixedHdr[:])
   ▼
[Step 6] hs.Complete(cipherSuite) -> generates ServerSalt + ek_s, runs ek_s.ECDH(epk_c)
         (rejecting all 14 low-order epk_c values!), derives 5 SessionKeys, seals 84B ServerResponsePrefix!
```

### 2.3 Startup Validation & Runtime Handling of Degenerate / Low-Order X25519 Keys (`S-6`)
1. **Why `NewPublicKey` Alone Is Insufficient at Startup**:
   - Because `ecdh.X25519().NewPublicKey(raw)` returns `err == nil` on all 14 low-order 32-byte points (Observation 1.3), an Outbound configured with `public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="` or `"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="` (`u=1`) would silently pass `NewOutbound` / `sing-box check` and then fail 100% of connections at runtime!
   - **Algebraic Proof for Startup Probe**: Curve25519 has order `8 * l` (`l > 2^252` prime) and its twist has order `4 * l'` (`l' > 2^252` prime). Every clamped X25519 scalar `s = 8 * k` has `2^251 <= k < 2^252 < min(l, l')`, so `gcd(k, l) = gcd(k, l') = 1`. Thus `probePriv.ECDH(pub)` returns an error for **one** clamped private key **if and only if** it returns an error for **every** clamped private key (i.e., `pub` is one of the 14 low-order encodings).
   - Therefore, `ParseX25519PublicKey(b64 string)` MUST run `_, err = startupProbePriv.ECDH(pub)` once at parse time, rejecting all 14 low-order encodings immediately at config load!
2. **`ParseX25519PrivateKey(b64 string)` Clamped-Zero Trap**:
   - `NewPrivateKey` accepts `[32]byte{0}` AND inputs like `[32]byte{1}`, `[32]byte{7}`, or `[32]byte{0, ..., 0, 0x80}` whose 251 variable scalar bits `(raw[0]&248) | raw[1..30] | (raw[31]&63)` are all zero (all clamping to identical deterministic scalar `2^254`). `ParseX25519PrivateKey` MUST reject inputs whose 251 variable bits are all zero (`ErrZeroKey`).
3. **Runtime `UnmaskAndECDH` Nil & Low-Order Safety**:
   - Always nil-check `localPriv != nil` before `localPriv.ECDH(peerPub)` (preventing `ecdh.go:132` nil dereference panic), and wrap `ECDH` errors into `ErrLowOrderPoint` (`errors.Join` or `%w`). Zero panics are possible for any `[32]byte` wire input during `FuzzHandshake`.

### 2.4 Base64 vs Passphrase Disambiguation & `<iPSK>:<uPSK>` Colon-Splitting Edge Cases (`S-6`)

| Edge Case | Input Pattern | Exact Hazard Found | Required Deterministic Rule in `crypto.go` |
|-----------|---------------|--------------------|--------------------------------------------|
| **Embedded `\r`/`\n` in passphrase** | `"PassphraseLine1\nPassphraseLine2Abcdefghij"` (43 Base64 chars + `\n`) | Go `encoding/base64` (`base64.go:335`) silently strips `\r` and `\n` anywhere in input, colliding newline vs non-newline strings into the same 32B Base64 key! | Only attempt Base64 32B fast-path when `!strings.ContainsAny(secret, "\r\n")` AND `(len(secret) == 43 \|\| (len(secret) == 44 && secret[43] == '='))`. (Note: in `ParseX25519{Private,Public}Key`, `strings.TrimSpace` is safe because static keys have no passphrase fallback.) |
| **Non-canonical 2-bit Base64 tail (`43`/`44` chars)** | `"MyCompanyDedicatedLineTransitSecretPass2026"` (`43` chars, `'6'` = index `58`, `58 & 3 != 0`) or `"AAA...B="` | Non-strict `RawStdEncoding` ignores the low 2 bits of char 42 (`base64.go:389`), causing `'4'`, `'5'`, `'6'`, `'7'` to collide 4-to-1 to the **exact same 32B key**! | Use `.Strict()` (`base64.StdEncoding.Strict()`, `RawStdEncoding.Strict()`, `URLEncoding.Strict()`, `RawURLEncoding.Strict()`): 100% of real `EncodeToString(32B)` keys have zero pad bits and pass `.Strict()`, while non-canonical 43-char alphanumeric passphrases fall through to `Argon2id` with zero 4-to-1 collisions! Also explicitly reject `"AAA...B="`/`"C="`/`"D="` if non-strict is ever used (decoded `== [32]byte{}`). |
| **32-char hex string (M1 test)** | `"0123456789abcdef0123456789abcdef"` (`cmd_generate_aether_test.go:195`) | Valid `StdEncoding` Base64, but decodes to `24` bytes (`!= 32`). | `len(decoded) != 32` (and gated out in `O(1)` by `len(s) != 43 && len(s) != 44`), falls through to `len >= 16` -> `Argon2id`. M1 test passes! |
| **44-char ASCII without `'='`** | `"0123456789abcdef0123456789abcdef0123456789ab"` | Valid `StdEncoding` Base64, decodes to `33` bytes (`!= 32`). | `s[43] != '='` skips 32B Base64 path in `O(1)`, runs `Argon2id`. |
| **Mixed `Std` + `URL` alphabet (`+` and `-`)** | `"ab+defghijklmnopqrstuvwxyz0123456789-bcdefA"` | Neither valid `Std` nor valid `URL` Base64. | All 4 `.Strict()` decoders return `CorruptInputError`, falls through to `Argon2id`. |
| **Single-user passphrase with 1 colon & short side** | `"aether:my-long-passphrase-2026"` (`left` len `6 < 16`) or `"my-long-passphrase-2026:v2"` (`right` len `2 < 16`) | Naive `strings.SplitN(s, ":", 2)` would reject `"aether"` as `< 16` chars instead of allowing colon in single-user passphrase! | Per `PROJECT.md:179`, split on `:` ONLY when **both** sides are valid secrets; otherwise treat whole `secret` as single `<uPSK>` (`hasServerPSK = false`). |
| **`<valid_secret>:<all-zero_32B_Base64>`** | `"server-secret-16chars:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="` | If splitter checks `errL == nil && errR == nil` and falls back to `DerivePSK(wholeString)` on ANY error, `ErrZeroKey` gets swallowed and hashes the string as a single passphrase! | Classify each side BEFORE KDF: if either side is a 32B Base64 all-zero key (`ErrZeroKey`), **fail immediately with `ErrZeroKey`** — NEVER swallow `ErrZeroKey` into passphrase fallback! |
| **Multi-colon `<Base64_iPSK>:<passphrase:with:colons>`** | `"K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=:node:sz:prod:secret:2026"` | `strings.Count(s, ":") > 1`, yet Base64 never contains `:`. | Check `idxFirst := strings.IndexByte(s, ':')` (if `s[:idxFirst]` is 32B Base64 and `s[idxFirst+1:]` is valid -> split at `idxFirst`), then `idxLast := strings.LastIndexByte(s, ':')` (if `s[idxLast+1:]` is 32B Base64 and `s[:idxLast]` is valid -> split at `idxLast`). |
| **Multi-colon passphrase(s)** | `"aether:sz:2026:transit"` (0 valid splits) vs `"aaaa-bbbb-cccc-dddd:eeee:ffff-gggg-hhhh-iiii"` (2 valid splits) | `0` valid split indices = unambiguous single passphrase; `>= 2` valid split indices = genuinely ambiguous `<iPSK>:<uPSK>` boundary! | Scan all `:` indices where both sides are valid secrets: if `count == 0`, treat whole string as single `<uPSK>`; if `count == 1`, split at that unique index; if `count >= 2`, return startup error `ErrAmbiguousCredentials` advising 32B Base64 keys (`sing-box generate aether-key`). Inbound NEVER splits `options.Password` or `user.Password` on `:`. |

### 2.5 Anti-Replay `SlidingBloomFilter` Edge Cases (`S-5`, `PROJECT.md § 4 U-13`)
1. **Zero-Allocation Keyed Probe Derivation (`0 B/op, 0 allocs/op`)**:
   - Store `seed [32]byte` initialized from `crypto/rand.Reader` in `NewSlidingBloomFilter`.
   - On each probe: format `var buf [64]byte` (`seed[32] || clientSalt[32]`) on the stack and compute `sum := sha256.Sum256(buf[:])` (`0` heap allocations).
   - Extract `k = 6` uniform 22-bit indices `[0, 4_194_304)` via `idx_i = binary.LittleEndian.Uint32(sum[i*4 : i*4+4]) & 0x3FFFFF` (`i = 0..5`) — **zero modulo bias** since `2^22` divides `2^32`, mapped to `word = idx_i >> 6` (`0..65535`) and `mask = uint64(1) << (idx_i & 63)`.
2. **Overflow-Safe Timestamp Check & Sub-Second Window Guard**:
   - Compute `absDiff` in `uint64`: `if nowSec >= timestampSec { absDiff = uint64(nowSec) - uint64(timestampSec) } else { absDiff = uint64(timestampSec) - uint64(nowSec) }`. Immune to `math.MinInt64` / `math.MaxInt64` signed wraparound across the entire `int64` domain.
   - If `0 < window < time.Second`, clamp `windowSec = 1` so integer second quantization (`now.Unix()`) never rejects 1ms-in-flight handshakes crossing a second boundary. When `window <= 0`, default to `DefaultTimeWindow = 30 * time.Second`.
3. **Lazy Rotation Anchoring, Multi-Window Idle Clear, & NTP Backward-Jump Protection**:
   - Anchor `bf.lastRotation = now` lazily on the **first** `CheckAndAdd` call (`!bf.initialized`), avoiding pre-`Start()` uncalibrated system clock anchoring.
   - Let `rotInterval = 2 * bf.window` (`60s` for `30s` window):
     - If `elapsed := now.Sub(bf.lastRotation); elapsed < 0`: **do NOT wipe** `current` or `previous`; clamp `bf.lastRotation = now` so an NTP backward step (`service.go:120`) never stalls future rotations.
     - Else if `elapsed >= 2*rotInterval`: server was idle across both generations; `clear(bf.current[:]); clear(bf.previous[:]); bf.lastRotation = bf.lastRotation.Add((elapsed / rotInterval) * rotInterval)` (`0` allocations via vectorized `clear`).
     - Else if `elapsed >= rotInterval`: single-generation step; `bf.previous, bf.current = bf.current, bf.previous; clear(bf.current[:]); bf.lastRotation = bf.lastRotation.Add(rotInterval)`.
4. **HKDF `masterSecret` vs Subkey Exact RFC 5869 Contract (`S-3`, `PROJECT.md:199-205`)**:
   - `masterSecret` uses **full Extract + Expand** (`crypto/hkdf.Key(sha256.New, ikmSession, dualSalt[:], "AetherFlow-v2-Session", 32)`).
   - The 5 subkeys (`"AetherFlow-v2-Resp"`, `"AetherFlow-v2-C2S-Header"`, `"AetherFlow-v2-C2S-Payload"`, `"AetherFlow-v2-S2C-Header"`, `"AetherFlow-v2-S2C-Payload"`) use **`HKDF-Expand` ONLY** (`crypto/hkdf.Expand(sha256.New, masterSecret[:], label, 32)` — do **NOT** call `hkdf.Key` / `hkdf.New` a second time, which would run a spurious `HKDF-Extract` with a zero salt!).

### 2.6 Exact Proposed M2 Public API Blueprint for M3 & M4 Consumers

```go
// protocol/aether/crypto.go — Zero-allocation types & helpers for M3 (wire.go, conn.go) and M4 (inbound.go, outbound.go)

const (
	ProtocolVersion        uint8 = 0x02
	PSKSize                      = 32
	SaltLen                      = 32
	EPKSize                      = 32
	EIHSize                      = 16
	AEADNonceSize                = 12
	AEADTagSize                  = 16
	ClientPrefixNoEIHSize        = 96  // 32B Salt + 32B MaskedEPK + 32B EncryptedFixedHeader
	ClientPrefixEIHSize          = 112 // 32B Salt + 32B MaskedEPK + 16B EIH + 32B EncryptedFixedHeader
	ServerRespPrefixSize         = 84  // 32B ServerSalt + 32B MaskedServerEPK + 20B EncryptedRespHeader
	CipherAES256GCM        uint8 = 0x01
	CipherChaCha20Poly1305 uint8 = 0x02
)

type AuthMode uint8
const (
	AuthModeSingleUser AuthMode = iota + 1
	AuthModeMultiUserEIH
	AuthModeMultiUserDirect
)

// Startup Credential & Static Key Helpers (called once in M4 NewInbound / NewOutbound)
func DerivePSK(secret string) ([32]byte, error)
func ParseOutboundCredentials(secret string) (ClientCredentials, error)
func ParseX25519PrivateKey(b64 string) (*ecdh.PrivateKey, error) // rejects zero variable scalar bits
func ParseX25519PublicKey(b64 string) (*ecdh.PublicKey, error)   // probes ECDH to reject all 14 low-order points
func HasAESGCMHardware() bool
func SelectCipherSuite(cipherOpt string) (uint8, error)          // preserves "unsupported aether cipher" error substring
func NewDataAEAD(suite uint8, key [32]byte) (cipher.AEAD, error)

// Low-Level Primitives (KAT-tested & reusable)
func EncodeNonce(seq uint64, dst *[12]byte)
func DeriveUserID(uPSK [32]byte) [16]byte
func MaskEIH(iPSK, clientSalt [32]byte, userID [16]byte) [16]byte // self-inverting XOR (UnmaskEIH = MaskEIH)
func MaskEPK(uPSK, salt, epk [32]byte) [32]byte                   // self-inverting ChaCha20 44B HKDF stream XOR
func GenerateMaskedEPK(uPSK, salt [32]byte) (*ecdh.PrivateKey, [32]byte, [32]byte, error) // returns (priv, rawEPK, maskedEPK, err)
func UnmaskAndECDH(localPriv *ecdh.PrivateKey, uPSK, salt, maskedPeerEPK [32]byte) ([32]byte, error)
func DeriveClientInitKey(uPSK, clientSalt [32]byte, hasStatic bool, ssStatic [32]byte) ([32]byte, error)
func DeriveSessionKeys(uPSK, ssEph [32]byte, hasStatic bool, ssStatic, clientSalt, serverSalt [32]byte) (SessionKeys, error)

// Handshake Coordinators (called in M3 wire.go)
type ClientCredentials struct {
	HasServerPSK bool
	IPSK         [32]byte
	UPSK         [32]byte
	UserID       [16]byte
}
type UserConfig struct {
	Name   string
	Secret string
}
type ServerAuthenticator struct { /* immutable after NewServerAuthenticator; safe for concurrent goroutines */ }
func NewServerAuthenticator(serverSecret string, users []UserConfig, serverPrivateKeyB64 string) (*ServerAuthenticator, error)
func (a *ServerAuthenticator) Mode() AuthMode
func (a *ServerAuthenticator) ClientPrefixSize() int // 96 or 112
func (a *ServerAuthenticator) OpenClientFixedPrefix(prefix []byte) (*ServerHandshakeState, [16]byte, error)

type ServerHandshakeState struct {
	ClientSalt [32]byte
	UserName   string
	UserIndex  int // -1 in SingleUser, 0..N-1 in MultiUserEIH / MultiUserDirect
	// internal: uPSK, rawClientEPK, hasStatic, ssStatic, fixedHeader[16], initAEAD
}
func (s *ServerHandshakeState) OpenVarHeader(dst, ciphertext []byte) ([]byte, error)
func (s *ServerHandshakeState) Complete(cipherSuite uint8, respPlain [4]byte) (respPrefix [84]byte, send *DirectionalCipher, recv *DirectionalCipher, err error)

// Zero-Allocation Data-Plane Directional Cipher (0 B/op, 0 allocs/op per frame in M3 conn.go)
// Owned exclusively by writer (under writeMu) or reader (under readMu).
type DirectionalCipher struct {
	headerAEAD   cipher.AEAD
	payloadAEAD  cipher.AEAD
	seq          uint64
	nonceScratch [12]byte
	lenPlain     [2]byte
	lenCipher    [18]byte
}
func NewDirectionalCipher(suite uint8, headerKey, payloadKey [32]byte) (*DirectionalCipher, error)
func (dc *DirectionalCipher) SealFrame(dst []byte, bodyPlain []byte) ([]byte, error) // writes 18B enc len + enc body, increments seq
func (dc *DirectionalCipher) OpenLengthHeader(encHeader18 []byte) (uint16, error)    // decrypts 18B len header at current seq
func (dc *DirectionalCipher) OpenPayloadBody(dst, encBody []byte) ([]byte, error)    // decrypts body at current seq & increments seq
```

```go
// protocol/aether/replay.go — Zero-allocation anti-replay & NTP time helpers for M3 & M4
const DefaultTimeWindow = 30 * time.Second

func ResolveTimeFunc(ctx context.Context) func() time.Time // nil-safe ntp.TimeFuncFromContext(ctx) -> time.Now
func ValidateTimestamp(timestampSec int64, now time.Time, window time.Duration) error

type SlidingBloomFilter struct { /* mu sync.Mutex, seed [32]byte, current/previous *[65536]uint64, window, timeFunc */ }
func NewSlidingBloomFilter(window time.Duration, timeFunc func() time.Time) (*SlidingBloomFilter, error)
func (bf *SlidingBloomFilter) CheckAndAdd(clientSalt [32]byte, now time.Time) bool // 0 allocs/op
func (bf *SlidingBloomFilter) ValidateAndRecord(clientSalt [32]byte, timestampSec int64) error // checks timestamp BEFORE Bloom!
```

### 2.7 Statistical Randomness Verification Test Design for `crypto_test.go` (`N = 2000`)
To prove Curve25519 MSB bias (`rawEPK[31] & 0x80 == 0`) is 100% eliminated across both `MaskedClientEPK` and `MaskedServerEPK` with **zero CI flakiness**:
1. **Sample Generation (`N = 2000` iterations)**:
   - On each iteration `i = 0..1999`, generate fresh CSPRNG `clientSalt [32]byte` and `serverSalt [32]byte`, call `GenerateMaskedEPK(uPSK, clientSalt)` and `GenerateMaskedEPK(uPSK, serverSalt)`, and also verify round-trip `MaskEPK(uPSK, salt, maskedEPK) == rawEPK`.
2. **Positive Control (Proving Unmasked Bias Exists & Is Caught)**:
   - Assert `unmaskedMSBOnes == 0` across all `2000` `rawClientEPK` and all `2000` `rawServerEPK` (`rawEPK[31] & 0x80 == 0` 100% of the time).
   - Compute byte-31 Pearson `χ²` on `rawClientEPK[31]` (`df = 255`, `E = 2000.0 / 256.0 = 7.8125`): because bins `128..255` are all `0`, theoretical `E[χ²_31] ≈ 2127.0`; assert `unmaskedChi2[31] > 1800.0`, proving the test statistic deterministically catches Curve25519 MSB bias by `> 70 σ`.
3. **Bit-255 (`epk[31] & 0x80`) Binomial Frequency Test (`N = 2000`)**:
   - Under `H_0: Binomial(2000, 0.5)`, `μ = 1000`, `σ = sqrt(500) ≈ 22.3607`.
   - Assert **`888 <= msbOnes <= 1112`** (`|X - 1000| <= 5.0 * σ`, frequency `∈ [0.444, 0.556]`) independently for both `MaskedClientEPK` and `MaskedServerEPK`.
   - Two-sided false-positive (flake) probability: `2 * Φ(-5.0) = 5.73 × 10^-7` (`< 1` in `1.7 million` runs), while unmasked X25519 sits at `X = 0` (`-44.72 σ`, detection power `100%`).
   - Additionally check all `256` bit positions `b ∈ 0..255` (`masked[b/8] & (1 << (b%8))`) fall within `[870, 1130]` (`±5.81 σ`, `512`-bit FWER `< 3.2 × 10^-6`), catching any partial clamping leak on bits `0, 1, 2, 254, 255`.
4. **Per-Byte Chi-Squared (`χ²`) Uniformity Test (`N = 2000`, `df = 255`, 64 Byte Columns FWER-Calibrated)**:
   - For each byte index `j ∈ 0..31` (32 columns for `MaskedClientEPK` + 32 columns for `MaskedServerEPK` = **64 simultaneous hypothesis tests**), tally `counts[j][0..255]` and compute:
     $$\chi^2_j = \sum_{v=0}^{255} \frac{(\text{counts}[j][v] - 7.8125)^2}{7.8125}, \quad E = \frac{2000}{256} = 7.8125, \quad \text{df} = 255$$
   - **Critical CI Anti-Flake Calibration**: Using a naive `p = 0.001` (`z = 3.0`, `χ² <= 328`) across 64 byte columns causes an **8.64% suite flake rate**! By Wilson-Hilferty transformation at `z ≈ ±5.65`, assert **`145.0 <= χ²_j <= 405.0`** for every byte `j ∈ 0..31`:
     - **64-column Family-Wise Error Rate (FWER)**: `< 1.0 × 10^-6` (fewer than 1 false failure in 1,000,000 test runs).
     - **Detection Power**: Any single stuck/biased bit doubles half the bins and zeros the other half (`χ² >= 2000 >> 405`, `100%` caught); any 15% bit bias shifts `χ²` above `435`.
   - Also compute the **pooled 64,000-byte `χ²_pooled`** (`32 * 2000 = 64,000` bytes, `E = 250.0`, `df = 255`) and assert **`150.0 <= χ²_pooled <= 400.0`** (`p < 2 × 10^-8`), catching global byte-distribution skew down to `< 0.8%`.

---

## 3. Caveats

1. **`SlidingBloomFilter` Single-Window 1M Saturation vs Multi-Window 1M Throughput (`replay_test.go`)**:
   - With `m = 4,194,304` bits per generation and `k = 6`, inserting `1,000,000` entries across `10` rotated windows (`100,000` conn/min) maintains a tiny `0.0011%` false-positive rate (`p_2(100k) = 1.12 × 10^-5`). If all `1,000,000` entries are inserted into a **single unrotated** `60s` window (`6,000,000` bit probes in `4,194,304` bits), the theoretical single-window false-positive rate is `(1 - e^-1.4305)^6 = 19.4%` — while the **false-negative rate remains strictly `0.000%`** (`100%` of the `1,000,000` salts are still caught as replays, unlike v1 `ReplayFilter` which wiped the entire map 100 times!). `replay_test.go` should test `0%` false-negative replay catch on 1M entries AND `< 0.01%` false-positive rate at `100,000` entries/window.
2. **Go 1.26+ `ecdh.Curve.GenerateKey(rand)` Ignores Custom `io.Reader`**:
   - Per `/usr/local/go/src/crypto/ecdh/ecdh.go:21-24`, `ecdh.X25519().GenerateKey(r)` ignores `r` in Go 1.26+ unless `testing/cryptotest.SetGlobalRandom` is used. Therefore, deterministic KAT tests in `crypto_test.go` should construct fixed keys via `ecdh.X25519().NewPrivateKey(fixedScalar32)` + `MaskEPK`, while statistical tests use live CSPRNG with the `FWER < 10^-6` thresholds derived in § 2.7.

---

## 4. Conclusion

To make M2 (`crypto.go`, `replay.go`) drop seamlessly into M3 (`wire.go`, `conn.go`) and M4 (`inbound.go`, `outbound.go`) with zero security gaps, zero steady-state allocations, and zero test regressions:
1. **Expose `ServerAuthenticator`, `ClientCredentials`, `ServerHandshakeState`, and `DirectionalCipher` in `crypto.go`** without referencing or colliding with `cipher.go` symbols, and preserve `"unsupported aether cipher"` in `SelectCipherSuite`.
2. **Eliminate all timing side-channels and Bloom pollution across all 3 auth modes**: use dummy-user fallback on `MultiUserEIH` lookup miss, full non-breaking scan (deferring `UnmaskEPK` when `staticPriv == nil`) on `MultiUserDirect`, and enforce `OpenClientFixedPrefix` (AEAD tag) → `FixedHeader` structural check → `ValidateTimestamp` → `SlidingBloomFilter.CheckAndAdd` ordering.
3. **Reject all degenerate keys at both startup and runtime**: run a startup `ECDH` probe inside `ParseX25519PublicKey` to reject all 14 low-order Curve25519 encodings, reject zero variable scalar bits in `ParseX25519PrivateKey`, guard `localPriv != nil` in `UnmaskAndECDH`, use `.Strict()` + `!strings.ContainsAny(s, "\r\n")` in 32B Base64 detection, and never swallow `ErrZeroKey` into passphrase fallback during `<iPSK>:<uPSK>` colon splitting.
4. **Embed `[12]byte`/`[2]byte`/`[18]byte` scratch buffers in `DirectionalCipher`** and use `[64]byte` stack `sha256.Sum256` + lazy/backward-safe rotation in `SlidingBloomFilter` to guarantee `0 allocs/op` on both frame encryption/decryption and replay checks.
5. **Implement the FWER-calibrated `N = 2000` statistical randomness suite in `crypto_test.go`** (`888 <= msbOnes <= 1112`, per-byte `145.0 <= χ²_j <= 405.0`, pooled `150.0 <= χ²_pooled <= 400.0`, plus positive control `unmaskedMSBOnes == 0` and `unmaskedChi2[31] > 1800.0`).

---

## 5. Verification Method

1. **Repository Cleanliness & Source Verification**:
   - Inspect Go 1.27.3 stdlib contracts directly:
     - `/usr/local/go/src/crypto/ecdh/x25519.go:49-89` (`NewPublicKey` length-only check vs `ecdh` `isZero(out)` low-order rejection)
     - `/usr/local/go/src/encoding/base64/base64.go:335-399` (`\r\n` skipping & `.Strict()` trailing-bit check)
     - `/home/antigravity/go/pkg/mod/github.com/sagernet/sing@v0.9.7-0.20261023115459-5dc452e537bf/common/ntp/{context.go:10-16,service.go:118-121}`
   - Confirm clean repo state: `git status --short --branch` in `.` outputs only `## dev/aether-v2`.
2. **M2 Build, Race, Allocation & Statistical Test Commands (once M2 worker implements `crypto.go` & `replay.go`)**:
   ```bash
   GOPROXY=direct GOSUMDB=off go test -v -race -count=1 ./protocol/aether/... ./cmd/sing-box/...
   GOPROXY=direct GOSUMDB=off go test -run='^$' -bench='Benchmark(DirectionalCipher|SlidingBloomFilter)' -benchmem ./protocol/aether/...
   ```
   - **Invalidation Conditions**: Any `allocs/op > 0` on `BenchmarkDirectionalCipher` or `BenchmarkSlidingBloomFilter`; any of the 14 low-order X25519 encodings accepted by `ParseX25519PublicKey` or `UnmaskAndECDH`; any Bloom bit set when `EncryptedFixedHeader` tag or `TimestampSec` fails; or `cmd/sing-box` `TestAetherConfigCipherAndSecretValidation` failing.
