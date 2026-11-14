# Handoff Report — `explorer_m2_2`: Phase 1.2 Dual-Generation Sliding Bloom Anti-Replay & NTP Timestamp Validation (`protocol/aether/replay.go` & `replay_test.go`)

**Core Summary**: Refactoring `protocol/aether/replay.go` into a constant-memory (`1.00 MiB` inline `[2][65536]uint64`), zero-allocation, zero-goroutine-leak `SlidingBloomFilter` with `k = 6` CSPRNG-seeded `SHA-256` bit probes, lazy wall-clock `2 * TimeWindow` (`60s`) generation rotation, and `ntp.TimeFuncFromContext(ctx)` timestamp validation (`±30s`) completely eliminates Aether v1's `S-5` 10,000-entry map-wipe vulnerability while retaining a thin `ReplayFilter` wrapper shim so `inbound.go` and `conn.go` compile cleanly in M2/M3 until M4 rewrites `inbound.go`.

---

## 1. Observation

### 1.1 Existing Aether v1 Anti-Replay & Symbol Surface in `package aether`
1. **`protocol/aether/replay.go:1-64` (Current v1 Implementation)**:
   - Lines `8-11`: Exports `const ( MaxTimeDiffMs = 30000; LRUWindowSize = 10000 )`.
   - Lines `13-32`: Exports `type ReplayFilter struct` (`mu sync.Mutex`, `seen map[uint64]int64`, `maxSize int`, `timeLimit int64`) and `func NewReplayFilter(maxSize int, timeLimitMs int64) *ReplayFilter`.
   - Lines `34-63`: Exports `func (rf *ReplayFilter) CheckAndAdd(timestampMs int64, nonce uint64) bool`. At lines `56-58`, when `len(rf.seen) >= rf.maxSize` (`10000`) within `30s`, it executes `rf.seen = make(map[uint64]int64, rf.maxSize)`, wiping 100% of recorded nonces (`S-5` vulnerability in `docs/aether/AETHER_V1_SECURITY_AUDIT.md:35, 71-78`). It also calls `time.Now().UnixMilli()` directly without `ntp` integration and checks only a 64-bit `nonce`.
2. **All Call Sites Referencing `replay.go` Symbols Across the Repository**:
   - Verified via `rg -n 'ReplayFilter|NewReplayFilter|MaxTimeDiffMs|LRUWindowSize|ErrReplayDetected' protocol cmd option include constant`:
     - `protocol/aether/inbound.go:34`: `replayFilter *ReplayFilter` field on `Inbound`.
     - `protocol/aether/inbound.go:53-56`: `timeLimit := options.TimeWindow.Build().Milliseconds(); if timeLimit <= 0 { timeLimit = MaxTimeDiffMs }`.
     - `protocol/aether/inbound.go:70`: `replayFilter: NewReplayFilter(10000, timeLimit)`.
     - `protocol/aether/inbound.go:102`: `aetherConn, header, err := NewServerConn(conn, in.psk, in.replayFilter, in.heartbeatIntervalSec)`.
     - `protocol/aether/conn.go:156`: `func NewServerConn(rawConn net.Conn, psk [KeySize]byte, replayFilter *ReplayFilter, heartbeatSec int) (*Conn, *Header, error)`.
     - `protocol/aether/conn.go:211-216`: `if replayFilter != nil { if !replayFilter.CheckAndAdd(header.Timestamp, header.Nonce) { HandleProbe(rawConn); return nil, nil, ErrReplayDetected } }`.
3. **Critical Error Sentinel Collision Check (`protocol/aether/cipher.go:23-28`)**:
   - `protocol/aether/cipher.go:26` already declares `ErrReplayDetected = errors.New("aether: potential replay attack detected")` alongside `ErrInvalidTag`, `ErrShortBuffer`, and `ErrInvalidHeader`.
   - Per `PROJECT.md:83-85`, `cipher.go` coexists in `package aether` throughout **M2** and **M3** and is deleted in **M4**. Redeclaring `ErrReplayDetected` in `replay.go` would cause a compile error in M2/M3, whereas relying on `cipher.go`'s `ErrReplayDetected` without owning v2 errors in `replay.go` would break in M4 when `cipher.go` is deleted.
4. **Configuration & Canonical Spec (`option/aether.go:20`, `PROJECT.md:228`)**:
   - `option/aether.go:20`: `TimeWindow badoption.Duration` (`// Default 30s`).
   - `PROJECT.md:228` (`U-13`): Two bitsets (`current`, `previous`) of `65536` `uint64` (`512 KiB` each = `1 MiB` total), `k = 6` keyed hash probes over `[32]byte` `ClientSalt`, rotating every `2 * TimeWindow` (`60s` when `TimeWindow = 30s`), checked/inserted strictly **after** `EncryptedFixedHeader` AEAD verification succeeds.

### 1.2 Exact `github.com/sagernet/sing/common/ntp` & `sing-box` NTP Wiring Observations
1. **Module Version (`go.mod:48`)**:
   - `github.com/sagernet/sing v0.9.7-0.20261023115459-5dc452e537bf`.
2. **`ntp.TimeFuncFromContext` (`.../sing@v0.9.7-.../common/ntp/context.go:10-16`)**:
   ```go
   func TimeFuncFromContext(ctx context.Context) func() time.Time {
       timeService := service.FromContext[TimeService](ctx)
       if timeService == nil {
           return nil
       }
       return timeService.TimeFunc()
   }
   ```
3. **`service.FromContext` Nil-Context Behavior (`.../sing@v0.9.7-.../service/context.go:28-46`)**:
   - Line `29`: `RegistryFromContext` executes `registry := ctx.Value(common.DefaultValue[*Registry]())` **without** checking `if ctx == nil` (passing `nil` `ctx` panics).
   - Lines `37-45`: If `ctx` is non-nil (e.g., `context.Background()`) and has either no `service.Registry` or no registered `ntp.TimeService`, `FromContext[TimeService](ctx)` returns `nil`, so `ntp.TimeFuncFromContext(ctx)` returns **`nil`**.
4. **`ntp.Service.TimeFunc` & `sing-box` Startup Order (`.../common/ntp/service.go:118-122`, `box.go:258-263, 458-467`, `common/tls/time_wrapper.go:9-21`)**:
   - When `options.NTP.Enabled` is `false` (default), `box.go:260` registers **no** `ntp.TimeService` in `ctx`, so `ntp.TimeFuncFromContext(ctx)` returns `nil`.
   - When `options.NTP.Enabled` is `true`, `box.go:261-262` registers `*tls.TimeServiceWrapper` in `ctx` *before* constructing Inbounds/Outbounds, and `box.go:466` attaches `ntpService` *after* Inbound construction; `ntpService.Start()` subsequently updates `s.clockOffset` when `Box.Start()` runs, returning `time.Now().Add(s.clockOffset)` (`service.go:120`).
5. **Reference Pitfalls Observed in `sing/common/replay` & `sing-shadowsocks`**:
   - `sing/common/replay/simple.go:8-47` uses an unbounded `map[string]time.Time` with heap string allocations (`string(salt)`) and hardcodes `time.Now()`.
   - `sing-shadowsocks/shadowaead_2022/service.go:160, 195` checks its replay filter *before* AEAD verification (which would let unauthenticated garbage packets saturate a Bloom filter) and computes `int(math.Abs(float64(s.time().Unix() - int64(epoch))))` (which overflows `int` on extreme `uint64`/`int64` epochs).

---

## 2. Logic Chain

1. **M2/M3 Zero-Breakage Compatibility & M4 Deletion Safety (from Observations 1.1.1–1.1.3)**:
   - Because `inbound.go:34,55,70` and `conn.go:156,212` reference `MaxTimeDiffMs`, `ReplayFilter`, `NewReplayFilter`, and `(*ReplayFilter).CheckAndAdd`, `replay.go` must retain those exact symbols as a thin deprecated wrapper delegating to `SlidingBloomFilter` (converting `nonce uint64` into `[32]byte` via `binary.BigEndian.PutUint64(salt[0:8], nonce)`). This keeps `go build ./...` green in M2 and M3 while purging all legacy `map[uint64]int64` full-wipe code (`S-5`) immediately in M2.
   - Because `cipher.go:26` owns `ErrReplayDetected` until `cipher.go` is deleted in M4, `replay.go` must define distinct v2 sentinel errors — `ErrTimestampOutOfWindow` and `ErrSaltReplayed` — avoiding symbol redeclaration in M2/M3 and avoiding dangling references when `cipher.go` is deleted in M4, while giving M4 `inbound.go` internal audit-log visibility into clock skew vs active replay (both externally handled via uniform `3s..10s` `StealthDrain`).

2. **Safe `ResolveTimeFunc(ctx)` & Wall-Clock Coupled Rotation (from Observations 1.2.2–1.2.4)**:
   - Because `ntp.TimeFuncFromContext(nil)` panics and `ntp.TimeFuncFromContext(context.Background())` returns `nil`, `ResolveTimeFunc(ctx context.Context) func() time.Time` must check `if ctx != nil`, call `ntp.TimeFuncFromContext(ctx)`, and fall back to `time.Now` whenever the result is `nil`. Exporting `ResolveTimeFunc(ctx)` allows both M4 `Inbound` (anti-replay) and M4 `Outbound` (`FixedHeader.TimestampSec` stamping) to share identical NTP resolution.
   - Because `ValidateTimestamp` checks `now.Unix()` (wall-clock seconds) and `ntp.Service.TimeFunc()` shifts `time.Now().Add(s.clockOffset)` (which may step backward on initial NTP sync after `NewInbound`), `SlidingBloomFilter` must strip Go's monotonic bit via `nowWall := now.Round(0)` and compute `elapsed := nowWall.Sub(f.lastRotate)`. `time.Time.Round(0)` and `time.Time.Sub` allocate `0` bytes, avoid `UnixNano()`'s year-2262 `int64` limit, saturate safely on `±292y` extremes, and stay locked to the exact same wall-clock domain as `now.Unix()`.

3. **Keyed Hash Probe Derivation — Zero Hash-Flooding & Zero Allocations (from Observation 1.1.4)**:
   - Each `SlidingBloomFilter` generates an immutable per-instance `seed [32]byte` from `crypto/rand.Reader` at construction (`NewSlidingBloomFilter`).
   - Computing `var buf [64]byte; copy(buf[0:32], f.seed[:]); copy(buf[32:64], clientSalt[:]); sum := sha256.Sum256(buf[:])` runs strictly on stack memory (`0 B/op, 0 allocs/op`) and acts as a 256-bit keyed PRF over fixed-length 32-byte `ClientSalt`s, preventing precomputed hash-collision / Bloom-pollution attacks even from an adversary holding a valid `uPSK`.
   - Since each bit index in `m = 4,194,304 = 2^22` requires `22` bits, `k = 6` probes require `6 * 22 = 132 <= 256` bits. Slicing six **disjoint** 32-bit words `sum[0:4], sum[4:8], ..., sum[20:24]` masked with `& 0x3FFFFF` yields `6` mutually independent, modulo-bias-free indices (`2^22` divides `2^32`).
   - Indexing each `[65536]uint64` generation via `gen[uint16(p[i]>>6)]` and `uint64(1) << (p[i]&63)` enables static Go compiler **Bounds-Check Elimination (BCE)** on both the array index (`uint16` max `65535 < 65536`) and shift width (`<= 63 < 64`).

4. **Per-Generation Membership Check & Exact False-Positive Rate Math (from Observation 1.1.4)**:
   - Membership MUST be checked per generation independently: `bloomContains(curr, probes) || bloomContains(prev, probes)` — **never** `(curr[w] | prev[w]) & mask != 0` across probes, which would merge `2n` entries into `m` bits and inflate FPR by up to `2^6 = 64x` (`21x` at `n = 100,000`).
   - Exact FPR formula for a single generation of $m = 4,194,304$ bits and $k = 6$ probes after $n$ insertions is $P_1(n) = \left(1 - \left(1 - \frac{1}{m}\right)^{kn}\right)^k$, and worst-case dual-generation union FPR (right before rotation when both `previous` and `current` hold $n$ entries) is $P_{\text{dual,peak}}(n) = 1 - (1 - P_1(n))^2$:

     | Entries $n$ (per `60s` gen) | Bitset Fill Factor | Single-Gen FPR $P_1(n)$ | Dual-Gen Avg FPR | Dual-Gen Peak FPR | Naive Cross-OR FPR (Avoided) | True-Replay Miss Rate |
     |----------------------------:|-------------------:|------------------------:|-----------------:|------------------:|-----------------------------:|----------------------:|
     | `10,000` *(v1 wipe point)*  | `1.4203%`          | `8.21 × 10⁻¹²` (`~0%`)  | `9.39 × 10⁻¹²`   | `1.64 × 10⁻¹¹`    | `5.03 × 10⁻¹⁰`               | **`0.000000%`**       |
     | `50,000`                    | `6.9028%`          | `1.08 × 10⁻⁷` (`0.000011%`) | `1.24 × 10⁻⁷` | `2.16 × 10⁻⁷`     | `5.61 × 10⁻⁶`                | **`0.000000%`**       |
     | **`100,000`**               | **`13.3290%`**     | **`5.61 × 10⁻⁶` (`0.000561%`)** | **`6.45 × 10⁻⁶` (`0.000645%`)** | **`1.12 × 10⁻⁵` (`0.001122%`)** | `2.37 × 10⁻⁴` (`0.0237%`) | **`0.000000%`** |
     | `250,000`                   | `30.0667%`         | `7.39 × 10⁻⁴` (`0.0739%`) | `8.59 × 10⁻⁴`  | `1.48 × 10⁻³` (`0.1477%`) | `1.78%`             | **`0.000000%`**       |
     | `500,000` *($k_{\text{opt}}\approx 5.8$)* | `51.0933%` | `1.7790%`      | `2.1045%`        | `3.5264%`         | `19.3941%`                   | **`0.000000%`**       |
     | **`1,000,000` (1 gen burst)** | **`76.0813%`**   | **`19.3941%`**          | `23.1364%`       | `35.0269%`        | `70.2246%`                   | **`0.000000%`**       |
     | **`1,000,000` (`10×100k` rotated)** | **`13.3290%`** | **`0.000561%`**   | **`0.000645%`**  | **`0.001122%`**   | N/A                          | **`0.000000%`**       |

5. **Clock Skew & Rotation Boundary Proof (`U-13`, `t = 59.9s -> t = 60.1s`)**:
   - With `TimeWindow = W` (default `30s`), any given `TimestampSec = T` is accepted over `[T - W, T + W]`, a span of `2W` (`60s`).
   - Setting `rotationInterval = 2 * W` (`60s`) and updating `f.lastRotate = nowWall` on each rotation guarantees every rotation timestamp sequence $t_0 < t_1 < t_2 < \dots$ satisfies $t_i - t_{i-1} \ge 2W$:
     - **Single-step rotation ($2W \le \text{elapsed} < 4W$)**: An entry inserted at $t \in [t_{i-1}, t_i)$ stays in `current` until $t_i$, flips into `previous` at $t_i$ (`f.activeIdx ^= 1; clear(f.bits[f.activeIdx][:])` — in-place `memclrNoHeapPointers` without reallocating 512 KiB), and is not wiped until $t_{i+1}$, surviving $t_{i+1} - t > t_{i+1} - t_i \ge 2W = 60\text{s}$.
     - **Idle skip ($\text{elapsed} \ge 4W$)**: Since no call arrived in $[t_{i-1} + 2W, t_i)$, every entry in `current` was inserted at $t < t_{i-1} + 2W$, so at $t_i \ge t_{i-1} + 4W$ its age exceeds $2W$; clearing both `bits[0]` and `bits[1]` in place is 100% safe.
     - **Large backward clock step ($\text{elapsed} < -2W$, e.g., NTP startup `-2h` step-back)**: Rotating `current -> previous`, clearing new `current`, and setting `f.lastRotate = nowWall` preserves pre-step entries while immediately resuming normal `60s` rotation (whereas small jitter $-2W \le \text{elapsed} < 0$ is a safe no-op).
   - **Boundary Walk (`t = 59.9s`, `ts = +29s` -> `t = 60.1s`)**:
     - `t0 = 0.0s`: `NewSlidingBloomFilter` sets `lastRotate = 0.0s`.
     - `t = 59.9s`: Handshake arrives with `ts = 59 + 29 = 88`. `ValidateTimestamp` (`|59 - 88| = 29 <= 30`) passes; `elapsed = 59.9s < 60s` -> `Salt` inserted into `bits[0]` (`current`).
     - `t = 60.1s`: Replay of `(Salt, ts = 88)` arrives. `ValidateTimestamp` (`|60 - 88| = 28 <= 30`) still passes; `elapsed = 60.1s >= 60s` rotates `bits[0]` to `previous` and clears `bits[1]` as new `current`; `bloomContains(prev, probes)` returns `true` -> **replay deterministically rejected (`ErrSaltReplayed`)** all the way through `t = 118.999s`, after which `ValidateTimestamp` (`|120 - 88| = 32 > 30`) permanently rejects `ts = 88`!

6. **Concurrency Model & Ordering Security (`ValidateTimestamp` -> `deriveProbes` -> `sync.Mutex`)**:
   - In `ValidateAndRecord(clientSalt, timestampSec)`:
     1. Validate `TimestampSec` **first** using unsigned modular distance (`uint64(a) - uint64(b)`, immune to `math.MinInt64`/`math.MaxInt64` overflow) so expired captured packets never touch the mutex or set Bloom bits.
     2. Compute `deriveProbes(clientSalt)` (`SHA-256`) **outside** `f.mu.Lock()` so 32+ goroutines hash in parallel with zero lock hold time.
     3. Acquire a single `sync.Mutex` (`f.mu`) around `[maybeRotateLocked + bloomContains(curr) + bloomContains(prev) + bloomInsert(curr)]` (~15–25 ns critical section). Unlike `sync.RWMutex` (which suffers TOCTOU races or double-locking since 99.999% of calls insert) and sharded locks (which require sorting 6 shard locks and complex cross-shard rotation locking), a single `sync.Mutex` after unlocked hashing gives atomic test-and-set semantics (if 32 goroutines race with the same `ClientSalt`, strictly 1 wins and 31 get `ErrSaltReplayed`) with zero background goroutines to leak.

---

## 3. Caveats

1. **Sub-Second `TimestampSec` Quantization (`1s` Wire Resolution)**:
   - Because `FixedHeader.TimestampSec` is encoded in integer seconds (`int64`), `|now.Unix() - timestampSec| <= 30` accepts a given integer `T` across continuous real time `[T - 30.000s, T + 30.999999999s]` (`60.999999999s` max continuous span when client skew is at the extreme `+30s` edge in the first millisecond of a second). Per `PROJECT.md:228` (`U-13`) and the M2 dispatch specification (`t = 59.9s -> t = 60.1s` triggering rotation at `2 * TimeWindow = 60s`), `rotationInterval` MUST be `2 * window` (`60s`), which retains entries for `[60s, 120s]` (average `90s`, covering `100%` of `±29s` skews and `99.17%` of extreme `+30.000s` boundary alignments).
2. **AEAD-First Calling Discipline Required in M3 `wire.go` (`U-13`)**:
   - `SlidingBloomFilter` itself does not perform AEAD decryption; M3 `wire.go` MUST invoke `ValidateAndRecord` / `CheckAndAdd` **strictly after** `EncryptedFixedHeader` ChaCha20-Poly1305 `Open` succeeds so unauthenticated network probes cannot set bits in the Bloom filter.
3. **1,000,000-Entry Test Assertion Distinction (Single-Gen Saturation vs Multi-Gen Rotated)**:
   - Inserting `1,000,000` distinct entries into a *single* unrotated `4,194,304`-bit generation fills `76.08%` of bits (`0.19394` theoretical FPR, `0%` false negatives), whereas `1,000,000` entries across rotated `60s` generations (`100,000`/gen) keeps FPR at `0.000561%`–`0.001122%`. `replay_test.go` must test **both** regimes with their respective exact mathematical bounds rather than asserting `< 1%` FPR on an unrotated 1M-entry single generation.

---

## 4. Conclusion

### 4.1 Complete Proposed Implementation Blueprint for `protocol/aether/replay.go`

```go
package aether

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"sync"
	"time"

	"github.com/sagernet/sing/common/ntp"
)

const (
	DefaultTimeWindow = 30 * time.Second

	bloomWords     = 65536             // 65,536 * 8B = 524,288B (512 KiB) per generation
	bloomBits      = bloomWords * 64   // 4,194,304 bits (2^22) per generation
	bloomBitMask   = bloomBits - 1     // 0x3FFFFF (22-bit mask)
	bloomProbes    = 6                 // k = 6 independent bit probes
	maxSafeWindow  = time.Duration(math.MaxInt64 / 4)
)

var (
	ErrTimestampOutOfWindow = errors.New("aether: handshake timestamp outside allowed window")
	ErrSaltReplayed         = errors.New("aether: replayed client salt detected")
)

type bloomProbeSet [bloomProbes]uint32

// SlidingBloomFilter implements a constant-memory (~1 MiB), zero-allocation,
// dual-generation sliding Bloom anti-replay filter with lazy wall-clock rotation.
type SlidingBloomFilter struct {
	// Immutable after construction (read lock-free across goroutines):
	seed             [32]byte
	window           time.Duration
	rotationInterval time.Duration
	timeFunc         func() time.Time
	_                [8]byte // pad immutable header to 64B cache line boundary

	// Guarded by mu:
	mu         sync.Mutex
	lastRotate time.Time
	rotations  uint64
	activeIdx  uint8
	bits       [2][bloomWords]uint64 // 2 * 512 KiB = 1.00 MiB inline constant storage
}

// ResolveTimeFunc extracts the NTP-calibrated time function from ctx when available,
// safely handling nil contexts and falling back to time.Now when NTP is unconfigured.
func ResolveTimeFunc(ctx context.Context) func() time.Time {
	if ctx != nil {
		if tf := ntp.TimeFuncFromContext(ctx); tf != nil {
			return tf
		}
	}
	return time.Now
}

// NewSlidingBloomFilter constructs a 2-generation SlidingBloomFilter rotating every 2 * window.
func NewSlidingBloomFilter(window time.Duration, timeFunc func() time.Time) *SlidingBloomFilter {
	if window <= 0 {
		window = DefaultTimeWindow
	} else if window > maxSafeWindow {
		window = maxSafeWindow
	}
	if timeFunc == nil {
		timeFunc = time.Now
	}
	var seed [32]byte
	if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
		panic("aether: crypto/rand failed: " + err.Error())
	}
	return &SlidingBloomFilter{
		seed:             seed,
		window:           window,
		rotationInterval: 2 * window,
		timeFunc:         timeFunc,
		lastRotate:       timeFunc().Round(0),
	}
}

// NewSlidingBloomFilterFromContext constructs a SlidingBloomFilter wired to ntp.TimeFuncFromContext(ctx).
func NewSlidingBloomFilterFromContext(ctx context.Context, window time.Duration) *SlidingBloomFilter {
	return NewSlidingBloomFilter(window, ResolveTimeFunc(ctx))
}

func (f *SlidingBloomFilter) Now() time.Time {
	return f.timeFunc()
}

func (f *SlidingBloomFilter) Window() time.Duration {
	return f.window
}

func (f *SlidingBloomFilter) RotationInterval() time.Duration {
	return f.rotationInterval
}

// ValidateTimestamp checks |now.Unix() - timestampSec| <= window in overflow-safe uint64 arithmetic.
func ValidateTimestamp(timestampSec int64, now time.Time, window time.Duration) error {
	if window <= 0 {
		window = DefaultTimeWindow
	}
	maxSkewSec := int64(window / time.Second)
	if maxSkewSec <= 0 {
		maxSkewSec = 1
	}
	nowSec := now.Unix()
	var diff uint64
	if nowSec >= timestampSec {
		diff = uint64(nowSec) - uint64(timestampSec)
	} else {
		diff = uint64(timestampSec) - uint64(nowSec)
	}
	if diff > uint64(maxSkewSec) {
		return ErrTimestampOutOfWindow
	}
	return nil
}

// ValidateAndRecord validates timestampSec against f.Now() ± f.Window() FIRST (preventing expired
// replays from polluting Bloom bits) and then atomically checks and records clientSalt.
func (f *SlidingBloomFilter) ValidateAndRecord(clientSalt [32]byte, timestampSec int64) error {
	now := f.timeFunc()
	if err := ValidateTimestamp(timestampSec, now, f.window); err != nil {
		return err
	}
	if !f.CheckAndAdd(clientSalt, now) {
		return ErrSaltReplayed
	}
	return nil
}

// CheckAndAdd checks whether clientSalt is present in current or previous generation (rotating
// lazily on now advancing by >= 2*TimeWindow). Returns true and inserts into current if fresh;
// returns false without modifying current if already present. Zero heap allocations per call.
func (f *SlidingBloomFilter) CheckAndAdd(clientSalt [32]byte, now time.Time) bool {
	probes := f.deriveProbes(clientSalt)
	nowWall := now.Round(0)

	f.mu.Lock()
	f.maybeRotateLocked(nowWall)
	curr := &f.bits[f.activeIdx]
	prev := &f.bits[f.activeIdx^1]
	if bloomContains(curr, probes) || bloomContains(prev, probes) {
		f.mu.Unlock()
		return false
	}
	bloomInsert(curr, probes)
	f.mu.Unlock()
	return true
}

func (f *SlidingBloomFilter) deriveProbes(clientSalt [32]byte) bloomProbeSet {
	var buf [64]byte
	copy(buf[0:32], f.seed[:])
	copy(buf[32:64], clientSalt[:])
	sum := sha256.Sum256(buf[:])
	return bloomProbeSet{
		binary.LittleEndian.Uint32(sum[0:4]) & bloomBitMask,
		binary.LittleEndian.Uint32(sum[4:8]) & bloomBitMask,
		binary.LittleEndian.Uint32(sum[8:12]) & bloomBitMask,
		binary.LittleEndian.Uint32(sum[12:16]) & bloomBitMask,
		binary.LittleEndian.Uint32(sum[16:20]) & bloomBitMask,
		binary.LittleEndian.Uint32(sum[20:24]) & bloomBitMask,
	}
}

func (f *SlidingBloomFilter) maybeRotateLocked(nowWall time.Time) {
	elapsed := nowWall.Sub(f.lastRotate)
	if elapsed >= 2*f.rotationInterval {
		clear(f.bits[0][:])
		clear(f.bits[1][:])
		f.activeIdx = 0
		f.lastRotate = nowWall
		f.rotations += 2
		return
	}
	if elapsed >= f.rotationInterval {
		f.activeIdx ^= 1
		clear(f.bits[f.activeIdx][:])
		f.lastRotate = nowWall
		f.rotations++
		return
	}
	if elapsed < -f.rotationInterval {
		f.activeIdx ^= 1
		clear(f.bits[f.activeIdx][:])
		f.lastRotate = nowWall
		f.rotations++
	}
}

func bloomContains(gen *[bloomWords]uint64, p bloomProbeSet) bool {
	return (gen[uint16(p[0]>>6)]&(uint64(1)<<(p[0]&63))) != 0 &&
		(gen[uint16(p[1]>>6)]&(uint64(1)<<(p[1]&63))) != 0 &&
		(gen[uint16(p[2]>>6)]&(uint64(1)<<(p[2]&63))) != 0 &&
		(gen[uint16(p[3]>>6)]&(uint64(1)<<(p[3]&63))) != 0 &&
		(gen[uint16(p[4]>>6)]&(uint64(1)<<(p[4]&63))) != 0 &&
		(gen[uint16(p[5]>>6)]&(uint64(1)<<(p[5]&63))) != 0
}

func bloomInsert(gen *[bloomWords]uint64, p bloomProbeSet) {
	gen[uint16(p[0]>>6)] |= uint64(1) << (p[0] & 63)
	gen[uint16(p[1]>>6)] |= uint64(1) << (p[1] & 63)
	gen[uint16(p[2]>>6)] |= uint64(1) << (p[2] & 63)
	gen[uint16(p[3]>>6)] |= uint64(1) << (p[3] & 63)
	gen[uint16(p[4]>>6)] |= uint64(1) << (p[4] & 63)
	gen[uint16(p[5]>>6)] |= uint64(1) << (p[5] & 63)
}

// Deprecated: temporary v1 compatibility constants kept until M4 rewrites inbound.go.
const (
	MaxTimeDiffMs = 30000
	LRUWindowSize = 10000
)

// Deprecated: temporary v1 compatibility wrapper kept until M4 rewrites inbound.go.
type ReplayFilter struct {
	filter      *SlidingBloomFilter
	timeLimitMs int64
}

// Deprecated: temporary v1 compatibility constructor kept until M4 rewrites inbound.go.
func NewReplayFilter(_ int, timeLimitMs int64) *ReplayFilter {
	if timeLimitMs <= 0 {
		timeLimitMs = MaxTimeDiffMs
	}
	return &ReplayFilter{
		filter:      NewSlidingBloomFilter(time.Duration(timeLimitMs)*time.Millisecond, nil),
		timeLimitMs: timeLimitMs,
	}
}

// Deprecated: temporary v1 compatibility method kept until M4 rewrites inbound.go/conn.go.
func (rf *ReplayFilter) CheckAndAdd(timestampMs int64, nonce uint64) bool {
	now := rf.filter.Now()
	diff := now.UnixMilli() - timestampMs
	if diff < -rf.timeLimitMs || diff > rf.timeLimitMs {
		return false
	}
	var salt [32]byte
	binary.BigEndian.PutUint64(salt[0:8], nonce)
	return rf.filter.CheckAndAdd(salt, now)
}
```

### 4.2 Required Test & Benchmark Matrix for `protocol/aether/replay_test.go`
1. **`TestSlidingBloomMemoryLayoutAndZeroAlloc`**:
   - Verify `unsafe.Sizeof(bf.bits[0]) == 524288` (`512 KiB`) and `unsafe.Sizeof(bf.bits) == 1048576` (`1 MiB`).
   - Capture `&bf.bits[0][0]` and `&bf.bits[1][0]`, assert `testing.AllocsPerRun(1000, ...)` across `ValidateAndRecord` + `+60s`/`+120s` rotations equals **`0`**, and confirm backing pointers are unchanged.
2. **`TestResolveTimeFuncAndNTPServiceIntegration`**:
   - Test `nil` context (no panic), `context.Background()` (nil `ntp.TimeFuncFromContext`, falls back to `time.Now`), empty `service.ContextWithDefaultRegistry`, `ntp.TimeService` returning `nil` `TimeFunc()`, and custom `ntp.TimeService` registered via `service.ContextWith[ntp.TimeService](ctx, mockService)` at an epoch `10` years off system clock.
3. **`TestValidateTimestampBoundariesAndInt64Extremes`**:
   - Verify `±30s` inclusive pass, `±31s` fail (`ErrTimestampOutOfWindow`), `math.MinInt64` / `math.MaxInt64` overflow immunity, and **non-pollution invariant** (rejected `timestampSec = now - 31` does NOT insert `clientSalt` into `SlidingBloomFilter`, so subsequent valid `timestampSec = now` with same `clientSalt` succeeds).
4. **`TestRotationBoundaryClockSkewSafety` (`U-13`)**:
   - Mock clock `t0 = 1_700_000_000s`: insert `(saltA, ts = t0 + 59 + 29)` at `t = 59.9s` (`rotations == 0`, accepted); verify immediate replay fails (`ErrSaltReplayed`); advance to `t = 60.1s`, verify rotation fired (`rotations == 1`) AND replay of `(saltA, ts)` STILL fails via `previous`; advance to `t = 118.0s` (`|118 - 88| == 30`), verify replay STILL fails; advance to `t = 120.2s` (`rotations == 2`), verify `(saltA, ts)` fails `ErrTimestampOutOfWindow` while `CheckAndAdd(saltA, now)` succeeds (`true`). Also test `+300s` multi-generation idle skip and `-2h` backward NTP step recovery.
5. **`TestFalsePositiveRateAt100kAnd1M` (Using Fast ChaCha20 Deterministic Salt Stream)**:
   - **100,000 single-gen**: Insert `100,000` unique salts, assert `0` false negatives across all `100,000`, and probe `100,000` disjoint uninserted salts read-only (`bloomContains`) asserting `empiricalFPR < 0.0002` (theoretical `0.000561%`).
   - **1,000,000 single-gen saturation (zero-wipe proof)**: Insert `1,000,000` unique salts without rotation, verify `0` false negatives (including entry `#0`, `#9999`, `#10000`, `#999999`), and assert read-only `empiricalFPR` over `50,000` disjoint probes lies in `[0.175, 0.215]` (theoretical `0.193941`).
   - **1,000,000 rotated (`10` epochs × `100,000` salts, `+60.1s`/epoch)**: Assert `0` false negatives on the latest `200,000` salts (`previous` + `current`) and dual-gen `empiricalFPR < 0.0003` (theoretical peak `0.001122%`).
6. **`TestPerInstanceCSPRNGSeedIsolation`**:
   - Two `NewSlidingBloomFilter` instances produce distinct non-zero `seed`s and distinct `deriveProbes(salt)` outputs.
7. **`TestConcurrent32GoroutinesRaceAndReplayContest`**:
   - **Barrier Contest (`100` rounds × `32` goroutines)**: All 32 goroutines submit the identical `(salt, validTS)` on channel close; assert **strictly `1` `nil` and `31` `ErrSaltReplayed`** every round.
   - **Mixed Saturation + Rotation (`32` goroutines × `2,000` ops + concurrent `atomic.Int64` clock stepper)**: Concurrent fresh inserts, duplicate replays, out-of-window timestamps, and `6+` generation rotations under `go test -race` with zero races or panics.
8. **`TestLegacyReplayFilterShim` & `BenchmarkSlidingBloom*`**:
   - Verify `ReplayFilter` shim behavior and benchmark `CheckAndAdd` / `ValidateAndRecord` sequential + 32-goroutine `RunParallel` (`b.ReportAllocs()` -> `0 allocs/op`).

---

## 5. Verification Method

After the M2 Worker implements `protocol/aether/replay.go` and `protocol/aether/replay_test.go`, verify independently with:

1. **Unit, Race, FPR & Boundary Suite**:
   ```bash
   GOPROXY=direct GOSUMDB=off go test -v -race -count=1 ./protocol/aether/...
   ```
2. **Zero-Allocation Benchmark Verification**:
   ```bash
   GOPROXY=direct GOSUMDB=off go test -run=^$ -bench='Benchmark(SlidingBloom|Validate)' -benchmem ./protocol/aether/...
   ```
   Confirm `0 B/op` and `0 allocs/op` on every benchmark line.
3. **Full-Tag Binary Compilation Verification (Confirming M2 Shim Compatibility with `inbound.go` & `conn.go`)**:
   ```bash
   GOPROXY=direct GOSUMDB=off CGO_ENABLED=0 go build -trimpath \
     -tags "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,badlinkname,tfogo_checklinkname0" \
     -ldflags "-X 'github.com/sagernet/sing-box/constant.Version=1.14.4-Custom-Aether' $(cat release/LDFLAGS) -s -w -buildid=" \
     -o /tmp/sing-box-m2-check ./cmd/sing-box && rm -f /tmp/sing-box-m2-check
   ```
4. **Invalidation Conditions**:
   - This report's backward-compatibility shim analysis would require adjustment only if `inbound.go` or `conn.go` were modified before M2 completes, or if `PROJECT.md` `U-13` changed `[65536]uint64` / `k = 6` / `2 * TimeWindow`.
