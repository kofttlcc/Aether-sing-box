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

	bloomWords    = 65536           // 65,536 * 8B = 524,288B (512 KiB) per generation
	bloomBits     = bloomWords * 64 // 4,194,304 bits (2^22) per generation
	bloomBitMask  = bloomBits - 1   // 0x3FFFFF (22-bit mask)
	bloomProbes   = 6               // k = 6 independent bit probes
	maxSafeWindow = time.Duration(math.MaxInt64 / 4)
)

var (
	ErrTimestampOutOfWindow = errors.New("aether: handshake timestamp outside allowed window")
	ErrSaltReplayed         = errors.New("aether: replayed client salt detected")
)

type bloomProbeSet [bloomProbes]uint32

// SlidingBloomFilter implements a constant-memory (1.00 MiB: [2][65536]uint64),
// zero-allocation, dual-generation sliding Bloom anti-replay filter with lazy
// wall-clock 2 * TimeWindow rotation and k = 6 CSPRNG-seeded SHA-256 bit probes.
type SlidingBloomFilter struct {
	seed             [32]byte
	window           time.Duration
	rotationInterval time.Duration
	timeFunc         func() time.Time

	mu         sync.Mutex
	lastRotate time.Time
	rotations  uint64
	activeIdx  uint8
	bits       [2][bloomWords]uint64
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

// NewSlidingBloomFilterFromContext constructs a SlidingBloomFilter wired to ResolveTimeFunc(ctx).
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
	maxSkewSec := max(int64(window/time.Second), 1)
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

// ValidateAndRecord validates timestampSec against f.Now() +/- f.Window() FIRST (preventing
// expired replays from polluting Bloom bits) and then atomically checks and records clientSalt.
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
// lazily when now advances by >= 2 * TimeWindow). Returns true and inserts into current if fresh;
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
	if elapsed < 0 {
		// Backward NTP clock adjustment: preserve both current and previous
		// generations without wiping, and re-anchor lastRotate so future
		// 2*TimeWindow rotations proceed on schedule without stalling.
		f.lastRotate = nowWall
		return
	}
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
	var diff uint64
	nowMs := now.UnixMilli()
	if nowMs >= timestampMs {
		diff = uint64(nowMs) - uint64(timestampMs)
	} else {
		diff = uint64(timestampMs) - uint64(nowMs)
	}
	if diff > uint64(rf.timeLimitMs) {
		return false
	}
	var salt [32]byte
	binary.BigEndian.PutUint64(salt[0:8], nonce)
	return rf.filter.CheckAndAdd(salt, now)
}
