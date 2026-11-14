package aether

import (
	"context"
	"encoding/binary"
	"math"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20"
)

type mockNTPService struct {
	tf func() time.Time
}

func (m *mockNTPService) TimeFunc() func() time.Time {
	return m.tf
}

func (m *mockNTPService) Upstream() netip.AddrPort {
	return netip.AddrPort{}
}

type deterministicSaltStream struct {
	cipher *chacha20.Cipher
}

func newDeterministicSaltStream(t *testing.T, streamID byte) *deterministicSaltStream {
	t.Helper()
	var key [32]byte
	var nonce [12]byte
	key[0] = streamID
	key[31] = 0xa5
	c, err := chacha20.NewUnauthenticatedCipher(key[:], nonce[:])
	require.NoError(t, err)
	return &deterministicSaltStream{cipher: c}
}

func (s *deterministicSaltStream) next() [32]byte {
	var out [32]byte
	s.cipher.XORKeyStream(out[:], out[:])
	return out
}

func TestSlidingBloomMemoryLayoutAndZeroAlloc(t *testing.T) {

	now := time.Unix(1_700_000_000, 0)
	currentNow := now
	bf := NewSlidingBloomFilter(30*time.Second, func() time.Time {
		return currentNow
	})

	// Constant 1.00 MiB inline bitset layout: 2 * 524,288B = 1,048,576B
	require.Equal(t, uintptr(524_288), unsafe.Sizeof(bf.bits[0]))
	require.Equal(t, uintptr(1_048_576), unsafe.Sizeof(bf.bits))
	require.Equal(t, 30*time.Second, bf.Window())
	require.Equal(t, 60*time.Second, bf.RotationInterval())

	ptr0Before := &bf.bits[0][0]
	ptr1Before := &bf.bits[1][0]

	var seq uint64
	allocs := testing.AllocsPerRun(1000, func() {
		seq++
		if seq%250 == 0 {
			currentNow = currentNow.Add(61 * time.Second)
		} else if seq%600 == 0 {
			currentNow = currentNow.Add(130 * time.Second)
		}
		var salt [32]byte
		binary.LittleEndian.PutUint64(salt[0:8], seq)
		if err := bf.ValidateAndRecord(salt, currentNow.Unix()); err != nil {
			t.Fatal(err)
		}
	})
	require.Equal(t, float64(0), allocs)
	require.Same(t, ptr0Before, &bf.bits[0][0])
	require.Same(t, ptr1Before, &bf.bits[1][0])
}

func TestResolveTimeFuncAndNTPServiceIntegration(t *testing.T) {
	t.Parallel()

	// 1. nil context must NOT panic and must fall back to time.Now
	var nilCtx context.Context
	tfNil := ResolveTimeFunc(nilCtx)
	require.WithinDuration(t, time.Now(), tfNil(), 2*time.Second)

	// 2. Plain context.Background() without service registry falls back to time.Now
	tfBg := ResolveTimeFunc(context.Background())
	require.WithinDuration(t, time.Now(), tfBg(), 2*time.Second)

	// 3. Context with empty service registry falls back to time.Now
	emptyRegCtx := service.ContextWithDefaultRegistry(context.Background())
	tfEmpty := ResolveTimeFunc(emptyRegCtx)
	require.WithinDuration(t, time.Now(), tfEmpty(), 2*time.Second)

	// 4. Registered ntp.TimeService returning nil TimeFunc falls back to time.Now
	nilTFCtx := service.ContextWith[ntp.TimeService](context.Background(), &mockNTPService{tf: nil})
	require.WithinDuration(t, time.Now(), ResolveTimeFunc(nilTFCtx)(), 2*time.Second)

	// 5. Registered custom ntp.TimeService shifted +10 years from wall clock
	fixedNTPTime := time.Date(2036, 11, 14, 12, 0, 0, 0, time.UTC)
	ntpCtx := service.ContextWith[ntp.TimeService](context.Background(), &mockNTPService{
		tf: func() time.Time { return fixedNTPTime },
	})
	bf := NewSlidingBloomFilterFromContext(ntpCtx, 30*time.Second)
	require.Equal(t, fixedNTPTime, bf.Now())

	var salt [32]byte
	salt[0] = 0x42
	// Real wall clock timestamp must be rejected when NTP clock is +10y ahead
	require.ErrorIs(t, bf.ValidateAndRecord(salt, time.Now().Unix()), ErrTimestampOutOfWindow)
	// NTP-aligned timestamp succeeds because expired check above did NOT pollute Bloom!
	require.NoError(t, bf.ValidateAndRecord(salt, fixedNTPTime.Unix()))
}

func TestValidateTimestampBoundariesAndInt64Extremes(t *testing.T) {
	t.Parallel()

	baseNow := time.Unix(1_700_000_000, 500_000_000)
	bf := NewSlidingBloomFilter(30*time.Second, func() time.Time { return baseNow })

	// Exact +/-30s boundaries accepted; +/-31s and int64 extremes rejected without overflow
	for _, delta := range []int64{-30, -29, 0, 29, 30} {
		require.NoError(t, ValidateTimestamp(baseNow.Unix()+delta, baseNow, 30*time.Second), "delta=%d", delta)
	}
	for _, badTS := range []int64{
		baseNow.Unix() - 31,
		baseNow.Unix() + 31,
		0,
		-1_000_000_000,
		math.MinInt64,
		math.MinInt64 + 1,
		math.MaxInt64 - 1,
		math.MaxInt64,
	} {
		require.ErrorIs(t, ValidateTimestamp(badTS, baseNow, 30*time.Second), ErrTimestampOutOfWindow, "ts=%d", badTS)
	}

	// Non-pollution invariant: 1,000 expired/future attempts with the same salt NEVER set Bloom bits
	var targetSalt [32]byte
	targetSalt[0] = 0x99
	for _, badTS := range []int64{baseNow.Unix() - 31, baseNow.Unix() + 31, math.MinInt64, math.MaxInt64} {
		require.ErrorIs(t, bf.ValidateAndRecord(targetSalt, badTS), ErrTimestampOutOfWindow)
	}
	require.NoError(t, bf.ValidateAndRecord(targetSalt, baseNow.Unix()))
	require.ErrorIs(t, bf.ValidateAndRecord(targetSalt, baseNow.Unix()), ErrSaltReplayed)

	// Sub-second positive window clamps to >= 1s skew
	subSecBF := NewSlidingBloomFilter(500*time.Millisecond, func() time.Time { return baseNow })
	require.NoError(t, ValidateTimestamp(baseNow.Unix()+1, baseNow, subSecBF.Window()))
	require.ErrorIs(t, ValidateTimestamp(baseNow.Unix()+2, baseNow, subSecBF.Window()), ErrTimestampOutOfWindow)
}

func TestRotationBoundaryClockSkewAndBackwardNTPStep(t *testing.T) {
	t.Parallel()

	// Part 1: Exact t = 59.9s (ts = +29s) -> t = 60.1s clock-skew rotation boundary test
	t0 := time.Unix(1_700_000_000, 0)
	mockNow := t0
	bf := NewSlidingBloomFilter(30*time.Second, func() time.Time { return mockNow })

	var saltBoundary [32]byte
	saltBoundary[0] = 0x77

	// At t = 59.9s, client handshake arrives with +29s clock skew (ts = t0 + 88)
	mockNow = t0.Add(59_900 * time.Millisecond)
	tsSkewed := t0.Unix() + 59 + 29 // +88s
	require.NoError(t, bf.ValidateAndRecord(saltBoundary, tsSkewed))
	require.Equal(t, uint64(0), bf.rotations)

	// Immediate replay at t = 59.9s rejected via current generation
	require.ErrorIs(t, bf.ValidateAndRecord(saltBoundary, tsSkewed), ErrSaltReplayed)

	// Advance across the 60.0s rotation boundary to t = 60.1s:
	// ts = +88s is STILL within 60 +/- 30s (|60 - 88| = 28 <= 30), and rotation #1 fires!
	mockNow = t0.Add(60_100 * time.Millisecond)
	require.ErrorIs(t, bf.ValidateAndRecord(saltBoundary, tsSkewed), ErrSaltReplayed)
	require.Equal(t, uint64(1), bf.rotations)

	// Advance to t = 118.0s (|118 - 88| = 30 <= 30, edge of validity window): STILL rejected via previous!
	mockNow = t0.Add(118 * time.Second)
	require.ErrorIs(t, bf.ValidateAndRecord(saltBoundary, tsSkewed), ErrSaltReplayed)
	require.Equal(t, uint64(1), bf.rotations)

	// Advance to t = 120.2s: rotation #2 clears old previous; tsSkewed is now rejected by timestamp window
	mockNow = t0.Add(120_200 * time.Millisecond)
	require.ErrorIs(t, bf.ValidateAndRecord(saltBoundary, tsSkewed), ErrTimestampOutOfWindow)
	require.True(t, bf.CheckAndAdd(saltBoundary, mockNow))
	require.Equal(t, uint64(2), bf.rotations)

	// Part 2: Multi-generation idle skip (+300s) clears both generations cleanly
	var saltIdle [32]byte
	saltIdle[0] = 0x88
	require.NoError(t, bf.ValidateAndRecord(saltIdle, mockNow.Unix()))
	mockNow = mockNow.Add(300 * time.Second)
	require.NoError(t, bf.ValidateAndRecord(saltIdle, mockNow.Unix()))
	require.Equal(t, uint64(4), bf.rotations)

	// Part 3: Backward NTP step (-5s jitter AND -2h initial NTP jump) preserves BOTH generations
	// without wiping AND re-anchors lastRotate so subsequent +60.1s rotation is never stalled!
	var saltPrevGen, saltCurrGen [32]byte
	saltPrevGen[0] = 0x11
	saltCurrGen[0] = 0x22

	require.NoError(t, bf.ValidateAndRecord(saltPrevGen, mockNow.Unix()))
	mockNow = mockNow.Add(61 * time.Second) // rotates saltPrevGen into previous
	require.NoError(t, bf.ValidateAndRecord(saltCurrGen, mockNow.Unix()))
	rotBeforeJump := bf.rotations

	// Simulate NTP syncing and stepping clock backward by 2 hours!
	mockNow = mockNow.Add(-2 * time.Hour)
	var postSyncSalt [32]byte
	postSyncSalt[0] = 0x33
	require.NoError(t, bf.ValidateAndRecord(postSyncSalt, mockNow.Unix()))

	// Both pre-jump generations (previous AND current) remain intact against replay!
	require.False(t, bf.CheckAndAdd(saltPrevGen, mockNow))
	require.False(t, bf.CheckAndAdd(saltCurrGen, mockNow))
	require.False(t, bf.CheckAndAdd(postSyncSalt, mockNow))

	// Advancing just +61s after the -2h step MUST trigger normal rotation (not stalled for 2 hours!)
	mockNow = mockNow.Add(61 * time.Second)
	var afterResumeSalt [32]byte
	afterResumeSalt[0] = 0x44
	require.NoError(t, bf.ValidateAndRecord(afterResumeSalt, mockNow.Unix()))
	require.Equal(t, rotBeforeJump+1, bf.rotations)
	require.False(t, bf.CheckAndAdd(postSyncSalt, mockNow), "postSyncSalt must survive in previous after resumed rotation")
}

func TestFalsePositiveRateAnd1MillionEntryZeroWipe(t *testing.T) {
	t.Parallel()

	// Regime 1: 100,000 entries in a single generation -> 0% FN, empirical FPR < 0.0002 (theoretical 0.000561%)
	t.Run("100k_SingleGeneration", func(t *testing.T) {
		t.Parallel()
		now := time.Unix(1_700_000_000, 0)
		bf := NewSlidingBloomFilter(30*time.Second, func() time.Time { return now })

		insertStream := newDeterministicSaltStream(t, 0x01)
		for range 100_000 {
			bf.CheckAndAdd(insertStream.next(), now)
		}

		// Re-stream all 100,000 inserted salts: 0 false negatives allowed
		verifyStream := newDeterministicSaltStream(t, 0x01)
		for i := range 100_000 {
			require.False(t, bf.CheckAndAdd(verifyStream.next(), now), "false negative at index %d", i)
		}

		// Read-only probe of 100,000 disjoint salts
		probeStream := newDeterministicSaltStream(t, 0x02)
		falsePositives := 0
		curr := &bf.bits[bf.activeIdx]
		for range 100_000 {
			p := bf.deriveProbes(probeStream.next())
			if bloomContains(curr, p) {
				falsePositives++
			}
		}
		fpr := float64(falsePositives) / 100_000.0
		require.Less(t, fpr, 0.0002, "100k single-gen FPR=%f", fpr)
	})

	// Regime 2: 1,000,000 entries in a SINGLE unrotated generation -> 0% FN (proving v1 10k map-wipe is gone!)
	// and empirical FPR in [0.175, 0.215] (theoretical (1 - (1 - 1/2^22)^6000000)^6 = 0.193941)
	t.Run("1M_SingleGeneration_ZeroWipeProof", func(t *testing.T) {
		t.Parallel()
		now := time.Unix(1_700_000_000, 0)
		bf := NewSlidingBloomFilter(30*time.Second, func() time.Time { return now })

		insertStream := newDeterministicSaltStream(t, 0x11)
		for range 1_000_000 {
			bf.CheckAndAdd(insertStream.next(), now)
		}

		// Verify 100% of all 1,000,000 salts (including #0, #9999, #10000, #999999) are still present!
		verifyStream := newDeterministicSaltStream(t, 0x11)
		curr := &bf.bits[bf.activeIdx]
		for i := range 1_000_000 {
			p := bf.deriveProbes(verifyStream.next())
			if !bloomContains(curr, p) {
				t.Fatalf("false negative at entry #%d (filter wiped!)", i)
			}
		}

		probeStream := newDeterministicSaltStream(t, 0x12)
		falsePositives := 0
		const probeCount = 50_000
		for range probeCount {
			p := bf.deriveProbes(probeStream.next())
			if bloomContains(curr, p) {
				falsePositives++
			}
		}
		fpr := float64(falsePositives) / float64(probeCount)
		require.GreaterOrEqual(t, fpr, 0.175, "1M saturation FPR=%f", fpr)
		require.LessOrEqual(t, fpr, 0.215, "1M saturation FPR=%f", fpr)
	})

	// Regime 3: 1,000,000 entries across 10 rotated generations (100k/gen, +60.1s/gen)
	// -> 0% FN across the latest 200,000 salts (previous + current) and dual-gen FPR < 0.0003!
	t.Run("1M_RotatedAcross10Generations", func(t *testing.T) {
		t.Parallel()
		mockNow := time.Unix(1_700_000_000, 0)
		bf := NewSlidingBloomFilter(30*time.Second, func() time.Time { return mockNow })

		var accepted [10][100_000]bool
		for epoch := range 10 {
			if epoch > 0 {
				mockNow = mockNow.Add(60_100 * time.Millisecond)
			}
			epochStream := newDeterministicSaltStream(t, byte(0x20+epoch))
			for i := range 100_000 {
				accepted[epoch][i] = bf.CheckAndAdd(epochStream.next(), mockNow)
			}
		}
		require.Equal(t, uint64(9), bf.rotations)

		// All accepted salts in latest 2 generations (epochs 8 and 9 in previous and current) must have 0% false negatives
		for _, activeEpoch := range []int{8, 9} {
			checkStream := newDeterministicSaltStream(t, byte(0x20+activeEpoch))
			for i := range 100_000 {
				salt := checkStream.next()
				if !accepted[activeEpoch][i] {
					continue
				}
				if bf.CheckAndAdd(salt, mockNow) {
					t.Fatalf("epoch %d accepted entry %d was unexpectedly accepted as fresh", activeEpoch, i)
				}
			}
		}

		// Dual-generation FPR check across 100,000 fresh disjoint probes (theoretical peak 0.00001122)
		probeStream := newDeterministicSaltStream(t, 0x99)
		curr := &bf.bits[bf.activeIdx]
		prev := &bf.bits[bf.activeIdx^1]
		falsePositives := 0
		for range 100_000 {
			p := bf.deriveProbes(probeStream.next())
			if bloomContains(curr, p) || bloomContains(prev, p) {
				falsePositives++
			}
		}
		dualFPR := float64(falsePositives) / 100_000.0
		require.Less(t, dualFPR, 0.0003, "dual-gen rotated 1M FPR=%f", dualFPR)
	})
}

func TestPerInstanceCSPRNGSeedIsolation(t *testing.T) {
	t.Parallel()

	bf1 := NewSlidingBloomFilter(0, nil)
	bf2 := NewSlidingBloomFilter(0, nil)
	require.NotEqual(t, [32]byte{}, bf1.seed)
	require.NotEqual(t, [32]byte{}, bf2.seed)
	require.NotEqual(t, bf1.seed, bf2.seed)

	var sampleSalt [32]byte
	sampleSalt[0] = 0x55
	require.NotEqual(t, bf1.deriveProbes(sampleSalt), bf2.deriveProbes(sampleSalt))
}

func TestConcurrent32GoroutinesRaceAndReplayContest(t *testing.T) {
	t.Parallel()

	// Part 1: 100 rounds x 32 goroutines atomic single-winner contest on identical (salt, ts)
	baseUnix := int64(1_700_000_000)
	bfContest := NewSlidingBloomFilter(30*time.Second, func() time.Time {
		return time.Unix(baseUnix, 0)
	})

	const workers = 32
	for round := range 100 {
		var salt [32]byte
		binary.LittleEndian.PutUint64(salt[0:8], uint64(round+1))
		salt[31] = 0xee

		startBarrier := make(chan struct{})
		var winners atomic.Int32
		var replays atomic.Int32
		var wg sync.WaitGroup
		wg.Add(workers)

		for range workers {
			go func() {
				defer wg.Done()
				<-startBarrier
				err := bfContest.ValidateAndRecord(salt, baseUnix)
				switch err {
				case nil:
					winners.Add(1)
				case ErrSaltReplayed:
					replays.Add(1)
				default:
					t.Errorf("unexpected error: %v", err)
				}
			}()
		}
		close(startBarrier)
		wg.Wait()

		require.Equal(t, int32(1), winners.Load(), "round %d must have strictly 1 winner", round)
		require.Equal(t, int32(workers-1), replays.Load(), "round %d must have 31 replays", round)
	}

	// Part 2: 32 goroutines x 2,000 mixed ops + concurrent clock stepper across 6+ rotations under -race
	var atomicUnix atomic.Int64
	atomicUnix.Store(baseUnix)
	bfMixed := NewSlidingBloomFilter(30*time.Second, func() time.Time {
		return time.Unix(atomicUnix.Load(), 0)
	})

	stopClock := make(chan struct{})
	var clockWG sync.WaitGroup
	clockWG.Add(1)
	go func() {
		defer clockWG.Done()
		for {
			select {
			case <-stopClock:
				return
			default:
				atomicUnix.Add(15)
				time.Sleep(time.Millisecond)
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(workers)
	for g := range workers {
		go func(workerID int) {
			defer wg.Done()
			for i := range 2000 {
				nowSec := atomicUnix.Load()
				var salt [32]byte
				binary.LittleEndian.PutUint32(salt[0:4], uint32(workerID))
				binary.LittleEndian.PutUint32(salt[4:8], uint32(i/2)) // every odd i replays previous salt!
				if i%10 == 0 {
					_ = bfMixed.ValidateAndRecord(salt, nowSec-100) // expired
				} else {
					_ = bfMixed.ValidateAndRecord(salt, nowSec)
				}
			}
		}(g)
	}
	wg.Wait()
	close(stopClock)
	clockWG.Wait()
}

func BenchmarkSlidingBloomValidateAndRecord_Sequential(b *testing.B) {
	now := time.Unix(1_700_000_000, 0)
	bf := NewSlidingBloomFilter(30*time.Second, func() time.Time { return now })
	nowSec := now.Unix()
	var salt [32]byte

	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		binary.LittleEndian.PutUint64(salt[0:8], uint64(i))
		_ = bf.ValidateAndRecord(salt, nowSec)
	}
}

func BenchmarkSlidingBloomValidateAndRecord_Parallel32(b *testing.B) {
	now := time.Unix(1_700_000_000, 0)
	bf := NewSlidingBloomFilter(30*time.Second, func() time.Time { return now })
	nowSec := now.Unix()
	var counter atomic.Uint64

	b.SetParallelism(32)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var salt [32]byte
		for pb.Next() {
			id := counter.Add(1)
			binary.LittleEndian.PutUint64(salt[0:8], id)
			_ = bf.ValidateAndRecord(salt, nowSec)
		}
	})
}
