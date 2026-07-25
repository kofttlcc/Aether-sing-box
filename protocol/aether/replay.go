package aether

import (
	"sync"
	"time"
)

const (
	MaxTimeDiffMs = 30000
	LRUWindowSize = 10000
)

type ReplayFilter struct {
	mu        sync.Mutex
	seen      map[uint64]int64
	maxSize   int
	timeLimit int64
}

func NewReplayFilter(maxSize int, timeLimitMs int64) *ReplayFilter {
	if maxSize <= 0 {
		maxSize = LRUWindowSize
	}
	if timeLimitMs <= 0 {
		timeLimitMs = MaxTimeDiffMs
	}
	return &ReplayFilter{
		seen:      make(map[uint64]int64, maxSize),
		maxSize:   maxSize,
		timeLimit: timeLimitMs,
	}
}

func (rf *ReplayFilter) CheckAndAdd(timestampMs int64, nonce uint64) bool {
	rf.mu.Lock()
	defer rf.mu.Unlock()

	now := time.Now().UnixMilli()

	diff := now - timestampMs
	if diff < -rf.timeLimit || diff > rf.timeLimit {
		return false
	}

	if _, exists := rf.seen[nonce]; exists {
		return false
	}

	if len(rf.seen) >= rf.maxSize {
		cutoff := now - rf.timeLimit
		for k, t := range rf.seen {
			if t < cutoff {
				delete(rf.seen, k)
			}
		}
		if len(rf.seen) >= rf.maxSize {
			rf.seen = make(map[uint64]int64, rf.maxSize)
		}
	}

	rf.seen[nonce] = now
	return true
}
