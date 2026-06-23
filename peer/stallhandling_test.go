// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/jonboulle/clockwork"
)

// newStallTestPeer returns a minimal Peer suitable for exercising the stall
// handler in isolation.  It wires the supplied clock and a quit channel so that
// Disconnect and WaitForDisconnect behave as they do in production.
func newStallTestPeer(clock clockwork.Clock) *Peer {
	return &Peer{
		LocalClock: clock,
		quit:       make(chan struct{}),
	}
}

// newStallTestHandler returns a BitcoinStallHandler with its tracking maps
// initialized and bound to the given peer, bypassing the background goroutine so
// the message-handling logic can be tested deterministically.
func newStallTestHandler(p *Peer) *BitcoinStallHandler {
	return &BitcoinStallHandler{
		peer:                    p,
		pendingResponses:        make(map[string]time.Time),
		pendingRequestedObjects: make(map[string][]chainhash.Hash),
	}
}

// blockWithNonce returns a block whose header hashes to a value determined by
// the supplied nonce, allowing distinct, reproducible block hashes.
func blockWithNonce(nonce uint32) *wire.MsgBlock {
	blk := &wire.MsgBlock{}
	blk.Header.Nonce = nonce
	return blk
}

// isDisconnected reports whether Disconnect has been called on the peer.
func isDisconnected(p *Peer) bool {
	select {
	case <-p.quit:
		return true
	default:
		return false
	}
}

// TestStallHandlerPerObjectTracking verifies that a getdata request tracks each
// requested object individually: the shared deadline is renewed as objects
// arrive and only cleared once every requested object has been received.
func TestStallHandlerPerObjectTracking(t *testing.T) {
	clock := clockwork.NewFakeClock()
	p := newStallTestPeer(clock)
	sh := newStallTestHandler(p)

	// Request three distinct blocks.
	blocks := []*wire.MsgBlock{
		blockWithNonce(1), blockWithNonce(2), blockWithNonce(3),
	}
	getData := wire.NewMsgGetData()
	for _, blk := range blocks {
		hash := blk.Header.BlockHash()
		if err := getData.AddInvVect(
			wire.NewInvVect(wire.InvTypeBlock, &hash),
		); err != nil {
			t.Fatalf("failed to add inv vect: %v", err)
		}
	}
	sh.handleOutgoingMessage(getData)

	if got := len(sh.pendingRequestedObjects[wire.CmdBlock]); got != 3 {
		t.Fatalf("expected 3 pending block objects, got %d", got)
	}
	if _, ok := sh.pendingResponses[wire.CmdBlock]; !ok {
		t.Fatal("expected a pending block deadline after getdata")
	}

	// Deliver the first two blocks; the deadline must remain (renewed) while
	// objects are still outstanding.
	for i := 0; i < 2; i++ {
		clock.Advance(time.Second)
		want := clock.Now().Add(stallResponseTimeout)
		sh.handleIncomingMessage(&stallControlMsg{
			command: sccReceiveMessage, message: blocks[i],
		})

		remaining := len(sh.pendingRequestedObjects[wire.CmdBlock])
		if remaining != 2-i {
			t.Fatalf("after %d blocks: expected %d remaining, got %d",
				i+1, 2-i, remaining)
		}
		deadline, ok := sh.pendingResponses[wire.CmdBlock]
		if !ok {
			t.Fatalf("after %d blocks: deadline cleared too early",
				i+1)
		}
		if !deadline.Equal(want) {
			t.Fatalf("after %d blocks: deadline not renewed, "+
				"got %v want %v", i+1, deadline, want)
		}
	}

	// Deliver the final block; now the deadline must be cleared.
	sh.handleIncomingMessage(&stallControlMsg{
		command: sccReceiveMessage, message: blocks[2],
	})
	if got := len(sh.pendingRequestedObjects[wire.CmdBlock]); got != 0 {
		t.Fatalf("expected 0 pending block objects, got %d", got)
	}
	if _, ok := sh.pendingResponses[wire.CmdBlock]; ok {
		t.Fatal("expected block deadline to be cleared after final block")
	}
}

// TestStallHandlerNotFoundSatisfiesDeadline verifies that a notfound message
// satisfies the deadlines for the objects it references.
func TestStallHandlerNotFoundSatisfiesDeadline(t *testing.T) {
	clock := clockwork.NewFakeClock()
	p := newStallTestPeer(clock)
	sh := newStallTestHandler(p)

	blocks := []*wire.MsgBlock{blockWithNonce(10), blockWithNonce(11)}
	getData := wire.NewMsgGetData()
	notFound := wire.NewMsgNotFound()
	for _, blk := range blocks {
		hash := blk.Header.BlockHash()
		if err := getData.AddInvVect(
			wire.NewInvVect(wire.InvTypeBlock, &hash),
		); err != nil {
			t.Fatalf("failed to add inv vect: %v", err)
		}
		if err := notFound.AddInvVect(
			wire.NewInvVect(wire.InvTypeBlock, &hash),
		); err != nil {
			t.Fatalf("failed to add notfound inv vect: %v", err)
		}
	}
	sh.handleOutgoingMessage(getData)

	if _, ok := sh.pendingResponses[wire.CmdBlock]; !ok {
		t.Fatal("expected a pending block deadline after getdata")
	}

	// The peer reports it could not find either block; the deadline must be
	// satisfied and cleared.
	sh.handleIncomingMessage(&stallControlMsg{
		command: sccReceiveMessage, message: notFound,
	})
	if got := len(sh.pendingRequestedObjects[wire.CmdBlock]); got != 0 {
		t.Fatalf("expected 0 pending block objects after notfound, "+
			"got %d", got)
	}
	if _, ok := sh.pendingResponses[wire.CmdBlock]; ok {
		t.Fatal("expected block deadline cleared after notfound")
	}
}

// TestStallHandlerTickerDisconnect verifies that an expired deadline causes the
// ticking interval handler to disconnect the peer, and that a deadline still in
// the future does not.
func TestStallHandlerTickerDisconnect(t *testing.T) {
	clock := clockwork.NewFakeClock()
	p := newStallTestPeer(clock)
	sh := newStallTestHandler(p)

	// A deadline in the future must not trip the stall handler.
	sh.pendingResponses[wire.CmdBlock] = clock.Now().Add(stallResponseTimeout)
	sh.handleTickingInterval()
	if isDisconnected(p) {
		t.Fatal("peer disconnected before its deadline elapsed")
	}

	// Once the deadline has elapsed, the peer must be disconnected.
	clock.Advance(stallResponseTimeout + time.Second)
	sh.handleTickingInterval()
	if !isDisconnected(p) {
		t.Fatal("peer was not disconnected after its deadline elapsed")
	}
}

// TestStallHandlerInjectableClock exercises the full handler lifecycle through
// InitializeStallHandling, confirming that the injected fake clock drives the
// stall ticker and that an expired deadline results in disconnection.
func TestStallHandlerInjectableClock(t *testing.T) {
	clock := clockwork.NewFakeClock()
	p := newStallTestPeer(clock)
	sh := &BitcoinStallHandler{}

	sh.InitializeStallHandling(p)

	// Wait until the background handler has registered its ticker on the
	// fake clock before advancing time.
	clock.BlockUntil(1)

	// Record an already-expired deadline directly, then advance the clock so
	// the next tick observes the stall.
	sh.pendingMapsMutex.Lock()
	sh.pendingResponses[wire.CmdBlock] = clock.Now().Add(-time.Second)
	sh.pendingMapsMutex.Unlock()

	clock.Advance(stallTickInterval)

	select {
	case <-p.Done():
		// Disconnected as expected.
	case <-time.After(5 * time.Second):
		t.Fatal("stall handler did not disconnect peer on timeout")
	}
}
