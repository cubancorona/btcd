// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// TestMaybeAddDeadlineGetBlocksStopHash verifies that the stall deadline for an
// outgoing getblocks depends on its stop hash.  A getblocks with a zero stop
// hash is an open-ended request the protocol does not guarantee a response to
// -- a fully-synced peer legitimately sends no inv -- so it must not arm a
// deadline (btcsuite/btcd#1317).  A getblocks with a non-zero stop hash targets
// a specific block we expect the peer to have, so it must arm an inv deadline.
func TestMaybeAddDeadlineGetBlocksStopHash(t *testing.T) {
	t.Parallel()

	// maybeAddDeadline does not dereference the peer, so a zero-value Peer
	// is sufficient to exercise it.
	p := &Peer{}

	// Zero stop hash: open-ended request the protocol need not answer, so
	// no deadline is armed.
	zero := make(map[string]time.Time)
	p.maybeAddDeadline(zero, wire.NewMsgGetBlocks(&chainhash.Hash{}))
	if len(zero) != 0 {
		t.Fatalf("zero stopHash getblocks armed deadlines: %v", zero)
	}

	// Non-zero stop hash: targets a specific expected block, so an inv
	// deadline is armed.
	stop := chainhash.Hash{0x01}
	nonZero := make(map[string]time.Time)
	p.maybeAddDeadline(nonZero, wire.NewMsgGetBlocks(&stop))
	if _, ok := nonZero[wire.CmdInv]; !ok {
		t.Fatalf("non-zero stopHash getblocks armed no inv deadline")
	}

	// Positive control: an unrelated request command still arms its
	// deadline, guarding against the logic being removed wholesale.
	mempool := make(map[string]time.Time)
	p.maybeAddDeadline(mempool, wire.NewMsgMemPool())
	if len(mempool) == 0 {
		t.Fatal("mempool armed no stall deadline; want one")
	}
}
