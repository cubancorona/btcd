// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// stallControlMessageQueueSize specifies the size of the buffered channel that
// holds queued stall control messages.
const stallControlMessageQueueSize int = 1707

// StallHandler is an intentionally flexible interface to a stall handler,
// corresponding to a particular implementation of stall handling
// functionality.  It provides a seam that lets callers supply an alternative
// stall detection strategy (see Config.StallHandler) while defaulting to the
// per-object BitcoinStallHandler below.
type StallHandler interface {
	// InitializeStallHandling wires the handler to the given peer and starts
	// any background processing required to detect stalls.  It must be safe
	// to call once per peer.
	InitializeStallHandling(*Peer)

	// Disconnect stops the stall handling functionality from continuing to
	// run.
	Disconnect()

	// ProcessStallControlMessage informs the handler about a stall control
	// event (a message being sent or received, or a callback starting or
	// finishing) so it can maintain its view of pending responses.
	ProcessStallControlMessage(msg *stallControlMsg)
}

// newStallHandler returns the StallHandler implementation to use for a peer
// based on its configuration.  A caller-supplied implementation takes
// precedence; otherwise a no-op handler is returned when stall handling is
// disabled, and the default per-object BitcoinStallHandler is used in all other
// cases.
func newStallHandler(cfg *Config) StallHandler {
	switch {
	case cfg.StallHandler != nil:
		return cfg.StallHandler
	case cfg.DisableStallHandler:
		return &noopStallHandler{}
	default:
		return &BitcoinStallHandler{}
	}
}

// noopStallHandler is a StallHandler that does nothing.  It is used when stall
// handling is disabled via Config.DisableStallHandler.
type noopStallHandler struct{}

// InitializeStallHandling is part of the StallHandler interface.
func (n *noopStallHandler) InitializeStallHandling(*Peer) {}

// Disconnect is part of the StallHandler interface.
func (n *noopStallHandler) Disconnect() {}

// ProcessStallControlMessage is part of the StallHandler interface.
func (n *noopStallHandler) ProcessStallControlMessage(*stallControlMsg) {}

// BitcoinStallHandler handles stall detection for the Bitcoin peer-to-peer
// network.  Unlike the legacy stall handler, it tracks the individual inventory
// objects expected in response to each request, so a steady stream of responses
// to a large batch of requests renews the deadline rather than tripping it, and
// notfound messages satisfy the corresponding deadlines.
type BitcoinStallHandler struct {
	// initializationMutex protects peer and stallControlMessageHandlingQueue.
	initializationMutex              sync.RWMutex
	peer                             *Peer                // Subject Peer.
	stallControlMessageHandlingQueue chan stallControlMsg // Stall control message channel.

	// quit indicates disconnection of the stall handling functionality.  It
	// is accessed atomically.
	quit int32

	// initializationOnlyOneTime ensures initialization occurs only once even
	// if InitializeStallHandling is called multiple times.
	initializationOnlyOneTime sync.Once

	// pendingMapsMutex protects pendingResponses and pendingRequestedObjects.
	pendingMapsMutex        sync.RWMutex
	pendingResponses        map[string]time.Time
	pendingRequestedObjects map[string][]chainhash.Hash
}

// Disconnect stops the stall handling functionality from continuously running.
func (sh *BitcoinStallHandler) Disconnect() {
	atomic.SwapInt32(&sh.quit, 3)
}

// disconnectAutomatically waits for the peer to disconnect and then stops the
// stall handling functionality.
func (sh *BitcoinStallHandler) disconnectAutomatically() {
	// Wait for the Peer to signal disconnection.
	sh.peer.WaitForDisconnect()
	// Disconnect the stall handling functionality.
	sh.Disconnect()
}

// InitializeStallHandling wires the handler to the peer, creates the message
// queue, and starts the background handler goroutine.  It is safe to call more
// than once; only the first call has any effect.
func (sh *BitcoinStallHandler) InitializeStallHandling(peer *Peer) {
	go func() {
		// Only initialize once.
		sh.initializationOnlyOneTime.Do(func() {
			// Initialize subject Peer and stall control message
			// channel.
			sh.initializationMutex.Lock()
			sh.peer = peer
			sh.stallControlMessageHandlingQueue = make(
				chan stallControlMsg, stallControlMessageQueueSize,
			)
			sh.initializationMutex.Unlock()

			// Start handling incoming stall control messages.
			go sh.stallControlMessageHandler()
		})
	}()
}

// ProcessStallControlMessage enqueues a stall control message for processing.
// It never blocks: if the queue is full or not yet initialized, the message is
// dropped.
func (sh *BitcoinStallHandler) ProcessStallControlMessage(msg *stallControlMsg) {
	sh.initializationMutex.RLock()
	defer sh.initializationMutex.RUnlock()

	// Prevent blocking.
	select {
	case sh.stallControlMessageHandlingQueue <- *msg:
		return
	default:
		log.Debugf("Stall handler for peer %s not ready for message "+
			"handling", sh.peer)
	}
}

// handleOutgoingMessage potentially adds a deadline for the appropriate
// expected response for the passed wire protocol command to the pending
// responses map, and records the specific inventory objects expected in
// response so they can be tracked individually.
func (sh *BitcoinStallHandler) handleOutgoingMessage(msg wire.Message) {
	sh.pendingMapsMutex.Lock()
	defer sh.pendingMapsMutex.Unlock()

	// Setup a deadline for each message being sent that expects a response.
	//
	// NOTE: Pings are intentionally ignored here since they are typically
	// sent asynchronously and as a result of a long backlog of messages,
	// such as is typical in the case of initial block download, the response
	// won't be received in time.
	deadline := sh.peer.LocalClock.Now().Add(stallResponseTimeout)
	msgCmd := msg.Command()
	switch msgCmd {
	case wire.CmdVersion:
		// Expects a verack message.
		sh.pendingResponses[wire.CmdVerAck] = deadline

	case wire.CmdMemPool:
		// Expects an inv message.
		sh.pendingResponses[wire.CmdInv] = deadline

		// Placeholder hash for any inventory object of type transaction.
		emptyTxHash := (&wire.MsgTx{}).TxHash()
		sh.pendingRequestedObjects[wire.CmdInv] = append(
			sh.pendingRequestedObjects[wire.CmdInv], emptyTxHash,
		)

	case wire.CmdGetBlocks:
		// Expects an inv message describing at least one block.
		sh.pendingResponses[wire.CmdInv] = deadline

		// Placeholder hash for any inventory object of type block.
		emptyBlockHash := (&wire.BlockHeader{}).BlockHash()
		sh.pendingRequestedObjects[wire.CmdInv] = append(
			sh.pendingRequestedObjects[wire.CmdInv], emptyBlockHash,
		)

	case wire.CmdGetData:
		// Expects a block, merkleblock, tx, or notfound message.
		msgGetData, ok := msg.(*wire.MsgGetData)
		if !ok {
			log.Criticalf("stallHandler for peer %s received a "+
				"getdata command that is not a *wire.MsgGetData",
				sh.peer)
			return
		}

		// Add a deadline corresponding to the expected response message
		// for each type of object being requested, and record the hash
		// of each requested object so it can be tracked individually.
		for _, invItem := range msgGetData.InvList {
			var expectedMsgCmd string
			switch invItem.Type {
			case wire.InvTypeBlock, wire.InvTypeWitnessBlock:
				// We expect a block message (or notfound).
				expectedMsgCmd = wire.CmdBlock

			case wire.InvTypeFilteredBlock,
				wire.InvTypeFilteredWitnessBlock:
				// We expect a merkleblock message (or notfound).
				expectedMsgCmd = wire.CmdMerkleBlock

			case wire.InvTypeTx, wire.InvTypeWitnessTx:
				// We expect a tx message (or notfound).
				expectedMsgCmd = wire.CmdTx

			default:
				continue
			}

			// If there are multiple commands issued simultaneously,
			// reset the shared deadline to avoid stalling after
			// receiving some of them while others are still pending.
			sh.pendingResponses[expectedMsgCmd] = deadline
			sh.pendingRequestedObjects[expectedMsgCmd] = append(
				sh.pendingRequestedObjects[expectedMsgCmd],
				invItem.Hash,
			)
		}

	case wire.CmdGetHeaders:
		// Expects a headers message.  Use a longer deadline since it can
		// take a while for the remote peer to load all of the headers.
		deadline = sh.peer.LocalClock.Now().Add(stallResponseTimeout * 3)
		sh.pendingResponses[wire.CmdHeaders] = deadline
	}
}

// handleIncomingMessage removes received objects from the expected response
// maps, renewing or clearing the corresponding deadlines as appropriate.
func (sh *BitcoinStallHandler) handleIncomingMessage(msg *stallControlMsg) {
	sh.pendingMapsMutex.Lock()
	defer sh.pendingMapsMutex.Unlock()

	switch msgCmd := msg.message.Command(); msgCmd {
	case wire.CmdBlock, wire.CmdMerkleBlock, wire.CmdTx:
		// Calculate the hash of the object using the appropriate method
		// for the object type.
		var objHash chainhash.Hash
		switch m := msg.message.(type) {
		case *wire.MsgBlock:
			objHash = m.Header.BlockHash()
		case *wire.MsgMerkleBlock:
			objHash = m.Header.BlockHash()
		case *wire.MsgTx:
			// Note this is TxHash, not WitnessHash, for both
			// InvTypeTx and InvTypeWitnessTx.
			objHash = m.TxHash()
		default:
			log.Criticalf("stallHandler for peer %s: unhandled "+
				"message type for command %s", sh.peer, msgCmd)
			return
		}

		var countOfHashesFound int
		sh.pendingRequestedObjects[msgCmd], countOfHashesFound =
			sh.removeHashesFromUnderlyingArray(
				sh.pendingRequestedObjects[msgCmd], objHash,
			)

		// Only remove the shared deadline for this object type if there
		// are no pending requested objects of this type remaining.
		// Otherwise, if we found a matching object, renew the deadline.
		if len(sh.pendingRequestedObjects[msgCmd]) == 0 {
			delete(sh.pendingResponses, msgCmd)
		} else if countOfHashesFound > 0 {
			sh.pendingResponses[msgCmd] =
				sh.peer.LocalClock.Now().Add(stallResponseTimeout)
		}

	case wire.CmdInv:
		msgInv, ok := msg.message.(*wire.MsgInv)
		if !ok {
			log.Criticalf("stallHandler for peer %s: unhandled "+
				"message type for command %s", sh.peer, msgCmd)
			return
		}

		// If the inventory message is empty, it might satisfy a deadline
		// for an outgoing mempool command (the mempool could be empty).
		emptyTxHash := (&wire.MsgTx{}).TxHash()
		if len(msgInv.InvList) == 0 {
			var countOfHashesRemoved int
			sh.pendingRequestedObjects[wire.CmdInv], countOfHashesRemoved =
				sh.removeHashesFromUnderlyingArray(
					sh.pendingRequestedObjects[wire.CmdInv],
					emptyTxHash,
				)
			if countOfHashesRemoved > 0 {
				if len(sh.pendingRequestedObjects[wire.CmdInv]) > 0 {
					// Renew the deadline.
					sh.pendingResponses[wire.CmdInv] =
						sh.peer.LocalClock.Now().Add(
							stallResponseTimeout,
						)
				} else {
					// Remove the deadline.
					delete(sh.pendingResponses, msgCmd)
				}
				break
			}
		}

		// For each received inventory vector, remove the corresponding
		// placeholder from pendingRequestedObjects.  getblocks insists on
		// an inv containing a block object, and mempool insists on an inv
		// containing a transaction object.
		emptyBlockHash := (&wire.MsgBlock{}).BlockHash()
		var countOfHashesRemoved int
		for _, invVect := range msgInv.InvList {
			var instantaneousRemovalCount int
			switch invVect.Type {
			case wire.InvTypeBlock, wire.InvTypeWitnessBlock:
				sh.pendingRequestedObjects[wire.CmdInv], instantaneousRemovalCount =
					sh.removeHashesFromUnderlyingArray(
						sh.pendingRequestedObjects[wire.CmdInv],
						emptyBlockHash,
					)
				countOfHashesRemoved += instantaneousRemovalCount

			case wire.InvTypeTx, wire.InvTypeWitnessTx:
				sh.pendingRequestedObjects[wire.CmdInv], instantaneousRemovalCount =
					sh.removeHashesFromUnderlyingArray(
						sh.pendingRequestedObjects[wire.CmdInv],
						emptyTxHash,
					)
				countOfHashesRemoved += instantaneousRemovalCount
			}
		}

		// Now remove or renew the deadline for an expected inv command.
		if len(sh.pendingRequestedObjects[wire.CmdInv]) == 0 {
			delete(sh.pendingResponses, msgCmd)
		} else if countOfHashesRemoved > 0 {
			sh.pendingResponses[wire.CmdInv] =
				sh.peer.LocalClock.Now().Add(stallResponseTimeout)
		}

	case wire.CmdNotFound:
		// The peer has indicated it did not find one or more objects.
		// If we requested any of these objects, this message satisfies
		// the corresponding stall deadline.
		msgNotFound, ok := msg.message.(*wire.MsgNotFound)
		if !ok {
			log.Criticalf("stallHandler for peer %s: unhandled "+
				"message type for command %s", sh.peer, msgCmd)
			return
		}

		// Make a list of object hashes in the inventory vector.
		var invHashesToRemove []chainhash.Hash
		for _, invVect := range msgNotFound.InvList {
			invHashesToRemove = append(
				invHashesToRemove, invVect.Hash,
			)
		}

		// For all types for which we have pending requests, remove any
		// matching hashes and renew or clear the deadlines accordingly.
		for msgType := range sh.pendingRequestedObjects {
			var countOfHashesFound int
			sh.pendingRequestedObjects[msgType], countOfHashesFound =
				sh.removeHashesFromUnderlyingArray(
					sh.pendingRequestedObjects[msgType],
					invHashesToRemove...,
				)

			if len(sh.pendingRequestedObjects[msgType]) == 0 {
				delete(sh.pendingResponses, msgType)
			} else if countOfHashesFound > 0 {
				sh.pendingResponses[msgType] =
					sh.peer.LocalClock.Now().Add(
						stallResponseTimeout,
					)
			}
		}

	default:
		delete(sh.pendingResponses, msgCmd)
	}
}

// handleTickingInterval disconnects the peer if any of the pending responses
// have not arrived by their deadline.
func (sh *BitcoinStallHandler) handleTickingInterval() {
	sh.pendingMapsMutex.RLock()
	defer sh.pendingMapsMutex.RUnlock()

	now := sh.peer.LocalClock.Now()

	// Disconnect the peer if any of the pending responses don't arrive by
	// their deadline.
	for command, deadline := range sh.pendingResponses {
		if now.Before(deadline) {
			continue
		}

		log.Infof("Peer %s appears to be stalled or misbehaving, %s "+
			"timeout -- disconnecting", sh.peer, command)
		sh.peer.Disconnect()
		break
	}
}

// stallControlMessageHandler handles stall detection for the peer.  This entails
// keeping track of expected responses and assigning them deadlines.  It must be
// run as a goroutine.
func (sh *BitcoinStallHandler) stallControlMessageHandler() {
	// Stop the stall handling functionality once the peer disconnects.
	go sh.disconnectAutomatically()

	// pendingResponses tracks the expected response deadline times.
	sh.pendingResponses = make(map[string]time.Time)

	// pendingRequestedObjects tracks, by object type, the inventory objects
	// we have requested from this peer.
	sh.pendingRequestedObjects = make(map[string][]chainhash.Hash)

	// stallTicker is used to periodically check pending responses that have
	// exceeded their deadline and disconnect the peer due to stalling.
	stallTicker := sh.peer.LocalClock.NewTicker(stallTickInterval)
	defer stallTicker.Stop()

out:
	for {
		// Exit the loop if we are disconnecting.
		if atomic.LoadInt32(&sh.quit) > 1 {
			break out
		}

		select {
		case msg := <-sh.stallControlMessageHandlingQueue:
			switch msg.command {
			case sccSendMessage:
				// Add a deadline for the expected response
				// message if needed.
				sh.handleOutgoingMessage(msg.message)

			case sccReceiveMessage:
				// Remove received objects from the expected
				// response maps.
				sh.handleIncomingMessage(&msg)
			}

		case <-stallTicker.Chan():
			// Disconnect the peer if any pending response has
			// exceeded its deadline.
			sh.handleTickingInterval()
		}
	}

	// Drain the queue before going away so there is nothing left waiting on
	// this goroutine.
cleanup:
	for {
		select {
		case <-sh.stallControlMessageHandlingQueue:
		default:
			break cleanup
		}
	}
	log.Tracef("Peer stallHandler done for peer %s", sh.peer)
}

// removeHashesFromUnderlyingArray removes one or more hashes from the array
// underlying subjectSlice and returns the resulting slice and the number of
// hashes removed.
//
// Caution is advised when updating this logic: the returned slice shares the
// same underlying array as subjectSlice, since it is built by passing through
// the original slice item-by-item and only appending the items that should
// remain.
func (sh *BitcoinStallHandler) removeHashesFromUnderlyingArray(
	subjectSlice []chainhash.Hash,
	hashesToRemove ...chainhash.Hash) ([]chainhash.Hash, int) {

	var countOfHashesRemoved int
	modifiedSlice := subjectSlice[:0]

subjectSliceIteration:
	for _, hash := range subjectSlice {
		for _, hashToRemove := range hashesToRemove {
			if hash.IsEqual(&hashToRemove) {
				countOfHashesRemoved++
				continue subjectSliceIteration
			}
		}
		modifiedSlice = append(modifiedSlice, hash)
	}

	return modifiedSlice, countOfHashesRemoved
}
