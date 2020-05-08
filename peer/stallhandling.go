package peer

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// stallControlMessageQueueSize specifies the size of the buffered
// channel that holds queued stall control messages.
const stallControlMessageQueueSize int = 1707

// stallControlCmd represents the command of a stall control message.
type stallControlCmd uint8

// Constants for the command of a stall control message.
const (
	// sccSendMessage indicates a message is being sent to the remote peer.
	sccSendMessage stallControlCmd = iota

	// sccReceiveMessage indicates a message has been received from the
	// remote peer.
	sccReceiveMessage

	// sccHandlerStart indicates a callback handler is about to be invoked.
	sccHandlerStart

	// sccHandlerStart indicates a callback handler has completed.
	sccHandlerDone
)

// stallControlMsg is used to signal the stall handler about specific events
// so it can properly detect and handle stalled remote peers.
type stallControlMsg struct {
	command stallControlCmd
	message wire.Message
}

// StallHandler is an intentionally flexible interface to a stall handler,
// corresponding to a certain implementation of stall handlling functionality.
type StallHandler interface {

	// Starting and stopping functionality
	InitializeStallHandling(*Peer)
	Disconnect()

	// Handling functionality
	ProcessStallControlMessage(msg *stallControlMsg)
}

// BitcoinStallHandler handles stalling functionality for the Bitcoin
// communication network.
type BitcoinStallHandler struct {
	// Subject Peer
	peer *Peer

	// Stall control message channel
	stallControl chan stallControlMsg

	// Atomic variable for indiciating disconnection of the stall
	// handling functionality.
	quit int32

	// Synchronization variables for ensuring initialization only
	// occurs one time, for example, despite multiple external calling.
	initializationOnlyOneTime sync.Once

	// Protected by the pendingMapsMutex
	pendingMapsMutex        sync.RWMutex
	pendingResponses        map[string]time.Time
	pendingRequestedObjects map[string][]chainhash.Hash
}

// Disconnect stops the stall handling functionality from continuously
// running and tries to cleanup existing information used to keep
// track of incoming messaging.
func (sh *BitcoinStallHandler) Disconnect() {
	atomic.SwapInt32(&sh.quit, 3)
}

// disconnectAutomatically provides an automated implementation of the
// disconnection of the stall handling functionality from the corresponding
// Peer.
func (sh *BitcoinStallHandler) disconnectAutomatically() {
	// Wait for the Peer to signal disconnection.
	sh.peer.WaitForDisconnect()
	// Disconnect the stall handling functionality.
	sh.Disconnect()
}

// InitializeStallHandling creates the message queue, among other housekeeping
// functionality.
func (sh *BitcoinStallHandler) InitializeStallHandling(peer *Peer) {

	go func() {
		// Only initialize once.
		sh.initializationOnlyOneTime.Do(func() {
			// Initialize subject Peer and stall control message channel
			sh.peer = peer
			sh.stallControl = make(chan stallControlMsg, stallControlMessageQueueSize)

			// Start the handling functionality to process and determine appropriate
			// action for incoming stall control messages.
			sh.stallControlMessageHandler()
		})
	}()
}

// calculateAndMonitorDeadlineForOutgoingMessage (based on previous function MaybeAddDeadline)
// potentially adds a deadline for the appropriate expected response for the passed wire
// protocol command to the pending responses map.
func (sh *BitcoinStallHandler) handleCalculatingAndMonitoringDeadlineForOutgoingMessage(msg wire.Message) {

	sh.pendingMapsMutex.Lock()
	defer sh.pendingMapsMutex.Unlock()

	// Setup a deadline for each message being sent that expects a response.
	//
	// NOTE: Pings are intentionally ignored here since they are typically
	// sent asynchronously and as a result of a long backlock of messages,
	// such as is typical in the case of initial block download, the
	// response won't be received in time.
	deadline := sh.peer.LocalClock.Now().Add(stallResponseTimeout)
	msgCmd := msg.Command()
	switch msgCmd {
	case wire.CmdVersion:
		// Expects a verack message.
		sh.pendingResponses[wire.CmdVerAck] = deadline

	case wire.CmdMemPool:
		// Expects an inv message.
		sh.pendingResponses[wire.CmdInv] = deadline

		// Placeholder hash for any inventory object of type transaction
		emptyTxHash := (&wire.MsgTx{}).TxHash()
		sh.pendingRequestedObjects[wire.CmdInv] = append(sh.pendingRequestedObjects[wire.CmdInv], emptyTxHash)

		log.Debugf("stallHandler() for peer %s adding a deadline for corrseponding inv message for outgoing %s command.", sh.peer, msgCmd)

	case wire.CmdGetBlocks:
		// Expects an inv message describing at least one block.
		sh.pendingResponses[wire.CmdInv] = deadline

		// Placeholder hash for any inventory object of type block
		emptyBlockHash := (&wire.BlockHeader{}).BlockHash() // chainhash.NewHashFromStr("b")
		sh.pendingRequestedObjects[wire.CmdInv] = append(sh.pendingRequestedObjects[wire.CmdInv], emptyBlockHash)

		log.Debugf("stallHandler() for peer %s adding a deadline for corrseponding inv message for outgoing %s command.", sh.peer, msgCmd)

	case wire.CmdGetData:
		// Expects a block, merkleblock, tx, or notfound message.

		msgGetData, ok := msg.(*wire.MsgGetData)
		if ok != true {
			log.Criticalf("This should not be happening: improper message received by the stallHandler()'s outgoing processing facility.")
			return
		}

		// expectedMsgs keeps counts of expected responses for logging
		var expectedMsgs map[string]int = make(map[string]int)

		// The is a getdata message.
		// Add a deadline corresponding to the expected response message for the type of object being requested
		for _, invItem := range msgGetData.InvList {

			var expectedMsgCmd string

			switch invItem.Type {
			case wire.InvTypeBlock, wire.InvTypeWitnessBlock:
				// We expect a block message (or notfound message)
				expectedMsgCmd = wire.CmdBlock
				expectedMsgs[expectedMsgCmd] = expectedMsgs[expectedMsgCmd] + 1

			case wire.InvTypeFilteredBlock, wire.InvTypeFilteredWitnessBlock:
				// We expect a merkleblock message (or notfound message)
				expectedMsgCmd = wire.CmdMerkleBlock
				expectedMsgs[expectedMsgCmd] = expectedMsgs[expectedMsgCmd] + 1

			case wire.InvTypeTx, wire.InvTypeWitnessTx:
				// We expect a transaction message (or notfound message)
				expectedMsgCmd = wire.CmdTx
				expectedMsgs[expectedMsgCmd] = expectedMsgs[expectedMsgCmd] + 1
			}
			// [Policy consideration]: If there is already a deadline for this command in pendingResponses,
			// should we leave it as-is?
			// [Possible answer]: No.  If there are multiple commands issued simultaneously,
			// we may need to reset the deadline to avoid stalling after receiving
			// some of them, while the others are still being issued by the remote
			// connection.
			sh.pendingResponses[expectedMsgCmd] = deadline
			sh.pendingRequestedObjects[expectedMsgCmd] = append(sh.pendingRequestedObjects[expectedMsgCmd], invItem.Hash)
		}

		log.Debugf("stallHandler(), processing outgoing message %s for peer %s, adding a deadline for the following command vector: ", msgCmd, sh.peer, expectedMsgs)

	case wire.CmdGetHeaders:
		// Expects a headers message.  Use a longer deadline since it
		// can take a while for the remote peer to load all of the
		// headers.
		deadline = sh.peer.LocalClock.Now().Add(stallResponseTimeout * 3)
		sh.pendingResponses[wire.CmdHeaders] = deadline

		log.Debugf("stallHandler() for peer %s adding a deadline for corrseponding headers message for outgoing %s command.", sh.peer, msgCmd)
	}
}

// ProcessStallControlMessage processes stall handler control messages by adding
// them to the channel containing messages related to pending processing
// of messaging, starting, and stopping.
func (sh *BitcoinStallHandler) ProcessStallControlMessage(msg *stallControlMsg) {

	// Prevent blocking
	select {
	case sh.stallControl <- *msg:
		return
	default:
		log.Debug("Stall handler for peer", sh.peer, "not ready for message handling")
	}
}

func (sh *BitcoinStallHandler) handleTickingInterval() {

	sh.pendingMapsMutex.Lock()
	defer sh.pendingMapsMutex.Unlock()

	now := sh.peer.LocalClock.Now()

	// Disconnect the peer if any of the pending responses
	// don't arrive by their adjusted deadline.
	for command, deadline := range sh.pendingResponses {
		if now.Before(deadline) {
			continue
		}

		log.Infof("Peer %s appears to be stalled or "+
			"misbehaving, %s timeout -- "+
			"disconnecting", sh.peer, command)
		sh.peer.Disconnect()
		break
	}
}

func (sh *BitcoinStallHandler) handleIncomingMessage(msg *stallControlMsg) {

	sh.pendingMapsMutex.Lock()
	defer sh.pendingMapsMutex.Unlock()

	switch msgCmd := msg.message.Command(); msgCmd {
	case wire.CmdBlock, wire.CmdMerkleBlock, wire.CmdTx:
		// Calculate the hash of the object using the appropriate method
		// for the object type
		var objHash chainhash.Hash
		switch msg := msg.message.(type) {
		case *wire.MsgBlock:
			objHash = msg.Header.BlockHash()
		case *wire.MsgMerkleBlock:
			objHash = msg.Header.BlockHash()
		case *wire.MsgTx:
			// Note that this is msg.TxHash() -- not msg.WitnessHash() -- for both wire.InvTypeTx and wire.InvTypeWitnessTx.
			objHash = msg.TxHash()
		default:
			log.Criticalf("This should not be happening: stallHandler() for Peer %s handler: unhandled message type", sh.peer)
		}

		var countOfHashesFound int
		sh.pendingRequestedObjects[msgCmd], countOfHashesFound = sh.removeHashesFromUnderlyingArray(sh.pendingRequestedObjects[msgCmd], objHash)

		// Only remove the single, shared deadline for this object type if there are
		// no pending requested objects of this type remaining.
		if len(sh.pendingRequestedObjects[msgCmd]) == 0 {
			delete(sh.pendingResponses, msgCmd)
		} else if countOfHashesFound > 0 {
			// We found a matching object, and there are still pending requested objects
			// of this type, so reset the single, shared deadline for this object type.
			sh.pendingResponses[msgCmd] = sh.peer.LocalClock.Now().Add(stallResponseTimeout)
		}

		log.Debugf("stallHandler() removing a deadline for a %s message for Peer %s, pendingResponses: %s, len(pendingRequestedObjects[%s]: %d", msgCmd, sh.peer, sh.pendingResponses, msgCmd, len(sh.pendingRequestedObjects[msgCmd]))

	case wire.CmdInv:
		msgInv, ok := msg.message.(*wire.MsgInv)
		if ok != true {
			log.Criticalf("This should not be happening: stallHandler() for Peer %s handler: unhandled message type", sh.peer)
		}

		// If the inventory message is empty, this might satisfy a corresponding deadline for a mempool command
		emptyTxHash := (&wire.MsgTx{}).TxHash()
		if len(msgInv.InvList) == 0 {
			var countOfHashesRemoved int
			sh.pendingRequestedObjects[wire.CmdInv], countOfHashesRemoved = sh.removeHashesFromUnderlyingArray(sh.pendingRequestedObjects[wire.CmdInv], emptyTxHash)
			// The inventory message is empty, and we were expecting transaction inventory corresponding
			// to an outgoing mempool command.  Count this empty inventory message as satisfactory, as the
			// mempool could be empty.
			if countOfHashesRemoved > 0 {
				if len(sh.pendingRequestedObjects[wire.CmdInv]) > 0 {
					// Renew the deadline
					sh.pendingResponses[wire.CmdInv] = sh.peer.LocalClock.Now().Add(stallResponseTimeout)
				} else {
					// Remove the deadline
					delete(sh.pendingResponses, msgCmd)
				}
				log.Debugf("stallHandler() removing a deadline for a %s message (empty inv satisfying outoing mempool command) for Peer %s, pendingResponses: %s, len(pendingRequestedObjects[%s]: %d", msgCmd, sh.peer, sh.pendingResponses, msgCmd, len(sh.pendingRequestedObjects[msgCmd]))
				break
			}
		}

		// For each received inventory vector, remove the corresponding entry from pendingRequestedObjects.
		emptyBlockHash := (&wire.MsgBlock{}).BlockHash()
		var countOfHashesRemoved int
		for _, invVect := range msgInv.InvList {
			// As of this version of btcd, getblocks and mempool are the only commands in response to which we insist on receiving
			// an inv message.  In particular, for getblocks, we insist on an inv message containing an inventory object of type block,
			// and for mempool, we insist on an inv message containing an inventory object of type transaction.
			// As a result, if the current inventory vector is of type block or message, we count it as satisfying the expected
			// response for the getblocks or mempool command, respectively.
			var instantaneousRemovalCount int
			if invVect.Type == wire.InvTypeBlock || invVect.Type == wire.InvTypeWitnessBlock {
				// If we receive a block inventory vector and were expecting block inventory, remove the block placeholder
				// from the pendingRequestsObjects map.
				sh.pendingRequestedObjects[wire.CmdInv], instantaneousRemovalCount = sh.removeHashesFromUnderlyingArray(sh.pendingRequestedObjects[wire.CmdInv], emptyBlockHash)
				countOfHashesRemoved = countOfHashesRemoved + instantaneousRemovalCount
			} else if invVect.Type == wire.InvTypeTx || invVect.Type == wire.InvTypeWitnessTx {
				// If we receive a transaction inventory vector and were expecting transaction inventory, remove the
				// transaction placeholder from the pendingRequestedResponses map.
				sh.pendingRequestedObjects[wire.CmdInv], instantaneousRemovalCount = sh.removeHashesFromUnderlyingArray(sh.pendingRequestedObjects[wire.CmdInv], emptyTxHash)
				countOfHashesRemoved = countOfHashesRemoved + instantaneousRemovalCount
			}
		}

		// Now, remove or reset the stall handler's deadline for an expected inv command, if appropriate.
		if len(sh.pendingRequestedObjects[wire.CmdInv]) == 0 {
			// If there are no remaining expectations for an incoming inv command, remove the corresponding deadline.
			delete(sh.pendingResponses, msgCmd)
			log.Debugf("stallHandler() removing a deadline for a %s message for Peer %s, pendingResponses: %s, len(pendingRequestedObjects[%s]: %d", msgCmd, sh.peer, sh.pendingResponses, msgCmd, len(sh.pendingRequestedObjects[msgCmd]))
		} else if countOfHashesRemoved > 0 {
			// If there are remaining expections for an incoming inv command, and we also received something
			// relevant in this iteration, renew the corresponding deadline.
			sh.pendingResponses[wire.CmdInv] = sh.peer.LocalClock.Now().Add(stallResponseTimeout)
			log.Debugf("stallHandler() renewing a deadline for a %s message for Peer %s, pendingResponses: %s, len(pendingRequestedObjects[%s]: %d", msgCmd, sh.peer, sh.pendingResponses, msgCmd, len(sh.pendingRequestedObjects[msgCmd]))
		}

	case wire.CmdNotFound:
		// The peer has indicated that it did not find one or more objects.  As a result, if we requested
		// any of these objects, this message should satisfy the timeout (stall) deadline.
		// [Policy consideration]: In some circumstances, this may be an indication of a misbehaving peer (e.g., if
		// the peer advertised the object as available).  Should we take additional action in any such cases?
		msgNotFound, ok := msg.message.(*wire.MsgNotFound)
		if ok != true {
			log.Criticalf("This should not be happening: stallHandler() for Peer %s handler: unhandled message type", sh.peer)
		}

		// Make a list of object hashes in the inventory vector
		var invHashesToRemove []chainhash.Hash
		for _, invVectToRemove := range msgNotFound.InvList {
			invHashesToRemove = append(invHashesToRemove, invVectToRemove.Hash)
		}

		// Loop: For all types for which we have requests pending
		for msgType := range sh.pendingRequestedObjects {

			var countOfHashesFound int
			sh.pendingRequestedObjects[msgType], countOfHashesFound = sh.removeHashesFromUnderlyingArray(sh.pendingRequestedObjects[msgType], invHashesToRemove...)

			// Remove the deadline if there are no pending requested objects of this type remaining,
			// and alternatively, renew the timeout if we received an object we were expecting.
			if len(sh.pendingRequestedObjects[msgType]) == 0 {
				delete(sh.pendingResponses, msgType)
			} else if countOfHashesFound > 0 {
				// We found a matching object, so reset the (single, shared) deadline for this object type.
				sh.pendingResponses[msgType] = sh.peer.LocalClock.Now().Add(stallResponseTimeout)
				log.Tracef("stallHandler() removing a deadline for a %s message for Peer %s", msgCmd, sh.peer)
			}
		}

	default:
		delete(sh.pendingResponses, msgCmd)
		// log.Debugf("stallHandler() removing a deadline for a %s message for Peer %s, pendingResponses: %s, len(pendingRequestedObjects[%s]: %d", msgCmd, sh.peer, pendingResponses, msgCmd, len(pendingRequestedObjects[msgCmd]))

	}

}

// start handles stall detection for the peer.  This entails keeping
// track of expected responses and assigning them deadlines while accounting for
// the time spent in callbacks.  It must be run as a goroutine.
func (sh *BitcoinStallHandler) stallControlMessageHandler() {

	// Wait for peer to signal disconnection
	go sh.disconnectAutomatically()

	// pendingResponses tracks the expected response deadline times.
	sh.pendingResponses = make(map[string]time.Time)
	// pendingRequestedObjects tracks (by object type) the inventory objects we have requested from this peer
	sh.pendingRequestedObjects = make(map[string][]chainhash.Hash)

	// stallTicker is used to periodically check pending responses that have
	// exceeded the expected deadline and disconnect the peer due to
	// stalling.
	stallTicker := sh.peer.LocalClock.NewTicker(stallTickInterval)
	defer stallTicker.Stop()

	// ioStopped is used to detect when both the input and output handler
	// goroutines are done.
	var ioStopped int32
out:
	for {
		// Check if we are disconnecting, and if so, exit the for loop
		// corresponding to handling functionality.
		ioStopped = atomic.LoadInt32(&sh.quit)
		if ioStopped > 1 {
			break out
		}
		// Proceed to processing of the next pending stall control
		// functionality message.
		select {
		case msg := <-sh.stallControl:
			switch msg.command {
			case sccSendMessage:
				// Add a deadline for the expected response
				// message if needed.
				sh.handleCalculatingAndMonitoringDeadlineForOutgoingMessage(msg.message)

			case sccReceiveMessage:
				// Remove received messages from the expected
				// response map.  Since certain commands expect
				// one of a group of responses, remove
				// everything in the expected group accordingly.
				sh.handleIncomingMessage(&msg)

			}

		case <-stallTicker.Chan():
			// Calculate the offset to apply to the deadline based
			// on how long the handlers have taken to execute since
			// the last tick.
			sh.handleTickingInterval()

		}
	}

	// Drain any wait channels before going away so there is nothing left
	// waiting on this goroutine.
cleanup:
	for {
		select {
		case <-sh.stallControl:
		default:
			break cleanup
		}
	}
	log.Tracef("Peer stallHandler() done for peer %s", sh.peer)
}

// removeHashesFromUnderlyingArray removes one or more hashes from the array underlying
// the subjectSlice and returns a new slice and the number of hashes removed.
func (sh *BitcoinStallHandler) removeHashesFromUnderlyingArray(subjectSlice []chainhash.Hash, hashesToRemove ...chainhash.Hash) ([]chainhash.Hash, int) {

	var modifiedSlice []chainhash.Hash
	var countOfHashesRemoved int = 0

	// modifiedSlice is a temporary slice to hold an updated subjectSlice.
	// Caution is advised in updating this logic, as the modified slice shares the same underlying array as the slice it is
	// updating, by way of passing through the original slice item-by-item and only appending to the modified slice items that
	// should remain in the updated slice.
	modifiedSlice = subjectSlice[:0]

subjectSliceIteration:
	for _, hash := range subjectSlice {
		for _, hashToRemove := range hashesToRemove {
			if hash.IsEqual(&hashToRemove) {
				countOfHashesRemoved = countOfHashesRemoved + 1
				continue subjectSliceIteration
			}
		}
		modifiedSlice = append(modifiedSlice, hash)
	}

	return modifiedSlice, countOfHashesRemoved
}
