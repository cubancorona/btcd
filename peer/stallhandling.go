package peer

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

const stallControlMessageQueueSize int = 100

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
	MessageHandling(msg *stallControlMsg)
}

// BitcoinStallHandler handles stalling functionality for the Bitcoin
// communication network.
type BitcoinStallHandler struct {
	// Peer object
	peer *Peer

	// Stall control message channel
	stallControl chan stallControlMsg

	// Atomic variable
	quit int32

	// Synchronization variables
	initializationOnlyOneTime sync.Once
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
	sh.peer.WaitForDisconnect()
	sh.Disconnect()
}

// InitializeStallHandling creates the message queue, among other housekeeping
// functionality.
func (sh *BitcoinStallHandler) InitializeStallHandling(peer *Peer) {

	sh.initializationOnlyOneTime.Do(func() {
		sh.peer = peer
		sh.stallControl = make(chan stallControlMsg, stallControlMessageQueueSize)

		go sh.start()
	})
}

// MaybeAddDeadline potentially adds a deadline for the appropriate expected
// response for the passed wire protocol command to the pending responses map.
func (sh *BitcoinStallHandler) maybeAddDeadline(pendingResponses map[string]time.Time, pendingRequestedObjects map[string][]chainhash.Hash, msg wire.Message) {
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
		pendingResponses[wire.CmdVerAck] = deadline

	case wire.CmdMemPool:
		// Expects an inv message.
		pendingResponses[wire.CmdInv] = deadline

		// Placeholder hash for any inventory object of type transaction
		emptyTxHash := (&wire.MsgTx{}).TxHash()
		pendingRequestedObjects[wire.CmdInv] = append(pendingRequestedObjects[wire.CmdInv], emptyTxHash)

		log.Debugf("stallHandler() for peer %s adding a deadline for corrseponding inv message for outgoing %s command.", sh.peer, msgCmd)

	case wire.CmdGetBlocks:
		// Expects an inv message describing at least one block.
		pendingResponses[wire.CmdInv] = deadline

		// Placeholder hash for any inventory object of type block
		emptyBlockHash := (&wire.BlockHeader{}).BlockHash() // chainhash.NewHashFromStr("b")
		pendingRequestedObjects[wire.CmdInv] = append(pendingRequestedObjects[wire.CmdInv], emptyBlockHash)

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
			// Question(cc): If there is already a deadline for this command in pendingResponses, should we leave it as-is?
			// Answer: No.  If there are multiple commands issued simultaneously,
			// we may need to reset the deadline to avoid stalling after receiving
			// some of them, while the others are still being issued by the remote
			// connection.
			pendingResponses[expectedMsgCmd] = deadline
			pendingRequestedObjects[expectedMsgCmd] = append(pendingRequestedObjects[expectedMsgCmd], invItem.Hash)
		}

		log.Debugf("stallHandler(), processing outgoing message %s for peer %s, adding a deadline for the following command vector: ", msgCmd, sh.peer, expectedMsgs)

	case wire.CmdGetHeaders:
		// Expects a headers message.  Use a longer deadline since it
		// can take a while for the remote peer to load all of the
		// headers.
		deadline = sh.peer.LocalClock.Now().Add(stallResponseTimeout * 3)
		pendingResponses[wire.CmdHeaders] = deadline

		log.Debugf("stallHandler() for peer %s adding a deadline for corrseponding headers message for outgoing %s command.", sh.peer, msgCmd)
	}
}

// MessageHandling processes stall handler control messages by adding
// them to the channel containing messages related to pending processing
// of messaging, starting, and stopping.
func (sh *BitcoinStallHandler) MessageHandling(msg *stallControlMsg) {

	// Prevent blocking
	select {
	case sh.stallControl <- *msg:
		return
	default:
		log.Debug("Stall handler for peer", sh.peer, "not ready for message handling")
	}
}

// start handles stall detection for the peer.  This entails keeping
// track of expected responses and assigning them deadlines while accounting for
// the time spent in callbacks.  It must be run as a goroutine.
func (sh *BitcoinStallHandler) start() {

	// Wait for peer to signal disconnection
	go sh.disconnectAutomatically()

	// These variables are used to adjust the deadline times forward by the
	// time it takes callbacks to execute.  This is done because new
	// messages aren't read until the previous one is finished processing
	// (which includes callbacks), so the deadline for receiving a response
	// for a given message must account for the processing time as well.
	var handlerActive bool
	var handlersStartTime time.Time
	var deadlineOffset time.Duration

	// pendingResponses tracks the expected response deadline times.
	pendingResponses := make(map[string]time.Time)
	// pendingRequestedObjects tracks (by object type) the inventory objects we have requested from this peer
	var pendingRequestedObjects map[string][]chainhash.Hash = make(map[string][]chainhash.Hash)

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
				sh.maybeAddDeadline(pendingResponses,
					pendingRequestedObjects,
					msg.message)

			case sccReceiveMessage:
				// Remove received messages from the expected
				// response map.  Since certain commands expect
				// one of a group of responses, remove
				// everything in the expected group accordingly.
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
					pendingRequestedObjects[msgCmd], countOfHashesFound = sh.removeHashesFromUnderlyingArray(pendingRequestedObjects[msgCmd], objHash)

					// Only remove the single, shared deadline for this object type if there are
					// no pending requested objects of this type remaining.
					if len(pendingRequestedObjects[msgCmd]) == 0 {
						delete(pendingResponses, msgCmd)
					} else if countOfHashesFound > 0 {
						// We found a matching object, and there are still pending requested objects
						// of this type, so reset the single, shared deadline for this object type.
						pendingResponses[msgCmd] = sh.peer.LocalClock.Now().Add(stallResponseTimeout)
					}

					log.Debugf("stallHandler() removing a deadline for a %s message for Peer %s, pendingResponses: %s, len(pendingRequestedObjects[%s]: %d", msgCmd, sh.peer, pendingResponses, msgCmd, len(pendingRequestedObjects[msgCmd]))

				case wire.CmdInv:
					msgInv, ok := msg.message.(*wire.MsgInv)
					if ok != true {
						log.Criticalf("This should not be happening: stallHandler() for Peer %s handler: unhandled message type", sh.peer)
					}

					// If the inventory message is empty, this might satisfy a corresponding deadline for a mempool command
					emptyTxHash := (&wire.MsgTx{}).TxHash()
					if len(msgInv.InvList) == 0 {
						var countOfHashesRemoved int
						pendingRequestedObjects[wire.CmdInv], countOfHashesRemoved = sh.removeHashesFromUnderlyingArray(pendingRequestedObjects[wire.CmdInv], emptyTxHash)
						// The inventory message is empty, and we were expecting transaction inventory corresponding
						// to an outgoing mempool command.  Count this empty inventory message as satisfactory, as the
						// mempool could be empty.
						if countOfHashesRemoved > 0 {
							if len(pendingRequestedObjects[wire.CmdInv]) > 0 {
								// Renew the deadline
								pendingResponses[wire.CmdInv] = sh.peer.LocalClock.Now().Add(stallResponseTimeout)
							} else {
								// Remove the deadline
								delete(pendingResponses, msgCmd)
							}
							log.Debugf("stallHandler() removing a deadline for a %s message (empty inv satisfying outoing mempool command) for Peer %s, pendingResponses: %s, len(pendingRequestedObjects[%s]: %d", msgCmd, sh.peer, pendingResponses, msgCmd, len(pendingRequestedObjects[msgCmd]))
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
							pendingRequestedObjects[wire.CmdInv], instantaneousRemovalCount = sh.removeHashesFromUnderlyingArray(pendingRequestedObjects[wire.CmdInv], emptyBlockHash)
							countOfHashesRemoved = countOfHashesRemoved + instantaneousRemovalCount
						} else if invVect.Type == wire.InvTypeTx || invVect.Type == wire.InvTypeWitnessTx {
							// If we receive a transaction inventory vector and were expecting transaction inventory, remove the
							// transaction placeholder from the pendingRequestedResponses map.
							pendingRequestedObjects[wire.CmdInv], instantaneousRemovalCount = sh.removeHashesFromUnderlyingArray(pendingRequestedObjects[wire.CmdInv], emptyTxHash)
							countOfHashesRemoved = countOfHashesRemoved + instantaneousRemovalCount
						}
					}

					// Now, remove or reset the stall handler's deadline for an expected inv command, if appropriate.
					if len(pendingRequestedObjects[wire.CmdInv]) == 0 {
						// If there are no remaining expectations for an incoming inv command, remove the corresponding deadline.
						delete(pendingResponses, msgCmd)
						log.Debugf("stallHandler() removing a deadline for a %s message for Peer %s, pendingResponses: %s, len(pendingRequestedObjects[%s]: %d", msgCmd, sh.peer, pendingResponses, msgCmd, len(pendingRequestedObjects[msgCmd]))
					} else if countOfHashesRemoved > 0 {
						// If there are remaining expections for an incoming inv command, and we also received something
						// relevant in this iteration, renew the corresponding deadline.
						pendingResponses[wire.CmdInv] = sh.peer.LocalClock.Now().Add(stallResponseTimeout)
						log.Debugf("stallHandler() renewing a deadline for a %s message for Peer %s, pendingResponses: %s, len(pendingRequestedObjects[%s]: %d", msgCmd, sh.peer, pendingResponses, msgCmd, len(pendingRequestedObjects[msgCmd]))
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
					for msgType := range pendingRequestedObjects {

						var countOfHashesFound int
						pendingRequestedObjects[msgType], countOfHashesFound = sh.removeHashesFromUnderlyingArray(pendingRequestedObjects[msgType], invHashesToRemove...)

						// Remove the deadline if there are no pending requested objects of this type remaining,
						// and alternatively, renew the timeout if we received an object we were expecting.
						if len(pendingRequestedObjects[msgType]) == 0 {
							delete(pendingResponses, msgType)
						} else if countOfHashesFound > 0 {
							// We found a matching object, so reset the (single, shared) deadline for this object type.
							pendingResponses[msgType] = sh.peer.LocalClock.Now().Add(stallResponseTimeout)
							log.Tracef("stallHandler() removing a deadline for a %s message for Peer %s", msgCmd, sh.peer)
						}
					}

				default:
					delete(pendingResponses, msgCmd)
					// log.Debugf("stallHandler() removing a deadline for a %s message for Peer %s, pendingResponses: %s, len(pendingRequestedObjects[%s]: %d", msgCmd, sh.peer, pendingResponses, msgCmd, len(pendingRequestedObjects[msgCmd]))

				}
			}

		case <-stallTicker.Chan():
			// Calculate the offset to apply to the deadline based
			// on how long the handlers have taken to execute since
			// the last tick.
			now := sh.peer.LocalClock.Now()
			offset := deadlineOffset
			if handlerActive {
				offset += now.Sub(handlersStartTime)
			}

			// Disconnect the peer if any of the pending responses
			// don't arrive by their adjusted deadline.
			for command, deadline := range pendingResponses {
				if now.Before(deadline.Add(offset)) {
					continue
				}

				log.Infof("Peer %s appears to be stalled or "+
					"misbehaving, %s timeout -- "+
					"disconnecting", sh.peer, command)
				sh.peer.Disconnect()
				break
			}

			// Reset the deadline offset for the next tick.
			deadlineOffset = 0

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
