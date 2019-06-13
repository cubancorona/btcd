package peer_test

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/peer"
	"github.com/btcsuite/btcd/wire"
)

type stallTestCase struct {
	request     wire.Message
	response    wire.Message
	shouldStall bool
	afterTime   time.Duration
}

// Tests that the stallHandler() is tracking objects
func TestStallHandler(t *testing.T) {

	var stallTestCases []stallTestCase

	stallTestCases = append(stallTestCases, stallTestCase{
		request:     &wire.MsgGetData{InvList: []*wire.InvVect{wire.NewInvVect(wire.InvTypeBlock, &chainhash.Hash{})}},
		response:    wire.NewMsgBlock(&wire.BlockHeader{}),
		afterTime:   40 * time.Second,
		shouldStall: true,
	})
	var emptyBlockHeaderHash *chainhash.Hash
	var err error
	emptyBlockHeaderHash, err = chainhash.NewHashFromStr("64f0387fc6daa6555c013e1e78c775f75b51149d948d0f681554705b791116ce")
	if err != nil {
		t.Fatal("Unexpected error ", err)
	}
	stallTestCases = append(stallTestCases, stallTestCase{
		request:     &wire.MsgGetData{InvList: []*wire.InvVect{wire.NewInvVect(wire.InvTypeBlock, emptyBlockHeaderHash)}},
		response:    wire.NewMsgBlock(&wire.BlockHeader{}),
		afterTime:   40 * time.Second,
		shouldStall: false,
	})
	stallTestCases = append(stallTestCases, stallTestCase{
		request:     &wire.MsgGetHeaders{ProtocolVersion: wire.ProtocolVersion},
		response:    wire.NewMsgHeaders(),
		afterTime:   40 * time.Second,
		shouldStall: false,
	})
	stallTestCases = append(stallTestCases, stallTestCase{
		request:     &wire.MsgGetBlocks{ProtocolVersion: wire.ProtocolVersion},
		response:    wire.NewMsgInv(),
		afterTime:   40 * time.Second,
		shouldStall: true,
	})
	var singleBlockInv *wire.MsgInv = wire.NewMsgInv()
	singleBlockInv.AddInvVect(&wire.InvVect{Type: wire.InvTypeBlock})
	stallTestCases = append(stallTestCases, stallTestCase{
		request:     &wire.MsgGetBlocks{ProtocolVersion: wire.ProtocolVersion},
		response:    singleBlockInv,
		afterTime:   40 * time.Second,
		shouldStall: false,
	})
	stallTestCases = append(stallTestCases, stallTestCase{
		request:     &wire.MsgGetData{InvList: []*wire.InvVect{wire.NewInvVect(wire.InvTypeBlock, emptyBlockHeaderHash)}},
		response:    wire.NewMsgNotFound(),
		afterTime:   40 * time.Second,
		shouldStall: true,
	})
	var msgNotFoundEmptyBlockHeader *wire.MsgNotFound = wire.NewMsgNotFound()
	msgNotFoundEmptyBlockHeader.AddInvVect(wire.NewInvVect(wire.InvTypeBlock, emptyBlockHeaderHash))
	stallTestCases = append(stallTestCases, stallTestCase{
		request:     &wire.MsgGetData{InvList: []*wire.InvVect{wire.NewInvVect(wire.InvTypeBlock, emptyBlockHeaderHash)}},
		response:    msgNotFoundEmptyBlockHeader,
		afterTime:   40 * time.Second,
		shouldStall: false,
	})

	runStallTestCase(t, stallTestCases[0])
	runStallTestCase(t, stallTestCases[1])
	runStallTestCase(t, stallTestCases[2])
	runStallTestCase(t, stallTestCases[3])
	runStallTestCase(t, stallTestCases[4])
	runStallTestCase(t, stallTestCases[5])
	runStallTestCase(t, stallTestCases[6])

}

func runStallTestCase(t *testing.T, testCase stallTestCase) {

	onVersionCalled := make(chan struct{})
	peerCfg := &peer.Config{
		UserAgentName:     "peer",
		UserAgentVersion:  "1.0",
		UserAgentComments: []string{"comment"},
		ChainParams:       &chaincfg.MainNetParams,
		Services:          0,
		TrickleInterval:   time.Second * 10,
		Listeners: peer.MessageListeners{
			OnVersion: func(p *peer.Peer, msg *wire.MsgVersion) *wire.MsgReject {
				go func() { onVersionCalled <- struct{}{} }()
				return nil
			},
		},
	}

	localNA := wire.NewNetAddressIPPort(
		net.ParseIP("10.0.0.1"),
		uint16(8333),
		wire.SFNodeNetwork,
	)
	remoteNA := wire.NewNetAddressIPPort(
		net.ParseIP("10.0.0.2"),
		uint16(8333),
		wire.SFNodeNetwork,
	)
	localConn, remoteConn := pipe(
		&conn{laddr: "10.0.0.1:8333", raddr: "10.0.0.2:8333"},
		&conn{laddr: "10.0.0.2:8333", raddr: "10.0.0.1:8333"},
	)

	p, err := peer.NewOutboundPeer(peerCfg, "10.0.0.1:8333")
	if err != nil {
		t.Fatalf("NewOutboundPeer: unexpected err - %v\n", err)
	}
	// Setup the peer's local clock as a fake clock for testing
	p.LocalClock = clockwork.NewFakeClockAt(time.Now())
	// Attach the pipe
	p.AssociateConnection(localConn)

	// Read messages incoming to remote peer into a channel
	outboundMessages := make(chan wire.Message)
	go func() {
		for {
			_, msg, _, err := wire.ReadMessageN(
				remoteConn,
				p.ProtocolVersion(),
				peerCfg.ChainParams.Net,
			)
			if err == io.EOF {
				close(outboundMessages)
				return
			}
			if err != nil {
				t.Errorf("Error reading message from local node: %v\n", err)
				return
			}

			t.Logf("runTestCase: Remote peer received message: [%s]:[%s]", msg.Command(), msg)
			outboundMessages <- msg
		}
	}()

	// Read version message sent to remote peer
	select {
	case msg := <-outboundMessages:
		if _, ok := msg.(*wire.MsgVersion); !ok {
			t.Logf("Expected version message, got [%s]", msg.Command())
		} else {
			t.Logf("Remote peer processed received message [%s]", msg.Command())
		}
	case <-time.After(time.Second):
		t.Fatal("Peer did not send version message")
	}

	// Send version message from remote peer
	validVersionMsg := wire.NewMsgVersion(remoteNA, localNA, 0, 0)
	validVersionMsg.ProtocolVersion = int32(wire.ProtocolVersion)

	_, err = wire.WriteMessageN(
		remoteConn.Writer,
		validVersionMsg,
		uint32(validVersionMsg.ProtocolVersion),
		peerCfg.ChainParams.Net,
	)
	if err != nil {
		t.Fatalf("wire.WriteMessageN: unexpected err - %v\n", err)
	}

	// Read verack message sent to remote peer
	select {
	case msg := <-outboundMessages:
		if _, ok := msg.(*wire.MsgVerAck); !ok {
			t.Logf("Expected verack message, got [%s]", msg.Command())
		} else {
			t.Logf("Remote peer processed received message [%s]", msg.Command())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Peer did not send verack message")
	}

	// Send testCase request to remote peer
	doneChan := make(chan struct{}, 1)
	p.QueueMessage(testCase.request, doneChan)

	// Read request sent to remote peer
	select {
	case msg := <-outboundMessages:
		if _, ok := msg.(*wire.MsgGetData); !ok {
			t.Logf("Expected getdata message, got [%s]", msg.Command())
		} else {
			t.Logf("Remote peer processed received message [%s]", msg.Command())
		}
	case <-time.After(time.Second):
		t.Fatal("Peer did not send getdata message")
	}

	// Block until sending above testCase request to remote peer is complete
	<-doneChan

	// Send testCase response from remote peer
	_, err = wire.WriteMessageN(
		remoteConn.Writer,
		testCase.response,
		wire.ProtocolVersion,
		peerCfg.ChainParams.Net,
	)
	if err != nil {
		t.Fatalf("wire.WriteMessageN: unexpected err - %v\n", err)
	}

	// Monitor peer for disconnection (as is expected behavior in case of detected stall)
	disconnected := make(chan struct{})
	go func() {
		p.WaitForDisconnect()
		disconnected <- struct{}{}
	}()

	// Advance the peer's local clock, including time before and after to ensure synchronicity
	relativeClock, ok := p.LocalClock.(clockwork.FakeClock)
	if !ok {
		t.Fatal("relativeClock error")
	}
	time.Sleep(time.Second)
	relativeClock.Advance(testCase.afterTime)
	time.Sleep(time.Second)

	// Check whether the peer is disconnected, and whether this is expected
	select {
	case <-disconnected:
		close(disconnected)
		if !testCase.shouldStall {
			t.Fatal("Peer improperly disconnected where we expect it not to detect a stall")
		}
	default:
		if testCase.shouldStall {
			t.Fatal("Peer did not disconnect where we expected it to detect a stall")
		}
	}

	// Expect a call to the peer's OnVersion listener
	select {
	case <-onVersionCalled:
		t.Log("OnVersion listener called for peer")

	default:
		close(onVersionCalled)
		t.Log("No call to OnVersion listener detected")
	}
}
