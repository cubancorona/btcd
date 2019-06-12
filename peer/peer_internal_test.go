package peer

import (
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/go-socks/socks"
)

// conn mocks a network connection by implementing the net.Conn interface.  It
// is used to test peer connection without actually opening a network
// connection.
type conn struct {
	io.Reader
	io.Writer
	io.Closer

	// local network, address for the connection.
	lnet, laddr string

	// remote network, address for the connection.
	rnet, raddr string

	// mocks socks proxy if true
	proxy bool
}

// LocalAddr returns the local address for the connection.
func (c conn) LocalAddr() net.Addr {
	return &addr{c.lnet, c.laddr}
}

// Remote returns the remote address for the connection.
func (c conn) RemoteAddr() net.Addr {
	if !c.proxy {
		return &addr{c.rnet, c.raddr}
	}
	host, strPort, _ := net.SplitHostPort(c.raddr)
	port, _ := strconv.Atoi(strPort)
	return &socks.ProxiedAddr{
		Net:  c.rnet,
		Host: host,
		Port: port,
	}
}

// Close handles closing the connection.
func (c conn) Close() error {
	if c.Closer == nil {
		return nil
	}
	return c.Closer.Close()
}

func (c conn) SetDeadline(t time.Time) error      { return nil }
func (c conn) SetReadDeadline(t time.Time) error  { return nil }
func (c conn) SetWriteDeadline(t time.Time) error { return nil }

// addr mocks a network address
type addr struct {
	net, address string
}

func (m addr) Network() string { return m.net }
func (m addr) String() string  { return m.address }

// pipe turns two mock connections into a full-duplex connection similar to
// net.Pipe to allow pipe's with (fake) addresses.
func pipe(c1, c2 *conn) (*conn, *conn) {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()

	c1.Writer = w1
	c1.Closer = w1
	c2.Reader = r1
	c1.Reader = r2
	c2.Writer = w2
	c2.Closer = w2

	return c1, c2
}

type stallTestCase struct {
	request     wire.Message
	response    wire.Message
	shouldStall bool
	afterTime   time.Duration
}

// Tests that the stallHandler() is tracking objects
func TestStallHandler(t *testing.T) {

	var testCase stallTestCase

	// Ask peer to getdata
	var emptyBlockHeaderHash *chainhash.Hash
	var err error
	emptyBlockHeaderHash, err = chainhash.NewHashFromStr("64f0387fc6daa6555c013e1e78c775f75b51149d948d0f681554705b791116ce")
	if err != nil {
		t.Fatalf("chainhash.NewHashFromStr: unexpected err - %v\n", err)
	}
	var msgGetData wire.Message = &wire.MsgGetData{InvList: []*wire.InvVect{wire.NewInvVect(wire.InvTypeBlock, &chainhash.Hash{})}}
	msgGetData = &wire.MsgGetData{InvList: []*wire.InvVect{wire.NewInvVect(wire.InvTypeBlock, emptyBlockHeaderHash)}}
	testCase.request = msgGetData

	// Respond with correct data
	var validBlockMsg *wire.MsgBlock
	validBlockMsg = wire.NewMsgBlock(&wire.BlockHeader{})
	t.Log("Empty block header hash: ", validBlockMsg.BlockHash())
	testCase.response = validBlockMsg

	// Set the stall timeout and expected outcome
	testCase.afterTime = 40 * time.Second
	testCase.shouldStall = false

	// Run test case
	runStallTestCase(t, testCase)

	// TEMPORARY: This should FAIL the test
	testCase.shouldStall = true
	//runStallTestCase(t, testCase)

	var stallTestCases []stallTestCase

	stallTestCases = append(stallTestCases, stallTestCase{
		request:     &wire.MsgGetData{InvList: []*wire.InvVect{wire.NewInvVect(wire.InvTypeBlock, &chainhash.Hash{})}},
		response:    wire.NewMsgBlock(&wire.BlockHeader{}),
		afterTime:   40 * time.Second,
		shouldStall: true,
	})
	//var emptyBlockHeaderHash *chainhash.Hash
	//var err error
	emptyBlockHeaderHash, err = chainhash.NewHashFromStr("64f0387fc6daa6555c013e1e78c775f75b51149d948d0f681554705b791116ce")
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

	runStallTestCase(t, stallTestCases[0])
	runStallTestCase(t, stallTestCases[1])
	runStallTestCase(t, stallTestCases[2])
	runStallTestCase(t, stallTestCases[3])
	runStallTestCase(t, stallTestCases[4])

}

func runStallTestCase(t *testing.T, testCase stallTestCase) {

	onVersionCalled := make(chan struct{})
	peerCfg := &Config{
		UserAgentName:     "peer",
		UserAgentVersion:  "1.0",
		UserAgentComments: []string{"comment"},
		ChainParams:       &chaincfg.MainNetParams,
		Services:          0,
		TrickleInterval:   time.Second * 10,
		Listeners: MessageListeners{
			OnVersion: func(p *Peer, msg *wire.MsgVersion) *wire.MsgReject {
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

	p, err := NewOutboundPeer(peerCfg, "10.0.0.1:8333")
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
			t.Logf("Received message [%s]", msg.Command())
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

	// Read VerAck message sent to remote peer
	select {
	case msg := <-outboundMessages:
		if _, ok := msg.(*wire.MsgVerAck); !ok {
			t.Logf("Expected verack message, got [%s]", msg.Command())
		}
		//t.Fatalf("Received messages.")
	case <-time.After(5 * time.Second):
		t.Fatal("Peer did not send verack message")
	}

	// Send request to remote peer
	doneChan := make(chan struct{}, 1)
	p.QueueMessage(testCase.request, doneChan)

	// Read request sent to remote peer
	select {
	case msg := <-outboundMessages:
		if _, ok := msg.(*wire.MsgGetData); !ok {
			t.Logf("Expected getdata message, got [%s]", msg.Command())
		}
		//t.Fatalf("Received messages.")
	case <-time.After(time.Second):
		t.Fatal("Peer did not send getdata message")
	}

	// Block until sending above request to remote peer is complete
	<-doneChan

	// Send response from remote peer
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

	// Advance the peer's local clock
	relativeClock, ok := p.LocalClock.(clockwork.FakeClock)
	if !ok {
		t.Fatal("relativeClock error")
	}
	time.Sleep(time.Second)
	relativeClock.Advance(testCase.afterTime)
	time.Sleep(time.Second)

	// Check whether the peer is disconnected, and whether the result is expected
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
