// Copyright (c) 2015-2016 The btcsuite developers
// Copyright (c) 2016-2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer_test

import (
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/peer"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/go-socks/socks"
	"github.com/jonboulle/clockwork"
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
	// Our connection is made of two one-way pipes, each pipe having a
	// Reader and Writer.  w1 writes to a pipe read by r1, and w2 writes to
	// a pipe read by r2.
	//         peer 1 (c1)  |  peer 2 (c2)
	// Pipe 1:       w1   ---->   r1
	// Pipe 2:       r2   <----   w2
	r1, w1 := io.Pipe() // Pipe 1
	r2, w2 := io.Pipe() // Pipe 2

	// Our first connection, possibly a simulated local connection, reads
	// incoming data presently written to Pipe 2, possibly by a simulated remote connection;
	// it writes outgoing data to Pipe 1 presently to be read, possibly a simulated remote
	// connection.
	c1.Reader = r2
	c1.Writer = w1
	c1.Closer = w1

	// Our second connection, possibly a simulated remote connection in possession of a remote
	// participant, reads incoming data presently written to Pipe 1, possibly by a simulated local
	// connection; it writes outgoing data to Pipe 2 presently to be read, possibly by a simulated
	// local connection.
	c2.Reader = r1
	c2.Writer = w2
	c2.Closer = w2

	return c1, c2
}

// peerStats holds the expected peer stats used for testing peer.
type peerStats struct {
	wantUserAgent       string
	wantServices        wire.ServiceFlag
	wantProtocolVersion uint32
	wantConnected       bool
	wantVersionKnown    bool
	wantVerAckReceived  bool
	wantLastBlock       int32
	wantStartingHeight  int32
	wantLastPingTime    time.Time
	wantLastPingNonce   uint64
	wantLastPingMicros  int64
	wantTimeOffset      int64
	wantBytesSent       uint64
	wantBytesReceived   uint64
	wantWitnessEnabled  bool
}

// testPeer tests the given peer's flags and stats
func testPeer(t *testing.T, p *peer.Peer, s peerStats) {
	if p.UserAgent() != s.wantUserAgent {
		t.Errorf("testPeer: wrong UserAgent - got %v, want %v", p.UserAgent(), s.wantUserAgent)
		return
	}

	if p.Services() != s.wantServices {
		t.Errorf("testPeer: wrong Services - got %v, want %v", p.Services(), s.wantServices)
		return
	}

	if !p.LastPingTime().Equal(s.wantLastPingTime) {
		t.Errorf("testPeer: wrong LastPingTime - got %v, want %v", p.LastPingTime(), s.wantLastPingTime)
		return
	}

	if p.LastPingNonce() != s.wantLastPingNonce {
		t.Errorf("testPeer: wrong LastPingNonce - got %v, want %v", p.LastPingNonce(), s.wantLastPingNonce)
		return
	}

	if p.LastPingMicros() != s.wantLastPingMicros {
		t.Errorf("testPeer: wrong LastPingMicros - got %v, want %v", p.LastPingMicros(), s.wantLastPingMicros)
		return
	}

	if p.VerAckReceived() != s.wantVerAckReceived {
		t.Errorf("testPeer: wrong VerAckReceived - got %v, want %v", p.VerAckReceived(), s.wantVerAckReceived)
		return
	}

	if p.VersionKnown() != s.wantVersionKnown {
		t.Errorf("testPeer: wrong VersionKnown - got %v, want %v", p.VersionKnown(), s.wantVersionKnown)
		return
	}

	if p.ProtocolVersion() != s.wantProtocolVersion {
		t.Errorf("testPeer: wrong ProtocolVersion - got %v, want %v", p.ProtocolVersion(), s.wantProtocolVersion)
		return
	}

	if p.LastBlock() != s.wantLastBlock {
		t.Errorf("testPeer: wrong LastBlock - got %v, want %v", p.LastBlock(), s.wantLastBlock)
		return
	}

	// Allow for a deviation of 1s, as the second may tick when the message is
	// in transit and the protocol doesn't support any further precision.
	if p.TimeOffset() != s.wantTimeOffset && p.TimeOffset() != s.wantTimeOffset-1 {
		t.Errorf("testPeer: wrong TimeOffset - got %v, want %v or %v", p.TimeOffset(),
			s.wantTimeOffset, s.wantTimeOffset-1)
		return
	}

	if p.BytesSent() != s.wantBytesSent {
		t.Errorf("testPeer: wrong BytesSent - got %v, want %v", p.BytesSent(), s.wantBytesSent)
		return
	}

	if p.BytesReceived() != s.wantBytesReceived {
		t.Errorf("testPeer: wrong BytesReceived - got %v, want %v", p.BytesReceived(), s.wantBytesReceived)
		return
	}

	if p.StartingHeight() != s.wantStartingHeight {
		t.Errorf("testPeer: wrong StartingHeight - got %v, want %v", p.StartingHeight(), s.wantStartingHeight)
		return
	}

	if p.Connected() != s.wantConnected {
		t.Errorf("testPeer: wrong Connected - got %v, want %v", p.Connected(), s.wantConnected)
		return
	}

	if p.IsWitnessEnabled() != s.wantWitnessEnabled {
		t.Errorf("testPeer: wrong WitnessEnabled - got %v, want %v",
			p.IsWitnessEnabled(), s.wantWitnessEnabled)
		return
	}

	stats := p.StatsSnapshot()

	if p.ID() != stats.ID {
		t.Errorf("testPeer: wrong ID - got %v, want %v", p.ID(), stats.ID)
		return
	}

	if p.Addr() != stats.Addr {
		t.Errorf("testPeer: wrong Addr - got %v, want %v", p.Addr(), stats.Addr)
		return
	}

	if p.LastSend() != stats.LastSend {
		t.Errorf("testPeer: wrong LastSend - got %v, want %v", p.LastSend(), stats.LastSend)
		return
	}

	if p.LastRecv() != stats.LastRecv {
		t.Errorf("testPeer: wrong LastRecv - got %v, want %v", p.LastRecv(), stats.LastRecv)
		return
	}
}

// TestPeerConnection tests connection between inbound and outbound peers.
func TestPeerConnection(t *testing.T) {
	verack := make(chan struct{})
	peer1Cfg := &peer.Config{
		Listeners: peer.MessageListeners{
			OnVerAck: func(p *peer.Peer, msg *wire.MsgVerAck) {
				verack <- struct{}{}
			},
			OnWrite: func(p *peer.Peer, bytesWritten int, msg wire.Message,
				err error) {
				if _, ok := msg.(*wire.MsgVerAck); ok {
					verack <- struct{}{}
				}
			},
		},
		UserAgentName:     "peer",
		UserAgentVersion:  "1.0",
		UserAgentComments: []string{"comment"},
		ChainParams:       &chaincfg.MainNetParams,
		ProtocolVersion:   wire.RejectVersion, // Configure with older version
		Services:          0,
		TrickleInterval:   time.Second * 10,
	}
	peer2Cfg := &peer.Config{
		Listeners:         peer1Cfg.Listeners,
		UserAgentName:     "peer",
		UserAgentVersion:  "1.0",
		UserAgentComments: []string{"comment"},
		ChainParams:       &chaincfg.MainNetParams,
		Services:          wire.SFNodeNetwork | wire.SFNodeWitness,
		TrickleInterval:   time.Second * 10,
	}

	wantStats1 := peerStats{
		wantUserAgent:       wire.DefaultUserAgent + "peer:1.0(comment)/",
		wantServices:        0,
		wantProtocolVersion: wire.RejectVersion,
		wantConnected:       true,
		wantVersionKnown:    true,
		wantVerAckReceived:  true,
		wantLastPingTime:    time.Time{},
		wantLastPingNonce:   uint64(0),
		wantLastPingMicros:  int64(0),
		wantTimeOffset:      int64(0),
		wantBytesSent:       167, // 143 version + 24 verack
		wantBytesReceived:   167,
		wantWitnessEnabled:  false,
	}
	wantStats2 := peerStats{
		wantUserAgent:       wire.DefaultUserAgent + "peer:1.0(comment)/",
		wantServices:        wire.SFNodeNetwork | wire.SFNodeWitness,
		wantProtocolVersion: wire.RejectVersion,
		wantConnected:       true,
		wantVersionKnown:    true,
		wantVerAckReceived:  true,
		wantLastPingTime:    time.Time{},
		wantLastPingNonce:   uint64(0),
		wantLastPingMicros:  int64(0),
		wantTimeOffset:      int64(0),
		wantBytesSent:       167, // 143 version + 24 verack
		wantBytesReceived:   167,
		wantWitnessEnabled:  true,
	}

	tests := []struct {
		name  string
		setup func() (*peer.Peer, *peer.Peer, error)
	}{
		{
			"basic handshake",
			func() (*peer.Peer, *peer.Peer, error) {
				inConn, outConn := pipe(
					&conn{raddr: "10.0.0.1:8333"},
					&conn{raddr: "10.0.0.2:8333"},
				)
				inPeer := peer.NewInboundPeer(peer1Cfg)
				inPeer.AssociateConnection(inConn)

				outPeer, err := peer.NewOutboundPeer(peer2Cfg, "10.0.0.2:8333")
				if err != nil {
					return nil, nil, err
				}
				outPeer.AssociateConnection(outConn)

				for i := 0; i < 4; i++ {
					select {
					case <-verack:
					case <-time.After(time.Second):
						return nil, nil, errors.New("verack timeout")
					}
				}
				return inPeer, outPeer, nil
			},
		},
		{
			"socks proxy",
			func() (*peer.Peer, *peer.Peer, error) {
				inConn, outConn := pipe(
					&conn{raddr: "10.0.0.1:8333", proxy: true},
					&conn{raddr: "10.0.0.2:8333"},
				)
				inPeer := peer.NewInboundPeer(peer1Cfg)
				inPeer.AssociateConnection(inConn)

				outPeer, err := peer.NewOutboundPeer(peer2Cfg, "10.0.0.2:8333")
				if err != nil {
					return nil, nil, err
				}
				outPeer.AssociateConnection(outConn)

				for i := 0; i < 4; i++ {
					select {
					case <-verack:
					case <-time.After(time.Second):
						return nil, nil, errors.New("verack timeout")
					}
				}
				return inPeer, outPeer, nil
			},
		},
	}
	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		inPeer, outPeer, err := test.setup()
		if err != nil {
			t.Errorf("TestPeerConnection setup #%d: unexpected err %v", i, err)
			return
		}
		testPeer(t, inPeer, wantStats2)
		testPeer(t, outPeer, wantStats1)

		inPeer.Disconnect()
		outPeer.Disconnect()
		inPeer.WaitForDisconnect()
		outPeer.WaitForDisconnect()
	}
}

// TestPeerListeners tests that the peer listeners are called as expected.
func TestPeerListeners(t *testing.T) {
	verack := make(chan struct{}, 1)
	ok := make(chan wire.Message, 20)
	peerCfg := &peer.Config{
		Listeners: peer.MessageListeners{
			OnGetAddr: func(p *peer.Peer, msg *wire.MsgGetAddr) {
				ok <- msg
			},
			OnAddr: func(p *peer.Peer, msg *wire.MsgAddr) {
				ok <- msg
			},
			OnPing: func(p *peer.Peer, msg *wire.MsgPing) {
				ok <- msg
			},
			OnPong: func(p *peer.Peer, msg *wire.MsgPong) {
				ok <- msg
			},
			OnAlert: func(p *peer.Peer, msg *wire.MsgAlert) {
				ok <- msg
			},
			OnMemPool: func(p *peer.Peer, msg *wire.MsgMemPool) {
				ok <- msg
			},
			OnTx: func(p *peer.Peer, msg *wire.MsgTx) {
				ok <- msg
			},
			OnBlock: func(p *peer.Peer, msg *wire.MsgBlock, buf []byte) {
				ok <- msg
			},
			OnInv: func(p *peer.Peer, msg *wire.MsgInv) {
				ok <- msg
			},
			OnHeaders: func(p *peer.Peer, msg *wire.MsgHeaders) {
				ok <- msg
			},
			OnNotFound: func(p *peer.Peer, msg *wire.MsgNotFound) {
				ok <- msg
			},
			OnGetData: func(p *peer.Peer, msg *wire.MsgGetData) {
				ok <- msg
			},
			OnGetBlocks: func(p *peer.Peer, msg *wire.MsgGetBlocks) {
				ok <- msg
			},
			OnGetHeaders: func(p *peer.Peer, msg *wire.MsgGetHeaders) {
				ok <- msg
			},
			OnGetCFilters: func(p *peer.Peer, msg *wire.MsgGetCFilters) {
				ok <- msg
			},
			OnGetCFHeaders: func(p *peer.Peer, msg *wire.MsgGetCFHeaders) {
				ok <- msg
			},
			OnGetCFCheckpt: func(p *peer.Peer, msg *wire.MsgGetCFCheckpt) {
				ok <- msg
			},
			OnCFilter: func(p *peer.Peer, msg *wire.MsgCFilter) {
				ok <- msg
			},
			OnCFHeaders: func(p *peer.Peer, msg *wire.MsgCFHeaders) {
				ok <- msg
			},
			OnFeeFilter: func(p *peer.Peer, msg *wire.MsgFeeFilter) {
				ok <- msg
			},
			OnFilterAdd: func(p *peer.Peer, msg *wire.MsgFilterAdd) {
				ok <- msg
			},
			OnFilterClear: func(p *peer.Peer, msg *wire.MsgFilterClear) {
				ok <- msg
			},
			OnFilterLoad: func(p *peer.Peer, msg *wire.MsgFilterLoad) {
				ok <- msg
			},
			OnMerkleBlock: func(p *peer.Peer, msg *wire.MsgMerkleBlock) {
				ok <- msg
			},
			OnVersion: func(p *peer.Peer, msg *wire.MsgVersion) *wire.MsgReject {
				ok <- msg
				return nil
			},
			OnVerAck: func(p *peer.Peer, msg *wire.MsgVerAck) {
				verack <- struct{}{}
			},
			OnReject: func(p *peer.Peer, msg *wire.MsgReject) {
				ok <- msg
			},
			OnSendHeaders: func(p *peer.Peer, msg *wire.MsgSendHeaders) {
				ok <- msg
			},
		},
		UserAgentName:     "peer",
		UserAgentVersion:  "1.0",
		UserAgentComments: []string{"comment"},
		ChainParams:       &chaincfg.MainNetParams,
		Services:          wire.SFNodeBloom,
		TrickleInterval:   time.Second * 10,
	}
	inConn, outConn := pipe(
		&conn{raddr: "10.0.0.1:8333"},
		&conn{raddr: "10.0.0.2:8333"},
	)
	inPeer := peer.NewInboundPeer(peerCfg)
	inPeer.AssociateConnection(inConn)

	peerCfg.Listeners = peer.MessageListeners{
		OnVerAck: func(p *peer.Peer, msg *wire.MsgVerAck) {
			verack <- struct{}{}
		},
	}
	outPeer, err := peer.NewOutboundPeer(peerCfg, "10.0.0.1:8333")
	if err != nil {
		t.Errorf("NewOutboundPeer: unexpected err %v\n", err)
		return
	}
	outPeer.AssociateConnection(outConn)

	for i := 0; i < 2; i++ {
		select {
		case <-verack:
		case <-time.After(time.Second * 1):
			t.Errorf("TestPeerListeners: verack timeout\n")
			return
		}
	}

	tests := []struct {
		listener string
		msg      wire.Message
	}{
		{
			"OnGetAddr",
			wire.NewMsgGetAddr(),
		},
		{
			"OnAddr",
			wire.NewMsgAddr(),
		},
		{
			"OnPing",
			wire.NewMsgPing(42),
		},
		{
			"OnPong",
			wire.NewMsgPong(42),
		},
		{
			"OnAlert",
			wire.NewMsgAlert([]byte("payload"), []byte("signature")),
		},
		{
			"OnMemPool",
			wire.NewMsgMemPool(),
		},
		{
			"OnTx",
			wire.NewMsgTx(wire.TxVersion),
		},
		{
			"OnBlock",
			wire.NewMsgBlock(wire.NewBlockHeader(1,
				&chainhash.Hash{}, &chainhash.Hash{}, 1, 1)),
		},
		{
			"OnInv",
			wire.NewMsgInv(),
		},
		{
			"OnHeaders",
			wire.NewMsgHeaders(),
		},
		{
			"OnNotFound",
			wire.NewMsgNotFound(),
		},
		{
			"OnGetData",
			wire.NewMsgGetData(),
		},
		{
			"OnGetBlocks",
			wire.NewMsgGetBlocks(&chainhash.Hash{}),
		},
		{
			"OnGetHeaders",
			wire.NewMsgGetHeaders(),
		},
		{
			"OnGetCFilters",
			wire.NewMsgGetCFilters(wire.GCSFilterRegular, 0, &chainhash.Hash{}),
		},
		{
			"OnGetCFHeaders",
			wire.NewMsgGetCFHeaders(wire.GCSFilterRegular, 0, &chainhash.Hash{}),
		},
		{
			"OnGetCFCheckpt",
			wire.NewMsgGetCFCheckpt(wire.GCSFilterRegular, &chainhash.Hash{}),
		},
		{
			"OnCFilter",
			wire.NewMsgCFilter(wire.GCSFilterRegular, &chainhash.Hash{},
				[]byte("payload")),
		},
		{
			"OnCFHeaders",
			wire.NewMsgCFHeaders(),
		},
		{
			"OnFeeFilter",
			wire.NewMsgFeeFilter(15000),
		},
		{
			"OnFilterAdd",
			wire.NewMsgFilterAdd([]byte{0x01}),
		},
		{
			"OnFilterClear",
			wire.NewMsgFilterClear(),
		},
		{
			"OnFilterLoad",
			wire.NewMsgFilterLoad([]byte{0x01}, 10, 0, wire.BloomUpdateNone),
		},
		{
			"OnMerkleBlock",
			wire.NewMsgMerkleBlock(wire.NewBlockHeader(1,
				&chainhash.Hash{}, &chainhash.Hash{}, 1, 1)),
		},
		// only one version message is allowed
		// only one verack message is allowed
		{
			"OnReject",
			wire.NewMsgReject("block", wire.RejectDuplicate, "dupe block"),
		},
		{
			"OnSendHeaders",
			wire.NewMsgSendHeaders(),
		},
	}
	t.Logf("Running %d tests", len(tests))
	for _, test := range tests {
		// Queue the test message
		outPeer.QueueMessage(test.msg, nil)
		select {
		case <-ok:
		case <-time.After(time.Second * 1):
			t.Errorf("TestPeerListeners: %s timeout", test.listener)
			return
		}
	}
	inPeer.Disconnect()
	outPeer.Disconnect()
}

// TestOutboundPeer tests that the outbound peer works as expected.
func TestOutboundPeer(t *testing.T) {

	peerCfg := &peer.Config{
		NewestBlock: func() (*chainhash.Hash, int32, error) {
			return nil, 0, errors.New("newest block not found")
		},
		UserAgentName:     "peer",
		UserAgentVersion:  "1.0",
		UserAgentComments: []string{"comment"},
		ChainParams:       &chaincfg.MainNetParams,
		Services:          0,
		TrickleInterval:   time.Second * 10,
	}

	r, w := io.Pipe()
	c := &conn{raddr: "10.0.0.1:8333", Writer: w, Reader: r}

	p, err := peer.NewOutboundPeer(peerCfg, "10.0.0.1:8333")
	if err != nil {
		t.Errorf("NewOutboundPeer: unexpected err - %v\n", err)
		return
	}

	// Test trying to connect twice.
	p.AssociateConnection(c)
	p.AssociateConnection(c)

	disconnected := make(chan struct{})
	go func() {
		p.WaitForDisconnect()
		disconnected <- struct{}{}
	}()

	select {
	case <-disconnected:
		close(disconnected)
	case <-time.After(time.Second):
		t.Fatal("Peer did not automatically disconnect.")
	}

	if p.Connected() {
		t.Fatalf("Should not be connected as NewestBlock produces error.")
	}

	// Test Queue Inv
	fakeBlockHash := &chainhash.Hash{0: 0x00, 1: 0x01}
	fakeInv := wire.NewInvVect(wire.InvTypeBlock, fakeBlockHash)

	// Should be noops as the peer could not connect.
	p.QueueInventory(fakeInv)
	p.AddKnownInventory(fakeInv)
	p.QueueInventory(fakeInv)

	fakeMsg := wire.NewMsgVerAck()
	p.QueueMessage(fakeMsg, nil)
	done := make(chan struct{})
	p.QueueMessage(fakeMsg, done)
	<-done
	p.Disconnect()

	// Test NewestBlock
	var newestBlock = func() (*chainhash.Hash, int32, error) {
		hashStr := "14a0810ac680a3eb3f82edc878cea25ec41d6b790744e5daeef"
		hash, err := chainhash.NewHashFromStr(hashStr)
		if err != nil {
			return nil, 0, err
		}
		return hash, 234439, nil
	}

	peerCfg.NewestBlock = newestBlock
	r1, w1 := io.Pipe()
	c1 := &conn{raddr: "10.0.0.1:8333", Writer: w1, Reader: r1}
	p1, err := peer.NewOutboundPeer(peerCfg, "10.0.0.1:8333")
	if err != nil {
		t.Errorf("NewOutboundPeer: unexpected err - %v\n", err)
		return
	}
	p1.AssociateConnection(c1)

	// Test update latest block
	latestBlockHash, err := chainhash.NewHashFromStr("1a63f9cdff1752e6375c8c76e543a71d239e1a2e5c6db1aa679")
	if err != nil {
		t.Errorf("NewHashFromStr: unexpected err %v\n", err)
		return
	}
	p1.UpdateLastAnnouncedBlock(latestBlockHash)
	p1.UpdateLastBlockHeight(234440)
	if p1.LastAnnouncedBlock() != latestBlockHash {
		t.Errorf("LastAnnouncedBlock: wrong block - got %v, want %v",
			p1.LastAnnouncedBlock(), latestBlockHash)
		return
	}

	// Test Queue Inv after connection
	p1.QueueInventory(fakeInv)
	p1.Disconnect()

	// Test regression
	peerCfg.ChainParams = &chaincfg.RegressionNetParams
	peerCfg.Services = wire.SFNodeBloom
	r2, w2 := io.Pipe()
	c2 := &conn{raddr: "10.0.0.1:8333", Writer: w2, Reader: r2}
	p2, err := peer.NewOutboundPeer(peerCfg, "10.0.0.1:8333")
	if err != nil {
		t.Errorf("NewOutboundPeer: unexpected err - %v\n", err)
		return
	}
	p2.AssociateConnection(c2)

	// Test PushXXX
	var addrs []*wire.NetAddress
	for i := 0; i < 5; i++ {
		na := wire.NetAddress{}
		addrs = append(addrs, &na)
	}
	if _, err := p2.PushAddrMsg(addrs); err != nil {
		t.Errorf("PushAddrMsg: unexpected err %v\n", err)
		return
	}
	if err := p2.PushGetBlocksMsg(nil, &chainhash.Hash{}); err != nil {
		t.Errorf("PushGetBlocksMsg: unexpected err %v\n", err)
		return
	}
	if err := p2.PushGetHeadersMsg(nil, &chainhash.Hash{}); err != nil {
		t.Errorf("PushGetHeadersMsg: unexpected err %v\n", err)
		return
	}

	p2.PushRejectMsg("block", wire.RejectMalformed, "malformed", nil, false)
	p2.PushRejectMsg("block", wire.RejectInvalid, "invalid", nil, false)

	// Test Queue Messages
	p2.QueueMessage(wire.NewMsgGetAddr(), nil)
	p2.QueueMessage(wire.NewMsgPing(1), nil)
	p2.QueueMessage(wire.NewMsgMemPool(), nil)
	p2.QueueMessage(wire.NewMsgGetData(), nil)
	p2.QueueMessage(wire.NewMsgGetHeaders(), nil)
	p2.QueueMessage(wire.NewMsgFeeFilter(20000), nil)

	p2.Disconnect()
}

// Tests that the node disconnects from peers with an unsupported protocol
// version.
func TestUnsupportedVersionPeer(t *testing.T) {
	peerCfg := &peer.Config{
		UserAgentName:     "peer",
		UserAgentVersion:  "1.0",
		UserAgentComments: []string{"comment"},
		ChainParams:       &chaincfg.MainNetParams,
		Services:          0,
		TrickleInterval:   time.Second * 10,
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
	p.AssociateConnection(localConn)

	// Read outbound messages to peer into a channel
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

			outboundMessages <- msg
		}
	}()

	// Read version message sent to remote peer
	select {
	case msg := <-outboundMessages:
		if _, ok := msg.(*wire.MsgVersion); !ok {
			t.Fatalf("Expected version message, got [%s]", msg.Command())
		}
	case <-time.After(time.Second):
		t.Fatal("Peer did not send version message")
	}

	// Remote peer writes version message advertising invalid protocol version 1
	invalidVersionMsg := wire.NewMsgVersion(remoteNA, localNA, 0, 0)
	invalidVersionMsg.ProtocolVersion = 1

	_, err = wire.WriteMessageN(
		remoteConn.Writer,
		invalidVersionMsg,
		uint32(invalidVersionMsg.ProtocolVersion),
		peerCfg.ChainParams.Net,
	)
	if err != nil {
		t.Fatalf("wire.WriteMessageN: unexpected err - %v\n", err)
	}

	// Expect peer to disconnect automatically
	disconnected := make(chan struct{})
	go func() {
		p.WaitForDisconnect()
		disconnected <- struct{}{}
	}()

	select {
	case <-disconnected:
		close(disconnected)
	case <-time.After(time.Second):
		t.Fatal("Peer did not automatically disconnect")
	}

	// Expect no further outbound messages from peer
	select {
	case msg, chanOpen := <-outboundMessages:
		if chanOpen {
			t.Fatalf("Expected no further messages, received [%s]", msg.Command())
		}
	case <-time.After(time.Second):
		t.Fatal("Timeout waiting for remote reader to close")
	}
}

// TestDuplicateVersionMsg ensures that receiving a version message after one
// has already been received results in the peer being disconnected.
func TestDuplicateVersionMsg(t *testing.T) {
	// Create a pair of peers that are connected to each other using a fake
	// connection.
	verack := make(chan struct{})
	peerCfg := &peer.Config{
		Listeners: peer.MessageListeners{
			OnVerAck: func(p *peer.Peer, msg *wire.MsgVerAck) {
				verack <- struct{}{}
			},
		},
		UserAgentName:    "peer",
		UserAgentVersion: "1.0",
		ChainParams:      &chaincfg.MainNetParams,
		Services:         0,
	}
	inConn, outConn := pipe(
		&conn{laddr: "10.0.0.1:9108", raddr: "10.0.0.2:9108"},
		&conn{laddr: "10.0.0.2:9108", raddr: "10.0.0.1:9108"},
	)
	outPeer, err := peer.NewOutboundPeer(peerCfg, inConn.laddr)
	if err != nil {
		t.Fatalf("NewOutboundPeer: unexpected err: %v\n", err)
	}
	outPeer.AssociateConnection(outConn)
	inPeer := peer.NewInboundPeer(peerCfg)
	inPeer.AssociateConnection(inConn)
	// Wait for the veracks from the initial protocol version negotiation.
	for i := 0; i < 2; i++ {
		select {
		case <-verack:
		case <-time.After(time.Second):
			t.Fatal("verack timeout")
		}
	}
	// Queue a duplicate version message from the outbound peer and wait until
	// it is sent.
	done := make(chan struct{})
	outPeer.QueueMessage(&wire.MsgVersion{}, done)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("send duplicate version timeout")
	}
	// Ensure the peer that is the recipient of the duplicate version closes the
	// connection.
	disconnected := make(chan struct{}, 1)
	go func() {
		inPeer.WaitForDisconnect()
		disconnected <- struct{}{}
	}()
	select {
	case <-disconnected:
	case <-time.After(time.Second):
		t.Fatal("peer did not disconnect")
	}
}

// Tests that OnVersion listener is not invoked for a disconnected Peer.
func TestVersionTimeoutSyncIssue(t *testing.T) {
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
				go func() {
					if !p.Connected() {
						t.Fatal("Improper OnVersion call by disconnected peer")
					} else {
						t.Log("OnVersion called for Connected() peer")
					}
					onVersionCalled <- struct{}{}
				}()
				return nil
			},
		},
	}

	// Our local port for connecting to a simulated remote peer
	localNA := wire.NewNetAddressIPPort(
		net.ParseIP("10.0.0.1"),
		uint16(8333),
		wire.SFNodeNetwork,
	)
	// Simulated port in posession of the simulated remote peer
	remoteNA := wire.NewNetAddressIPPort(
		net.ParseIP("10.0.0.2"),
		uint16(8333),
		wire.SFNodeNetwork,
	)
	// Establish connections between our local port and the simulated remote peer's port, and vice versa
	localConn, remoteConn := pipe(
		&conn{laddr: "10.0.0.1:8333", raddr: "10.0.0.2:8333"},
		&conn{laddr: "10.0.0.2:8333", raddr: "10.0.0.1:8333"},
	)

	// Create our Peer object to represent the (simulated) remote peer
	p, err := peer.NewOutboundPeer(peerCfg, "10.0.0.1:8333")
	if err != nil {
		t.Fatalf("NewOutboundPeer: unexpected err - %v\n", err)
	}
	// Associate, with our local Peer object representing the (simulated) remote peer,
	// our local connection to the simulated remote peer
	p.AssociateConnection(localConn)

	// Because writes to our local connection to the simulated remote peer will block presently until read,
	// start a thread to read (into a channel) data from the connection of the simulated remote peer.
	outboundMessages := make(chan wire.Message)
	go func() {
		for {
			_, msg, _, err := wire.ReadMessageN(
				remoteConn, // Connection in possession of the simulated remote peer
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

			outboundMessages <- msg
		}
	}()

	// A version message should have been sent by our local Peer object to the simulated
	// remote peer.  Confirm receipt by the simulated remote peer of this version message.
	select {
	case msg := <-outboundMessages:
		if _, ok := msg.(*wire.MsgVersion); !ok {
			t.Fatalf("Expected version message, got [%s]", msg.Command())
		}
	case <-time.After(time.Second):
		t.Fatal("Peer did not send version message")
	}

	// Wait for the local Peer object ostensibly to detect a timeout.
	// This test value of 32 is based on the constant peer.negotiateTimeout,
	// with additional time added to allow for processing the timeout.
	time.Sleep(32 * time.Second)

	// Now, cause the simulated remote peer to send a version message advertising valid protocol version
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

	// Wait for the the local Peer object to process any incoming messages, potentially from
	// the simulated remote peer
	time.Sleep(10 * time.Second)

	// Wait for the local Peer object to recognize a disconnection (potentially automatically)
	// from the simualted remote peer.
	disconnected := make(chan struct{})
	go func() {
		p.WaitForDisconnect()
		disconnected <- struct{}{}
	}()

	// Check to make sure that the local Peer object recognized a disconnection
	select {
	case <-disconnected:
		close(disconnected)
	case <-time.After(time.Second):
		t.Fatal("Peer did not automatically disconnect")
	}

	// Expect no call to OnVersion listener, because the connection handshake should have timed out.
	select {
	case <-onVersionCalled:
		t.Fatal("Improper call to OnVersion listener of peer type")

	case <-time.After(time.Second):
		close(onVersionCalled)
	}
}

// stallTestCase holds data describing a test of stall handling functionality
type stallTestCase struct {
	request     wire.Message  // Outgoing request
	response    wire.Message  // Incoming response
	shouldStall bool          // Do we expect the requesting Peer to stall?
	afterTime   time.Duration // Simulated duration in the Peer's stallHandler() after receiving response
}

// Tests that the Peer's stall handling functionality is working as expected
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

func init() {
	// Allow self connection when running the tests.
	peer.TstAllowSelfConns()
}
