// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// writeVersionMsg serializes a valid version message and writes it to w using
// the given protocol version and network, returning any write error on errc.
func writeVersionMsg(w net.Conn, pver uint32, net wire.BitcoinNet, errc chan<- error) {
	me := wire.NewNetAddressIPPort(
		net2IP("10.0.0.2"), 8333, wire.SFNodeNetwork,
	)
	you := wire.NewNetAddressIPPort(
		net2IP("10.0.0.1"), 8333, wire.SFNodeNetwork,
	)
	vmsg := wire.NewMsgVersion(me, you, 0x1234567890, 0)
	vmsg.ProtocolVersion = int32(pver)

	_, err := wire.WriteMessageN(w, vmsg, pver, net)
	errc <- err
}

// net2IP is a tiny helper to keep the message construction above readable.
func net2IP(s string) net.IP { return net.ParseIP(s) }

// TestReadRemoteVersionMsgSkipsOnVersionWhenDisconnected verifies that, when a
// peer has been disconnected during negotiation (e.g. by the negotiation
// timeout in start), reading the remote version message does NOT invoke the
// OnVersion listener and returns an error.
//
// The disconnect flag is set directly rather than via Disconnect so the
// connection stays open and the version message is actually read off the wire,
// reproducing the race window where readRemoteVersionMsg completes a successful
// read just as start has timed out the peer.
func TestReadRemoteVersionMsgSkipsOnVersionWhenDisconnected(t *testing.T) {
	var onVersionCalls int32
	cfg := &Config{
		ChainParams:     &chaincfg.MainNetParams,
		ProtocolVersion: MaxProtocolVersion,
		AllowSelfConns:  true,
		Listeners: MessageListeners{
			OnVersion: func(p *Peer, msg *wire.MsgVersion) *wire.MsgReject {
				atomic.AddInt32(&onVersionCalls, 1)
				return nil
			},
		},
	}
	p := newPeerBase(cfg, false)

	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	p.conn = local
	atomic.StoreInt32(&p.connected, 1)

	// Simulate the negotiation-timeout disconnect WITHOUT closing the conn.
	atomic.StoreInt32(&p.disconnect, 1)

	writeErr := make(chan error, 1)
	go writeVersionMsg(
		remote, p.ProtocolVersion(), cfg.ChainParams.Net, writeErr,
	)

	readErr := make(chan error, 1)
	go func() { readErr <- p.readRemoteVersionMsg(false) }()

	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("expected error reading version on a " +
				"disconnected peer, got nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out reading remote version message")
	}

	if got := atomic.LoadInt32(&onVersionCalls); got != 0 {
		t.Fatalf("OnVersion invoked %d times on a disconnected peer, "+
			"want 0", got)
	}
}

// TestReadRemoteVersionMsgInvokesOnVersionWhenConnected is the positive control
// for the guard above: a still-connected peer must invoke OnVersion exactly
// once and complete the read without error.
func TestReadRemoteVersionMsgInvokesOnVersionWhenConnected(t *testing.T) {
	var onVersionCalls int32
	cfg := &Config{
		ChainParams:     &chaincfg.MainNetParams,
		ProtocolVersion: MaxProtocolVersion,
		AllowSelfConns:  true,
		Listeners: MessageListeners{
			OnVersion: func(p *Peer, msg *wire.MsgVersion) *wire.MsgReject {
				atomic.AddInt32(&onVersionCalls, 1)
				return nil
			},
		},
	}
	p := newPeerBase(cfg, false)

	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	p.conn = local
	atomic.StoreInt32(&p.connected, 1)

	writeErr := make(chan error, 1)
	go writeVersionMsg(
		remote, p.ProtocolVersion(), cfg.ChainParams.Net, writeErr,
	)

	readErr := make(chan error, 1)
	go func() { readErr <- p.readRemoteVersionMsg(false) }()

	select {
	case err := <-readErr:
		if err != nil {
			t.Fatalf("unexpected error reading version: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out reading remote version message")
	}

	if got := atomic.LoadInt32(&onVersionCalls); got != 1 {
		t.Fatalf("OnVersion invoked %d times on a connected peer, "+
			"want 1", got)
	}
}

// TestProcessRemoteVerAckMsgGuard verifies that the OnVerAck listener is skipped
// when the peer has been disconnected during negotiation, and invoked normally
// otherwise.
func TestProcessRemoteVerAckMsgGuard(t *testing.T) {
	newPeerWithVerAckCounter := func() (*Peer, *int32) {
		var calls int32
		cfg := &Config{
			ChainParams: &chaincfg.MainNetParams,
			Listeners: MessageListeners{
				OnVerAck: func(p *Peer, msg *wire.MsgVerAck) {
					atomic.AddInt32(&calls, 1)
				},
			},
		}
		p := newPeerBase(cfg, false)
		atomic.StoreInt32(&p.connected, 1)
		return p, &calls
	}

	// Disconnected peer: the listener must not fire.
	disconnected, dcCalls := newPeerWithVerAckCounter()
	atomic.StoreInt32(&disconnected.disconnect, 1)
	disconnected.processRemoteVerAckMsg(wire.NewMsgVerAck())
	if got := atomic.LoadInt32(dcCalls); got != 0 {
		t.Fatalf("OnVerAck invoked %d times on a disconnected peer, "+
			"want 0", got)
	}

	// Connected peer: the listener must fire exactly once.
	connected, cCalls := newPeerWithVerAckCounter()
	connected.processRemoteVerAckMsg(wire.NewMsgVerAck())
	if got := atomic.LoadInt32(cCalls); got != 1 {
		t.Fatalf("OnVerAck invoked %d times on a connected peer, "+
			"want 1", got)
	}
}
