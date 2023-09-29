package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
)

// Bridge represents a Wake-on-LAN bridge.
type Bridge struct {
	conn     io.ReadCloser
	lastSent MagicPacket
	wakeFunc func(net.IP, net.HardwareAddr) error
	mu       sync.Mutex
}

// Listen listens for magic packets on the given addr.
func Listen(addr string) (*Bridge, error) {
	udpAddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		return nil, err
	}
	return &Bridge{conn: conn, wakeFunc: Wake}, nil
}

// Close closes the connection.
func Close(b *Bridge) error { return b.conn.Close() }

// Forward reads a magic packet and writes it back to the network using src as the local address.
func (b *Bridge) Forward(src net.IP) (MagicPacket, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	mp, err := b.read()
	if err != nil {
		return nil, err
	}
	// Do not resend if we just sent this packet
	if bytes.Equal(mp, b.lastSent) {
		b.lastSent = nil
		return nil, nil
	}
	if err := b.wakeFunc(src, mp.HardwareAddr()); err != nil {
		return nil, err
	}
	b.lastSent = mp
	return mp, nil
}

func (b *Bridge) read() (MagicPacket, error) {
	buf := make([]byte, 4096)
	n, err := b.conn.Read(buf)
	if err != nil {
		return nil, err
	}
	mp := buf[:n]
	if !IsMagicPacket(mp) {
		return nil, fmt.Errorf("invalid magic packet: %x", mp)
	}
	return mp, nil
}

const hwAddrN = 16

var (
	bcastAddr    = []byte{255, 255, 255, 255, 255, 255}
	bcastAddrOff = len(bcastAddr)
)

type MagicPacket []byte

// HardwareAddr returns the physical address of the target computer.
func (p MagicPacket) HardwareAddr() net.HardwareAddr {
	return net.HardwareAddr(p[bcastAddrOff : bcastAddrOff*2])
}

// Create a magic packet for the given hwAddr.
func NewMagicPacket(hwAddr net.HardwareAddr) MagicPacket {
	p := make([]byte, bcastAddrOff+(hwAddrN*len(hwAddr)))
	copy(p, bcastAddr)
	copy(p[bcastAddrOff:], bytes.Repeat(hwAddr, hwAddrN))
	return p
}

// IsMagicPacket reports whether the byte array is a magic packet.
func IsMagicPacket(b []byte) bool {
	if len(b) != 102 {
		return false
	}
	if !bytes.Equal(b[:6], bcastAddr) {
		return false
	}
	hwAddr := MagicPacket(b).HardwareAddr()
	return bytes.Equal(b[bcastAddrOff:], bytes.Repeat(hwAddr, hwAddrN))
}

// Wake sends a magic packet for hwAddr to the broadcast address. If src is not nil, it is used as the local address for
// the broadcast.
func Wake(src net.IP, hwAddr net.HardwareAddr) error {
	var laddr *net.UDPAddr
	if src != nil {
		laddr = &net.UDPAddr{IP: src}
	}
	raddr := &net.UDPAddr{IP: net.IPv4bcast, Port: 9}
	conn, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		return err
	}
	p := NewMagicPacket(hwAddr)
	n, err := conn.Write([]byte(p))
	if err == nil && n < len(p) {
		return io.ErrShortWrite
	}
	if err1 := conn.Close(); err1 != nil {
		err = err1
	}
	return err
}

// WakeString sends a magic packet for macAddr to the broadcast address. If srcIP non-empty, it is used as the local
// address for the broadcast.
func WakeString(srcIP, macAddr string) error {
	hwAddr, err := net.ParseMAC(macAddr)
	if err != nil {
		return err
	}
	var src net.IP
	if srcIP != "" {
		src = net.ParseIP(srcIP)
		if src == nil {
			return fmt.Errorf("invalid ip: %s", srcIP)
		}
	}
	return Wake(src, hwAddr)
}

func main() {
	forwardAddress, present := os.LookupEnv("FORWARD_ADDRESS")
	if !present {
		log.Fatal("FORWARD_ADDRESS environment variable not set")
	}

	listenAddress, present := os.LookupEnv("LISTEN_ADDRESS")

	if !present {
		listenAddress = "0.0.0.0:9"
	}

	forwardAddr := net.ParseIP(forwardAddress)
	if forwardAddr == nil {
		log.Fatalln("invalid ip:", forwardAddress, "needs to be in the format '255.255.255.255' with no port")
	}

	b, err := Listen(listenAddress)
	if err != nil {
		log.Fatal(err)
	}
	for {
		sent, err := b.Forward(forwardAddr)
		if err != nil {
			log.Fatal(err)
		}
		if sent != nil {
			log.Printf("Forwarded magic packet for %s to %s", strings.ToUpper(sent.HardwareAddr().String()), forwardAddr)
		}
	}
}
