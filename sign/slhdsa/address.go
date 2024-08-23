package slhdsa

import "encoding/binary"

const (
	addressWotsHash = iota
	addressWotsPk
	addressTree
	addressForsTree
	addressForsRoots
	addressWotsPrf
	addressForsPrf
)

func (p *params) newAddress() *address {
	if p.isSha2 {
		return &address{o: 0x0}
	} else {
		return &address{o: 0xA}
	}
}

type address struct {
	b [32]byte
	o int
}

func (a *address) SetLayerAddress(l uint32) {
	if a.o == 0 {
		a.b[0] = byte(l & 0xFF)
	} else {
		binary.BigEndian.PutUint32(a.b[0:], l)
	}
}

func (a *address) SetTreeAddress(t [3]uint32) {
	if a.o == 0 {
		binary.BigEndian.PutUint32(a.b[1:], t[1])
		binary.BigEndian.PutUint32(a.b[5:], t[2])
	} else {
		binary.BigEndian.PutUint32(a.b[4:], t[0])
		binary.BigEndian.PutUint32(a.b[8:], t[1])
		binary.BigEndian.PutUint32(a.b[12:], t[2])
	}
}

func (a *address) SetTypeAndClear(t uint32) {
	if a.o == 0 {
		a.b[9] = byte(t)
	} else {
		binary.BigEndian.PutUint32(a.b[16:], t)
	}
	for i := range a.b[a.o+10:] {
		a.b[a.o+10+i] = 0
	}
}
func (a *address) SetKeyPairAddress(i uint32) { binary.BigEndian.PutUint32(a.b[a.o+10:], i) }
func (a *address) SetChainAddress(i uint32)   { binary.BigEndian.PutUint32(a.b[a.o+14:], i) }
func (a *address) SetTreeHeight(i uint32)     { binary.BigEndian.PutUint32(a.b[a.o+14:], i) }
func (a *address) SetHashAddress(i uint32)    { binary.BigEndian.PutUint32(a.b[a.o+18:], i) }
func (a *address) SetTreeIndex(i uint32)      { binary.BigEndian.PutUint32(a.b[a.o+18:], i) }
func (a *address) GetKeyPairAddress() uint32  { return binary.BigEndian.Uint32(a.b[a.o+10:]) }
func (a *address) GetTreeIndex() uint32       { return binary.BigEndian.Uint32(a.b[a.o+18:]) }
func (a *address) Bytes() []byte              { return a.b[:a.o+22] }
