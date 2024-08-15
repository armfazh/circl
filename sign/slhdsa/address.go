package slhdsa

import "encoding/binary"

type addressType uint32

const (
	addressWotsHash addressType = iota
	addressWotsPk
	addressTree
	addressForsTree
	addressForsRoots
	addressWotsPrf
	addressForsPrf
)

type address struct {
	layer uint32
	tree  [3]uint32
	atype addressType
	addr  [3]uint32
}

func (a *address) Bytes() (out []byte) {
	out = make([]byte, 0, 32)
	out = binary.BigEndian.AppendUint32(out, a.layer)
	out = binary.BigEndian.AppendUint32(out, a.tree[0])
	out = binary.BigEndian.AppendUint32(out, a.tree[1])
	out = binary.BigEndian.AppendUint32(out, a.tree[2])
	out = binary.BigEndian.AppendUint32(out, uint32(a.atype))
	out = binary.BigEndian.AppendUint32(out, a.addr[0])
	out = binary.BigEndian.AppendUint32(out, a.addr[1])
	out = binary.BigEndian.AppendUint32(out, a.addr[2])

	return
}

func (a *address) CompressedBytes() (out []byte) {
	out = make([]byte, 0, 22)
	out = append(out, byte(a.layer&0xFF))
	out = binary.BigEndian.AppendUint32(out, a.tree[1])
	out = binary.BigEndian.AppendUint32(out, a.tree[2])
	out = append(out, byte(a.atype&0xFF))
	out = binary.BigEndian.AppendUint32(out, a.addr[0])
	out = binary.BigEndian.AppendUint32(out, a.addr[1])
	out = binary.BigEndian.AppendUint32(out, a.addr[2])

	return
}

func (a *address) SetLayerAddress(l uint32)      { a.layer = l }
func (a *address) SetTreeAddress(t [3]uint32)    { a.tree = t }
func (a *address) SetTypeAndClear(t addressType) { a.atype = t; a.addr = [3]uint32{} }
func (a *address) SetKeyPairAddress(i uint32)    { a.addr[0] = i }
func (a *address) SetChainAddress(i uint32)      { a.addr[1] = i }
func (a *address) SetTreeHeight(i uint32)        { a.addr[1] = i }
func (a *address) SetHashAddress(i uint32)       { a.addr[2] = i }
func (a *address) SetTreeIndex(i uint32)         { a.addr[2] = i }
func (a *address) GetKeyPairAddress() uint32     { return a.addr[0] }
func (a *address) GetTreeIndex() uint32          { return a.addr[2] }
