package xkem

import (
	"crypto"

	"github.com/cloudflare/circl/kem"
)

func (x xkem) Encapsulate(pkr kem.PublicKey) (ct []byte, ss []byte) {
	pke, ske, err := x.GenerateKey()
	if err != nil {
		panic(err)
	}
	return x.encap(pkr, pke, ske)
}

func (x xkem) EncapsulateDeterministically(pkr kem.PublicKey, seed []byte) (ct, ss []byte) {
	pke, ske := x.DeriveKey(seed)
	return x.encap(pkr, pke, ske)
}

func (x xkem) AuthEncapsulate(pkr kem.PublicKey, sks kem.PrivateKey) (ct []byte, ss []byte) {
	pke, ske, err := x.GenerateKey()
	if err != nil {
		panic(err)
	}
	return x.authEncap(pkr, sks, pke, ske)
}

func (x xkem) AuthEncapsulateDeterministically(pkr kem.PublicKey, seed []byte, sks kem.PrivateKey) (ct, ss []byte) {
	pke, ske := x.DeriveKey(seed)
	return x.authEncap(pkr, sks, pke, ske)
}

func (x xkem) encap(pkr kem.PublicKey, pke crypto.PublicKey, ske crypto.PrivateKey) (ct []byte, ss []byte) {
	dh := make([]byte, x.SharedKeySize())
	enc, kemCtx := x.coreEncap(dh, pkr, ske, pke)
	ss = x.extractExpand(dh, kemCtx)
	return enc, ss
}

func (x xkem) authEncap(
	pkr kem.PublicKey,
	sks kem.PrivateKey,
	pke crypto.PublicKey,
	ske crypto.PrivateKey,
) (ct []byte, ss []byte) {
	skS, ok := sks.(xkemPrivKey)
	if !ok {
		panic(kem.ErrTypeMismatch)
	}

	dhLen := x.SharedKeySize()
	dh := make([]byte, 2*dhLen)
	enc, kemCtx := x.coreEncap(dh[:dhLen], pkr, ske, pke)
	x.calcDH(dh[dhLen:], skS, pkr.(xkemPubKey))

	pkS := skS.Public()
	pkSm, err := pkS.MarshalBinary()
	if err != nil {
		panic(err)
	}
	kemCtx = append(kemCtx, pkSm...)

	ss = x.extractExpand(dh, kemCtx)
	return enc, ss
}

func (x xkem) coreEncap(
	dh []byte,
	pkr kem.PublicKey,
	ske crypto.PrivateKey,
	pke crypto.PublicKey,
) (enc []byte, kemCtx []byte) {
	pkR, ok := pkr.(xkemPubKey)
	if !ok {
		panic(kem.ErrTypeMismatch)
	}
	skE, ok := ske.(xkemPrivKey)
	if !ok {
		panic(kem.ErrTypeMismatch)
	}
	pkE, ok := pke.(xkemPubKey)
	if !ok {
		panic(kem.ErrTypeMismatch)
	}

	x.calcDH(dh, skE, pkR)

	enc, err := pkE.MarshalBinary()
	if err != nil {
		panic(err)
	}
	pkRm, err := pkR.MarshalBinary()
	if err != nil {
		panic(err)
	}
	kemCtx = append(append([]byte{}, enc...), pkRm...)

	return enc, kemCtx
}
