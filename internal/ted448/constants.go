package ted448

import fp "github.com/cloudflare/circl/math/fp448"

var (
	// genX is the x-coordinate of the generator of ted448 curve.
	genX = fp.Elt{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x80, 0xfe, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
	}
	// genY is the y-coordinate of the generator of ted448 curve.
	genY = fp.Elt{
		0x64, 0x4a, 0xdd, 0xdf, 0xb4, 0x79, 0x60, 0xc8,
		0xa1, 0x70, 0xb4, 0x3a, 0x1e, 0x0c, 0x9b, 0x19,
		0xe5, 0x48, 0x3f, 0xd7, 0x44, 0x18, 0x18, 0x14,
		0x14, 0x27, 0x45, 0x50, 0x2c, 0x24, 0xd5, 0x93,
		0xc3, 0x74, 0x4c, 0x50, 0x70, 0x43, 0x26, 0x05,
		0x08, 0x24, 0xca, 0x78, 0x30, 0xc1, 0x06, 0x8d,
		0xd4, 0x86, 0x42, 0xf0, 0x14, 0xde, 0x08, 0x85,
	}
	// paramD is -39082 in Fp. The D parameter of the ted448 curve.
	paramD = fp.Elt{
		0x55, 0x67, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	}
	// order is 2^446-0x8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d,
	// which is the number of points in the prime subgroup.
	order = Scalar{
		0xf3, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78, 0x23,
		0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2, 0x6c, 0x21,
		0x90, 0x36, 0xd6, 0xae, 0x49, 0xdb, 0x4e, 0xc4,
		0xe9, 0x23, 0xca, 0x7c, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
	}
	// residue448 is 2^448 mod order.
	residue448 = [4]uint64{
		0x721cf5b5529eec34, 0x7a4cf635c8e9c2ab, 0xeec492d944a725bf, 0x20cd77058,
	}
)
