package fourq

const (
	// This is the size of the largest scalar k = 2^256 - 1 + order
	fxT = 257
	// Number of tables
	fxV = 2
	// Window size
	fxW = 3
	// Number of points per table
	fx2w1 = (1 << (uint(fxW) - 1))
)

var tableBaseFixed = [fxV][fx2w1]pointR3{
	{
		{
			addYX: Fq{
				[SizeFp]byte{0x31, 0xe6, 0x03, 0xa7, 0xf3, 0x34, 0x8a, 0xe1, 0x5f, 0x2b, 0x50, 0x1d, 0xbf, 0x60, 0x74, 0x28},
				[SizeFp]byte{0x53, 0x03, 0xf9, 0xe4, 0xf7, 0x62, 0x2e, 0xe0, 0xde, 0xac, 0x86, 0x8b, 0x37, 0xa0, 0x3b, 0x0c},
			},
			subYX: Fq{
				[SizeFp]byte{0xdc, 0x7e, 0x93, 0xb0, 0x98, 0x0f, 0xbf, 0x90, 0x55, 0xc5, 0xf0, 0x24, 0x78, 0x7c, 0x0b, 0x74},
				[SizeFp]byte{0x66, 0x13, 0xa0, 0x23, 0x91, 0x23, 0x21, 0xb3, 0xa5, 0x57, 0x95, 0x3a, 0xb9, 0xf5, 0xfc, 0x4f},
			},
			dt2: Fq{
				[SizeFp]byte{0xbb, 0x42, 0xda, 0xab, 0xcb, 0xfc, 0x7a, 0x29, 0xc6, 0x97, 0x6c, 0x55, 0x37, 0xd1, 0x48, 0x59},
				[SizeFp]byte{0x4c, 0x68, 0x30, 0x33, 0x39, 0x9a, 0x18, 0xa8, 0x27, 0x1f, 0x34, 0x0a, 0x72, 0x2b, 0xaf, 0x0c},
			},
		},
		{
			addYX: Fq{
				[SizeFp]byte{0x6a, 0x23, 0x5d, 0xcf, 0x2e, 0xf2, 0x8b, 0x5f, 0x5a, 0x2a, 0x6f, 0xa0, 0xef, 0xa7, 0x76, 0x32},
				[SizeFp]byte{0x57, 0xad, 0x0b, 0x1a, 0x60, 0xc4, 0x43, 0xdf, 0x6a, 0xbc, 0x31, 0xe6, 0x55, 0xd5, 0xc4, 0x4b},
			},
			subYX: Fq{
				[SizeFp]byte{0xf7, 0xab, 0xbf, 0xd2, 0x55, 0x8c, 0x13, 0xfe, 0xca, 0x64, 0x65, 0x03, 0xa9, 0x93, 0x29, 0x64},
				[SizeFp]byte{0xb5, 0x9b, 0xdd, 0x17, 0xb1, 0x5a, 0x0e, 0xbc, 0x22, 0x41, 0x77, 0x11, 0x25, 0x6f, 0xa1, 0x68},
			},
			dt2: Fq{
				[SizeFp]byte{0xb6, 0x76, 0xfe, 0x14, 0xa1, 0x31, 0x4e, 0xc8, 0xc4, 0x5f, 0x2c, 0x8d, 0x05, 0x23, 0xa8, 0x16},
				[SizeFp]byte{0x9d, 0x45, 0x6d, 0x97, 0xd7, 0x0a, 0x22, 0x5a, 0x7a, 0x71, 0x2c, 0x06, 0x6d, 0xeb, 0x9a, 0x7d},
			},
		},
		{
			addYX: Fq{
				[SizeFp]byte{0x46, 0x6b, 0x69, 0xeb, 0x7f, 0x13, 0x9a, 0x2b, 0x40, 0x0a, 0xc1, 0xdc, 0xfa, 0x66, 0xf0, 0x39},
				[SizeFp]byte{0x77, 0x9c, 0xd9, 0x0a, 0x0e, 0x65, 0xb3, 0xc6, 0xbd, 0x1d, 0x7f, 0xe0, 0xf8, 0x5a, 0x4f, 0x55},
			},
			subYX: Fq{
				[SizeFp]byte{0xc1, 0x88, 0xb5, 0x09, 0xd0, 0xc5, 0x63, 0x62, 0x8e, 0x0e, 0x6b, 0xeb, 0xfd, 0x49, 0x27, 0x7a},
				[SizeFp]byte{0x8c, 0x38, 0x5e, 0x06, 0x05, 0x17, 0x5e, 0xe4, 0x2f, 0xda, 0x4b, 0x9f, 0x94, 0x68, 0x4d, 0x5b},
			},
			dt2: Fq{
				[SizeFp]byte{0x6f, 0x84, 0xf3, 0x3f, 0x08, 0x26, 0x0c, 0xb4, 0xfa, 0xc7, 0x9e, 0xe6, 0x2f, 0xef, 0x3f, 0x53},
				[SizeFp]byte{0x47, 0xd1, 0x71, 0x88, 0x9d, 0x2e, 0xcd, 0x4e, 0x94, 0x03, 0x49, 0xbe, 0x0b, 0x1a, 0x91, 0x6d},
			},
		},
		{
			addYX: Fq{
				[SizeFp]byte{0x73, 0x9b, 0x3b, 0x99, 0x69, 0x39, 0x8c, 0xda, 0xf2, 0x3d, 0xba, 0xad, 0x7c, 0x75, 0xeb, 0x26},
				[SizeFp]byte{0x18, 0x56, 0xe6, 0xa9, 0xa4, 0x10, 0xf3, 0x13, 0x33, 0x25, 0x04, 0x60, 0x2a, 0x00, 0x62, 0x18},
			},
			subYX: Fq{
				[SizeFp]byte{0x6d, 0xcd, 0x87, 0xca, 0xce, 0xd1, 0xda, 0xb4, 0x5f, 0xd9, 0x0c, 0x21, 0x45, 0x3d, 0xf4, 0x38},
				[SizeFp]byte{0xc1, 0xe5, 0x03, 0xa6, 0x64, 0x57, 0x30, 0x13, 0xc7, 0xf8, 0xaa, 0xf2, 0xcd, 0x8f, 0x57, 0x6e},
			},
			dt2: Fq{
				[SizeFp]byte{0x05, 0x02, 0xcb, 0x13, 0xd6, 0x24, 0xa0, 0x20, 0xa9, 0xe0, 0xe0, 0xdd, 0x90, 0x6f, 0xd0, 0x7c},
				[SizeFp]byte{0xfc, 0x91, 0x59, 0x14, 0x5b, 0xa4, 0x8e, 0xf5, 0xe1, 0xc0, 0x4c, 0x82, 0xce, 0xe2, 0xf6, 0x41},
			},
		},
	},
	{
		{
			addYX: Fq{
				[SizeFp]byte{0x60, 0x31, 0xb8, 0xc2, 0xb0, 0x7f, 0x36, 0xdb, 0x8c, 0xe8, 0xfc, 0x0a, 0x1b, 0xf3, 0x2e, 0x21},
				[SizeFp]byte{0x5e, 0x89, 0xd9, 0xf0, 0xfc, 0x47, 0xe5, 0x20, 0x10, 0xe6, 0x26, 0xf2, 0x67, 0xdb, 0xcc, 0x42},
			},
			subYX: Fq{
				[SizeFp]byte{0x0e, 0x3b, 0xad, 0x12, 0x15, 0xa3, 0x40, 0x9e, 0x73, 0x97, 0x99, 0x43, 0x28, 0x74, 0xfe, 0x6d},
				[SizeFp]byte{0x92, 0x93, 0x68, 0xe8, 0xf5, 0xaf, 0x70, 0x4f, 0x1b, 0x4a, 0x36, 0x13, 0x21, 0x89, 0xee, 0x5f},
			},
			dt2: Fq{
				[SizeFp]byte{0x41, 0xc5, 0x53, 0xc7, 0xf7, 0xa4, 0x99, 0x82, 0x00, 0x49, 0x7f, 0x5f, 0xbe, 0x40, 0xc2, 0x7f},
				[SizeFp]byte{0xa6, 0x22, 0xe3, 0x40, 0x6e, 0xc7, 0xee, 0x4c, 0xff, 0x36, 0xf4, 0x01, 0x4b, 0x52, 0x54, 0x77},
			},
		},
		{
			addYX: Fq{
				[SizeFp]byte{0x35, 0x58, 0xef, 0x56, 0xbc, 0xbb, 0xdf, 0xf9, 0x59, 0x2e, 0xf2, 0x2f, 0x4d, 0x89, 0xd8, 0x1d},
				[SizeFp]byte{0x6c, 0xde, 0xe6, 0xde, 0x89, 0x39, 0x24, 0x3a, 0xce, 0x8e, 0xf5, 0x46, 0x33, 0x2b, 0xa8, 0x12},
			},
			subYX: Fq{
				[SizeFp]byte{0x60, 0x72, 0x41, 0xb1, 0x06, 0xaf, 0x7d, 0x08, 0x6e, 0xee, 0xb7, 0x5e, 0x23, 0x95, 0xbf, 0x79},
				[SizeFp]byte{0x34, 0x42, 0xdc, 0x3a, 0x73, 0x96, 0x94, 0xbe, 0xb9, 0x5d, 0xb4, 0x4b, 0x10, 0x48, 0x5e, 0x25},
			},
			dt2: Fq{
				[SizeFp]byte{0x44, 0xff, 0xf4, 0x38, 0x90, 0x9d, 0xf4, 0x14, 0x9f, 0x4d, 0x5c, 0xab, 0xee, 0x68, 0xba, 0x0d},
				[SizeFp]byte{0x45, 0x95, 0xe5, 0x91, 0x20, 0x15, 0x7b, 0xe8, 0x1f, 0x89, 0x12, 0x51, 0xd3, 0xfa, 0x82, 0x0d},
			},
		},
		{
			addYX: Fq{
				[SizeFp]byte{0x0c, 0xa3, 0xf8, 0x33, 0x76, 0x28, 0x4f, 0x2d, 0x26, 0xcc, 0x29, 0x77, 0x1a, 0xb3, 0x6e, 0x41},
				[SizeFp]byte{0xef, 0xc8, 0x87, 0x5d, 0x26, 0x5d, 0x2f, 0xd1, 0x5c, 0xe0, 0x04, 0x58, 0x1c, 0xa9, 0x80, 0x4d},
			},
			subYX: Fq{
				[SizeFp]byte{0x0a, 0xff, 0x06, 0x42, 0xe4, 0x76, 0xc5, 0xfa, 0xcd, 0x2a, 0xfb, 0x4c, 0xfa, 0x22, 0x0a, 0x7d},
				[SizeFp]byte{0xd9, 0x5c, 0x89, 0x6d, 0x63, 0xe8, 0x0a, 0xb3, 0x29, 0xa4, 0xb9, 0x42, 0x12, 0x1d, 0xea, 0x00},
			},
			dt2: Fq{
				[SizeFp]byte{0xb3, 0x59, 0x9d, 0x40, 0xdb, 0x32, 0x11, 0x41, 0x10, 0xa1, 0xbf, 0xf1, 0x7a, 0xe3, 0xdd, 0x11},
				[SizeFp]byte{0x2c, 0xcc, 0x5c, 0x98, 0x1c, 0xd5, 0x95, 0xd2, 0x96, 0x51, 0xb1, 0x82, 0xb2, 0x7f, 0xe7, 0x6a},
			},
		},
		{
			addYX: Fq{
				[SizeFp]byte{0x07, 0xe9, 0xb9, 0x83, 0xeb, 0xf2, 0x9f, 0xd7, 0x43, 0x7c, 0xc2, 0xb0, 0x32, 0x70, 0xd0, 0x52},
				[SizeFp]byte{0xf9, 0x70, 0x82, 0x31, 0x7a, 0x9a, 0x9f, 0x75, 0xe9, 0x6c, 0x87, 0x73, 0x97, 0x1a, 0x5a, 0x22},
			},
			subYX: Fq{
				[SizeFp]byte{0x0b, 0x3b, 0xe5, 0x98, 0xdc, 0xf6, 0xd1, 0xf5, 0xb7, 0x7e, 0x34, 0x22, 0x35, 0x60, 0x41, 0x53},
				[SizeFp]byte{0x1f, 0xf4, 0xcc, 0x56, 0xbb, 0x76, 0x3e, 0xd9, 0x3b, 0x63, 0x82, 0x25, 0x98, 0x12, 0x80, 0x02},
			},
			dt2: Fq{
				[SizeFp]byte{0xeb, 0xdc, 0x9a, 0x7a, 0x70, 0x61, 0x5d, 0x6e, 0x41, 0x05, 0xd4, 0x0b, 0x4a, 0x63, 0x2a, 0x3b},
				[SizeFp]byte{0xab, 0x52, 0xe0, 0xb1, 0x3f, 0x8a, 0xb0, 0x2d, 0x55, 0xf8, 0x1c, 0xeb, 0xc1, 0x1b, 0xc8, 0x35},
			},
		},
	},
}
