// This code was ported from a Java implementation found at:
// https://github.com/dekellum/jetty/blob/master/jetty-http/src/main/java/org/eclipse/jetty/http/security/UnixCrypt.java
// The source bears the following copyright notice:
/*
 * @(#)UnixCrypt.java	0.9 96/11/25
 *
 * Copyright (c) 1996 Aki Yoshida. All rights reserved.
 *
 * Permission to use, copy, modify and distribute this software
 * for non-commercial or commercial purposes and without fee is
 * hereby granted provided that this copyright notice appears in
 * all copies.
 */
/**
 * modified April 2001
 * by Iris Van den Broeke, Daniel Deville
 */

// Package des implements the Version 7 Unix DES password hashing algorithm in
// pure Go. See crypt(3) for details. This algorithm was ported from Aki
// Yoshida's Java implementation.
package des

/* (mostly) Standard DES Tables from Tom Truscott */
var ip = [64]byte{ /* initial permutation */
	58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
}

/* The final permutation is the inverse of ip - no table is necessary */

var expandTr = [48]byte{ /* expansion operation */
	32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11,
	12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
	22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
}

var pc1 = [56]byte{ /* permuted choice table 1 */
	57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
	10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,

	63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
	14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
}

var rotates = [16]byte{ /* pc1 rotation schedule */
	1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1,
}

var pc2 = [64]byte{ /* permuted choice table 2 */
	9, 18, 14, 17, 11, 24, 1, 5, 22, 25, 3, 28, 15, 6, 21, 10,
	35, 38, 23, 19, 12, 4, 26, 8, 43, 54, 16, 7, 27, 20, 13, 2,

	0, 0, 41, 52, 31, 37, 47, 55, 0, 0, 30, 40, 51, 45, 33, 48,
	0, 0, 44, 49, 39, 56, 34, 53, 0, 0, 46, 42, 50, 36, 29, 32,
}

var s = [8][64]byte{ /* 48->32 bit substitution tables */
	/* s[1] */
	[64]byte{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
		0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
		4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
		15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
	/* s[2] */
	[64]byte{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
		3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
		0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
		13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
	/* s[3] */
	[64]byte{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
		13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
		13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
		1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
	/* s[4] */
	[64]byte{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
		13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
		10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
		3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
	/* s[5] */
	[64]byte{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
		14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
		4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
		11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
	/* s[6] */
	[64]byte{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
		10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
		9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
		4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},
	/* s[7] */
	[64]byte{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
		13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
		1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
		6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
	/* s[8] */
	[64]byte{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
		1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
		7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
		2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11},
}

var p32tr = [32]byte{ /* 32-bit permutation function */
	16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
	2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
}

var cifp = [64]byte{ /*
	* compressed/interleaved
	* permutation
	 */
	1, 2, 3, 4, 17, 18, 19, 20, 5, 6, 7, 8, 21, 22, 23, 24,
	9, 10, 11, 12, 25, 26, 27, 28, 13, 14, 15, 16, 29, 30, 31, 32,

	33, 34, 35, 36, 49, 50, 51, 52, 37, 38, 39, 40, 53, 54, 55, 56,
	41, 42, 43, 44, 57, 58, 59, 60, 45, 46, 47, 48, 61, 62, 63, 64,
}

/* 0..63 => ascii-64 */
var itoa64 = [64]byte{ /* 0..63 => ascii-64 */
	'.', '/', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D',
	'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
	'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
	'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
}

/* ===== Tables that are initialized at run time ==================== */

var a64toi [128]byte /* ascii-64 => 0..63 */

/* Initial key schedule permutation */
var pc1Rot [16][16]int64

/* Subsequent key schedule rotation permutations */
var pc2Rot [2][16][16]int64

/* Initial permutation/expansion table */
var ie3264 [8][16]int64

/* Table that combines the S, P, and E operations. */
var spe [8][64]int64

/* compressed/interleaved => final permutation table */
var cf6464 [16][16]int64

func init() {
	var perm [64]byte
	var temp [64]byte

	// inverse table.
	for i := 0; i < 64; i++ {
		a64toi[itoa64[i]] = byte(i)
	}

	// pc1Rot - bit reverse, then pc1, then Rotate, then pc2
	for i := 0; i < 64; i++ {
		perm[i] = 0
	}

	for i := 0; i < 64; i++ {
		k := int(pc2[i])
		if k == 0 {
			continue
		}
		k += int(rotates[0]) - 1
		if (k % 28) < int(rotates[0]) {
			k -= 28
		}
		k = int(pc1[k])
		if k > 0 {
			k--
			k = (k | 0x07) - (k & 0x07)
			k++
		}
		perm[i] = byte(k)
	}
	initPerm1616(&pc1Rot, perm, 8)

	// pc2Rot - pc2 inverse, then Rotate, then pc2
	for j := 0; j < 2; j++ {
		var k int
		for i := 0; i < 64; i++ {
			perm[i] = 0
			temp[i] = 0
		}
		for i := 0; i < 64; i++ {
			k = int(pc2[i])
			if k == 0 {
				continue
			}
			temp[k-1] = byte(i + 1)
		}
		for i := 0; i < 64; i++ {
			k = int(pc2[i])
			if k == 0 {
				continue
			}
			k += j
			if (k % 28) <= j {
				k -= 28
			}
			perm[i] = temp[k]
		}

		initPerm1616(&pc2Rot[j], perm, 8)
	}

	// Bit reverse, initial permutation, expansion
	for i := 0; i < 8; i++ {
		for j := 0; j < 8; j++ {
			k := 0
			if j >= 2 {
				k = int(ip[expandTr[i*6+j-2]-1])
			}
			if k > 32 {
				k -= 32
			} else if k > 0 {
				k--
			}
			if k > 0 {
				k--
				k = (k | 0x07) - (k & 0x07)
				k++
			}
			perm[i*8+j] = byte(k)
		}
	}

	initPerm816(&ie3264, perm, 8)

	// Compression, final permutation, bit reverse
	for i := 0; i < 64; i++ {
		k := int(ip[cifp[i]-1])
		if k > 0 {
			k--
			k = (k | 0x07) - (k & 0x07)
			k++
		}
		perm[k-1] = byte(i + 1)
	}

	initPerm1616(&cf6464, perm, 8)

	// spe table
	for i := 0; i < 48; i++ {
		perm[i] = p32tr[expandTr[i]-1]
	}
	for t := 0; t < 8; t++ {
		for j := 0; j < 64; j++ {
			k := (((j >> 0) & 0x01) << 5) | (((j >> 1) & 0x01) << 3) | (((j >> 2) & 0x01) << 2) | (((j >> 3) & 0x01) << 1) | (((j >> 4) & 0x01) << 0) | (((j >> 5) & 0x01) << 4)
			k = int(s[t][k])
			k = (((k >> 3) & 0x01) << 0) | (((k >> 2) & 0x01) << 1) | (((k >> 1) & 0x01) << 2) | (((k >> 0) & 0x01) << 3)
			for i := 0; i < 32; i++ {
				temp[i] = 0
			}
			for i := 0; i < 4; i++ {
				temp[4*t+i] = byte((k >> uint(i)) & 0x01)
			}
			kk := int64(0)
			for i := 23; i >= 0; i-- {
				kk = ((kk << 1) | (int64(temp[perm[i]-1])<<32 | int64(temp[perm[i+24]-1])))
			}

			spe[t][j] = int64(toSixBitLong(int64(kk)))
		}
	}
}

/**
 * Returns the transposed and split code of a 24-bit code into a 4-byte
 * code, each having 6 bits.
 */
func toSixBit(num int) int {
	return (((num << 26) & 0xfc000000) | ((num << 12) & 0xfc0000) | ((num >> 2) & 0xfc00) | ((num >> 16) & 0xfc))
}

/**
 * Returns the transposed and split code of two 24-bit code into two 4-byte
 * code, each having 6 bits.
 */
func toSixBitLong(num int64) int64 {
	return int64((uint64(num<<26) & uint64(0xfc000000fc000000)) |
		(uint64(num<<12) & uint64(0xfc000000fc0000)) |
		(uint64(num>>2) & uint64(0xfc000000fc00)) |
		(uint64(num>>16) & uint64(0xfc000000fc)))
}

/**
 * Initializes the given permutation table with the mapping table.
 */
func initPerm816(perm *[8][16]int64, p [64]byte, charsOut int) {
	for k := 0; k < charsOut*8; k++ {

		l := int(p[k]) - 1
		if l < 0 {
			continue
		}
		i := l >> 2
		l = 1 << uint(l&0x03)
		for j := 0; j < 16; j++ {
			s := ((k & 0x07) + ((7 - (k >> 3)) << 3))
			if (j & l) != 0x00 {
				perm[i][j] |= (1 << uint(s))
			}
		}
	}
}

func initPerm1616(perm *[16][16]int64, p [64]byte, charsOut int) {
	for k := 0; k < charsOut*8; k++ {

		l := int(p[k]) - 1
		if l < 0 {
			continue
		}
		i := l >> 2
		l = 1 << uint(l&0x03)
		for j := 0; j < 16; j++ {
			s := ((k & 0x07) + ((7 - (k >> 3)) << 3))
			if (j & l) != 0x00 {
				perm[i][j] |= (1 << uint(s))
			}
		}
	}
}

/**
 * Returns the permutation of the given 64-bit code with the specified
 * permutataion table.
 */
func perm6464(c int64, p [16][16]int64) int64 {
	out := int64(0)
	for i := 7; i >= 0; i-- {
		t := int(0x00ff & c)
		c >>= 8
		tp := p[i<<1][t&0x0f]
		out |= tp
		tp = p[(i<<1)+1][t>>4]
		out |= tp
	}
	return out
}

/**
 * Returns the permutation of the given 32-bit code with the specified
 * permutataion table.
 */
func perm3264(c int, p [8][16]int64) int64 {
	out := int64(0)
	for i := 3; i >= 0; i-- {
		t := (0x00ff & c)
		c >>= 8
		tp := p[i<<1][t&0x0f]
		out |= tp
		tp = p[(i<<1)+1][t>>4]
		out |= tp
	}
	return out
}

/**
 * Returns the key schedule for the given key.
 */
func setKey(keyword int64) [16]int64 {
	k := perm6464(keyword, pc1Rot)
	var ks [16]int64
	ks[0] = k & ^int64(0x0303030300000000)

	for i := 1; i < 16; i++ {
		ks[i] = k
		k = perm6464(k, pc2Rot[rotates[i]-1])

		ks[i] = k & ^int64(0x0303030300000000)
	}
	return ks
}

/**
 * Returns the DES encrypted code of the given word with the specified
 * environment.
 */
func cipher(in int64, salt, numIter int, ks [16]int64) int64 {
	salt = toSixBit(salt)
	l := in
	r := l
	l &= 0x5555555555555555
	r = int64(uint64(r)&uint64(0xaaaaaaaa00000000)) | ((r >> 1) & 0x0000000055555555)
	l = (int64(uint64((l<<1)|(l<<32))&uint64(0xffffffff00000000)) | ((r | (r >> 32)) & 0x00000000ffffffff))

	l = perm3264(int(l>>32), ie3264)
	r = perm3264(int(l&0xffffffff), ie3264)

	for {
		numIter--
		if numIter < 0 {
			break
		}
		for loopCount := 0; loopCount < 8; loopCount++ {
			var (
				kp int64
				b  int64
				k  int64
			)

			kp = ks[(loopCount << 1)]
			k = ((r >> 32) ^ r) & int64(salt) & 0xffffffff
			k |= (k << 32)
			b = (k ^ r ^ kp)

			l ^= (spe[0][int((b>>58)&0x3f)] ^ spe[1][int((b>>50)&0x3f)] ^
				spe[2][int((b>>42)&0x3f)] ^
				spe[3][int((b>>34)&0x3f)] ^
				spe[4][int((b>>26)&0x3f)] ^
				spe[5][int((b>>18)&0x3f)] ^
				spe[6][int((b>>10)&0x3f)] ^ spe[7][int((b>>2)&0x3f)])

			kp = ks[(loopCount<<1)+1]
			k = ((l >> 32) ^ l) & int64(salt) & 0xffffffff
			k |= (k << 32)
			b = (k ^ l ^ kp)

			r ^= (spe[0][int((b>>58)&0x3f)] ^ spe[1][int((b>>50)&0x3f)] ^
				spe[2][int((b>>42)&0x3f)] ^
				spe[3][int((b>>34)&0x3f)] ^
				spe[4][int((b>>26)&0x3f)] ^
				spe[5][int((b>>18)&0x3f)] ^
				spe[6][int((b>>10)&0x3f)] ^ spe[7][int((b>>2)&0x3f)])
		}
		// swap l and r
		l ^= r
		r ^= l
		l ^= r
	}
	l = ((((l>>35)&0x0f0f0f0f)|(((l&0xffffffff)<<1)&0xf0f0f0f0))<<32 | (((r >> 35) & 0x0f0f0f0f) | (((r & 0xffffffff) << 1) & 0xf0f0f0f0)))

	l = perm6464(l, cf6464)

	return l
}

/**
 * Encrypts String into crypt (Unix) code.
 *
 * @param key the key to be encrypted
 * @param setting the salt to be used
 * @return the encrypted String
 */

// Crypt returns the DES hash of the key, salted with the salt passed in setting.
func Crypt(key, setting string) string {
	constdatablock := int64(0) /* encryption constant */
	var cryptresult [13]byte   /* encrypted result */
	keyword := int64(0)
	/* invalid parameters! */
	if key == "" || setting == "" {
		return "*" // will NOT match under
		// ANY circumstances!
	}

	keylen := len(key)

	for i := 0; i < 8; i++ {
		keyword = (keyword << 8)
		if i < keylen {
			keyword |= 2 * int64(key[i])
		}
	}

	ks := setKey(keyword)

	salt := 0
	for i := 1; i >= 0; i-- {
		var c byte
		if i < len(setting) {
			c = setting[i]
		} else {
			c = '.'
		}
		cryptresult[i] = c
		salt = (salt << 6) | int(0x00ff&a64toi[c])
	}

	rsltblock := cipher(constdatablock, salt, 25, ks)

	cryptresult[12] = itoa64[(int(rsltblock)<<2)&0x3f]
	rsltblock >>= 4
	for i := 11; i >= 2; i-- {
		cryptresult[i] = itoa64[int(rsltblock)&0x3f]
		rsltblock >>= 6
	}

	return string(cryptresult[:])
}
