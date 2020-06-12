// Copyright 2020 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vrf

import (
	"bytes"
	"crypto/elliptic"
	"errors"
	"math/big"
)

// i2osp converts a nonnegative integer to an octet string of a specified length.
// RFC8017 section-4.1 (big endian representation)
func i2osp(x *big.Int, rLen uint) []byte {
	// 1.  If x >= 256^rLen, output "integer too large" and stop.
	upperBound := new(big.Int).Lsh(big.NewInt(1), rLen*8)
	if x.Cmp(upperBound) >= 0 {
		panic("integer too large")
	}
	// 2.  Write the integer x in its unique rLen-digit representation in base 256:
	//     x = x_(rLen-1) 256^(rLen-1) + x_(rLen-2) 256^(rLen-2) + ...  + x_1 256 + x_0,
	//     where 0 <= x_i < 256
	//     (note that one or more leading digits will be zero if x is less than 256^(rLen-1)).
	// 3.  Let the octet X_i have the integer value x_(rLen-i) for 1 <= i <= rLen.
	//     Output the octet string X = X_1 X_2 ... X_rLen.

	var b bytes.Buffer
	xLen := (uint(x.BitLen()) + 7) >> 3
	if rLen > xLen {
		b.Write(make([]byte, rLen-xLen)) // prepend 0s
	}
	b.Write(x.Bytes())
	return b.Bytes()[uint(b.Len())-rLen:] // The rightmost rLen bytes.
}

// bits2int takes as input a sequence of blen bits and outputs a non-negative
// integer that is less than 2^qlen.
// https://tools.ietf.org/html/rfc6979#section-2.3.2
func bits2int(b []byte, qlen int) *big.Int {
	blen := len(b) * 8
	v := new(big.Int).SetBytes(b)
	// 1.  The sequence is first truncated or expanded to length qlen:
	if qlen < blen {
		// if qlen < blen, then the qlen leftmost bits are kept, and
		// subsequent bits are discarded;
		v = new(big.Int).Rsh(v, uint(blen-qlen))
	} else {
		// otherwise, qlen-blen bits (of value zero) are added to the
		// left of the sequence (i.e., before the input bits in the
		// sequence order).
	}

	// 2.  The resulting sequence is then converted to an integer value
	//     using the big-endian convention: if input bits are called b_0
	//     (leftmost) to b_(qlen-1) (rightmost), then the resulting value
	//     is: b_0*2^(qlen-1) + b_1*2^(qlen-2) + ... + b_(qlen-1)*2^0
	return v
}

// SECG1EncodeCompressed converts an EC point to an octet string according to
// the encoding specified in Section 2.3.3 of [SECG1] with point compression
// on. This implies ptLen = 2n + 1 = 33.
//
// SECG1 Section 2.3.3 https://www.secg.org/sec1-v1.99.dif.pdf
//
// (Note that certain software implementations do not introduce a separate
// elliptic curve point type and instead directly treat the EC point as an
// octet string per above encoding.  When using such an implementation, the
// point_to_string function can be treated as the identity function.)
func marshalCompressed(curve elliptic.Curve, x, y *big.Int) []byte {
	byteLen := (curve.Params().BitSize + 7) >> 3
	compressed := make([]byte, 1+byteLen)
	compressed[0] = 2 // compressed point
	compressed[0] += byte(y.Bit(0))
	i := byteLen + 1 - len(x.Bytes())
	copy(compressed[i:], x.Bytes())
	return compressed
}

// This file implements compressed point unmarshaling.  Preferably this
// functionality would be in a standard library.  Code borrowed from:
// https://go-review.googlesource.com/#/c/1883/2/src/crypto/elliptic/elliptic.go

// SECG1Decode decodes a EC point, given as a compressed string.
// If the decoding fails x and y will be nil.
//
// http://www.secg.org/sec1-v2.pdf
// https://tools.ietf.org/html/rfc8032#section-5.1.3
// Section 4.3.6 of ANSI X9.62.

var errInvalidPoint = errors.New("invalid point")

func unmarshalCompressed(curve elliptic.Curve, data []byte) (x, y *big.Int, err error) {
	byteLen := (curve.Params().BitSize + 7) >> 3
	if (data[0] &^ 1) != 2 { // compressed form
		return nil, nil, errors.New("unrecognized point encoding")
	}
	if len(data) != 1+byteLen {
		return nil, nil, errors.New("invalid length for curve")
	}

	// Based on Routine 2.2.4 in NIST Mathematical routines paper
	x = new(big.Int).SetBytes(data[1:])
	y2 := y2(curve.Params(), x)
	y = new(big.Int).ModSqrt(y2, curve.Params().P)
	if y == nil {
		return nil, nil, errInvalidPoint // "y^2" is not a square
	}
	if !curve.IsOnCurve(x, y) {
		return nil, nil, errInvalidPoint // sqrt(y2)^2 != y2: invalid point
	}
	if y.Bit(0) != uint(data[0]&0x01) {
		y.Sub(curve.Params().P, y)
	}

	return x, y, nil // valid point: return x,y
}

// Use the curve equation to calculate y² given x.
// only applies to curves of the form y² = x³ - 3x + b.
func y2(curve *elliptic.CurveParams, x *big.Int) *big.Int {
	// y² = x³ - 3x + b
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)

	threeX := new(big.Int).Lsh(x, 1)
	threeX.Add(threeX, x)

	y2 := new(big.Int).Sub(x3, threeX)
	y2.Add(y2, curve.B)
	y2.Mod(y2, curve.P)
	return y2
}
