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
// integer that is less than 2^qlen.  bits2int operates on byte boundaries,
// meaning blen = 8*len(b). Returns the integer value of the qlen leftmost bits.
// https://tools.ietf.org/html/rfc6979#section-2.3.2
func bits2int(b []byte, qlen int) *big.Int {
	blen := len(b) * 8
	v := new(big.Int).SetBytes(b)
	// 1.  The sequence is first truncated or expanded to length qlen:
	if qlen < blen {
		// Truncate:
		// If qlen < blen, then the qlen leftmost bits are kept, and
		// subsequent bits are discarded;
		v = new(big.Int).Rsh(v, uint(blen-qlen))
	}
	// Expand: fill the high order bits with zeros. Happens by default.
	// otherwise, qlen-blen bits (of value zero) are added to the
	// left of the sequence (i.e., before the input bits in the
	// sequence order).

	// 2.  The resulting sequence is then converted to an integer value
	//     using the big-endian convention: if input bits are called b_0
	//     (leftmost) to b_(qlen-1) (rightmost), then the resulting value
	//     is: b_0*2^(qlen-1) + b_1*2^(qlen-2) + ... + b_(qlen-1)*2^0
	return v
}

// int2octets returns x as a sequence of rlen bits.
// int2octets deviates from x.Bytes() by returning a byte slice of exact length.
//
// x is an integer value less than q (and, in particular, a value that has been
// taken modulo q) as sequence of rlen bits, where rlen = 8*ceil(qlen/8).  This
// is the sequence of bits obtained by big-endian encoding.  In other words,
// the sequence bits x_i (for i ranging from 0 to rlen-1) are such that:
//
//   x = x_0*2^(rlen-1) + x_1*2^(rlen-2) + ... + x_(rlen-1)
//
// Since rlen is a multiple of 8 (the smallest multiple of 8 that is not
// smaller than qlen), then the resulting sequence of bits is also a sequence
// of octets, hence the name int2octets.
//
// https://tools.ietf.org/html/rfc6979#section-2.3.3
func int2octets(x *big.Int, qlen int) []byte {
	rlen := 8 * ((qlen + 7) >> 3) // rlen = 8*ceil(qlen/8)
	b := x.Bytes()
	blen := len(b) * 8
	if blen < rlen {
		// left pad with rlen - blen bits
		b = append(make([]byte, (rlen-blen)/8), b...)
	}
	if blen > rlen {
		// truncate to blen bits
		b = b[:rlen/8]
	}
	return b
}

//  bits2octets takes as input a sequence of blen bits and outputs a sequence
//  of rlen = 8*ceil(qlen/8) bits.
//
// https://datatracker.ietf.org/doc/html/rfc6979#section-2.3.4
func bits2octets(b []byte, q *big.Int) []byte {
	//  1.  The input sequence b is converted into an integer value z1 through the bits2int transform:
	z1 := bits2int(b, q.BitLen())
	//  2.  z1 is reduced modulo q, yielding z2 (an integer between 0 and q-1, inclusive):
	z2 := new(big.Int).Mod(z1, q)

	// Note that since z1 is less than 2^qlen, that modular reduction
	// can be implemented with a simple conditional subtraction:
	// z2 = z1-q if that value is non-negative; otherwise, z2 = z1.

	// 3.  z2 is transformed into a sequence of octets (a sequence of rlen bits) by applying int2octets.
	return int2octets(z2, q.BitLen())
}
