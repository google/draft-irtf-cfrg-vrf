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
