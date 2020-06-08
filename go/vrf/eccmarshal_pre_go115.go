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

// +build !go1.15

// This file implements compressed point unmarshaling.
// This code will be in go 1.15
// Code borrowed from: https://github.com/golang/go/pull/35110

package vrf

import (
	"crypto/elliptic"
	"errors"
	"math/big"
)

// marshalCompressed converts an EC point to an octet string according to
// the encoding specified in Section 2.3.3 of [SECG1] with point compression
// on. If 2n = ceil(log_2(q) / 8) then ptLen = 2n + 1 = 33.
//
// SECG1 Section 2.3.3 https://www.secg.org/sec1-v1.99.dif.pdf
func marshalCompressed(curve elliptic.Curve, x, y *big.Int) []byte {
	byteLen := (curve.Params().BitSize + 7) >> 3
	compressed := make([]byte, 1+byteLen)
	compressed[0] = 2 // compressed point
	compressed[0] += byte(y.Bit(0))
	i := byteLen + 1 - len(x.Bytes())
	copy(compressed[i:], x.Bytes())
	return compressed
}

var errInvalidPoint = errors.New("invalid point")

// unmarshalCompressed decodes a EC point, given as a compressed string.
// If the decoding fails x and y will be nil.
//
// http://www.secg.org/sec1-v2.pdf
// https://tools.ietf.org/html/rfc8032#section-5.1.3
// Section 4.3.6 of ANSI X9.62.
func unmarshalCompressed(curve elliptic.Curve, data []byte) (x, y *big.Int, err error) {
	byteLen := (curve.Params().BitSize + 7) >> 3
	if data[0] != 2 && data[0] != 3 { // compressed form
		return nil, nil, errors.New("unrecognized point encoding")
	}
	if len(data) != 1+byteLen {
		return nil, nil, errors.New("invalid length for curve")
	}

	// Based on Routine 2.2.4 in NIST Mathematical routines paper
	x = new(big.Int).SetBytes(data[1:])
	y2 := polynomial(curve.Params(), x)
	y = new(big.Int).ModSqrt(y2, curve.Params().P)
	if y == nil {
		return nil, nil, errInvalidPoint // "y^2" is not a square
	}
	if !curve.IsOnCurve(x, y) {
		return nil, nil, errInvalidPoint
	}
	if y.Bit(0) != uint(data[0]&0x01) {
		y.Sub(curve.Params().P, y)
	}

	return x, y, nil // valid point: return x,y
}

// polynomial returns x³ - 3x + b.
func polynomial(curve *elliptic.CurveParams, x *big.Int) *big.Int {
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)

	threeX := new(big.Int).Lsh(x, 1)
	threeX.Add(threeX, x)
	x3.Sub(x3, threeX)

	x3.Add(x3, curve.B)
	x3.Mod(x3, curve.P)
	return x3
}
