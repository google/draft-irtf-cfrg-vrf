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
	"crypto"
	"crypto/elliptic"
	"math/big"
)

func init() {
	initP256SHA256TAI()
}

// PublicKey holds a public VRF key.
type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

// PrivateKey holds a private VRF key.
type PrivateKey struct {
	PublicKey
	d *big.Int
}

// Public returns the public key corresponding to priv.
func (priv *PrivateKey) Public() *PublicKey {
	return &priv.PublicKey
}

func NewKey(curve elliptic.Curve, sk []byte) *PrivateKey {
	x, y := curve.ScalarBaseMult(sk)
	return &PrivateKey{
		PublicKey: PublicKey{Curve: curve, X: x, Y: y}, // VRF public key Y = x*B
		d:         new(big.Int).SetBytes(sk),           // Use SK to derive the VRF secret scalar x
	}
}

// ECVRFParams holds shared values across ECVRF implementations.
// ECVRFParams also has generic algorithms that rely on ECVRFAux for specific sub algorithms.
type ECVRFParams struct {
	suite    byte           // Single nonzero octet specifying the ECVRF ciphersuite.
	ec       elliptic.Curve // Elliptic curve defined over F.
	fieldLen int            // Length, in bytes, of a field element in F. Defined as 2n in spec.
	ptLen    int            // Length, in bytes, of an EC point encoded as an octet string.
	qLen     int            // Length, in bytes, of the prime order of the EC group (Typically ~fieldLen).
	cofactor *big.Int       // The number of points on EC divided by the prime order of the group.
	hash     crypto.Hash    // Cryptographic hash function.
	aux      ECVRFAux       // Suite specific helper functions.
}

// ECVRFAux contains auxiliary functions necesary for the computation of ECVRF.
type ECVRFAux interface {
	// PointToString converts an EC point to an octet string.
	PointToString(Px, Py *big.Int) []byte

	// StringToPoint converts an octet string to an EC point.
	// This function MUST output INVALID if the octet string does not decode to an EC point.
	StringToPoint(h []byte) (Px, Py *big.Int, err error)

	// ArbitraryStringToPoint converts an arbitrary 32 byte string s to an EC point.
	ArbitraryStringToPoint(s []byte) (Px, Py *big.Int, err error)

	// HashToCurve is a collision resistant hash of VRF input alpha to H, an EC point in G.
	HashToCurve(Y *PublicKey, alpha []byte) (Hx, Hy *big.Int)

	// GenerateNonoce generates the nonce value k in a deterministic, pseudorandom fashion.
	GenerateNonce(sk *PrivateKey, h []byte) (k *big.Int)
}

// hashPoints accepts X,Y pairs of EC points in G and returns an hash value between 0 and 2^(8n)-1
//
// https://tools.ietf.org/html/draft-irtf-cfrg-vrf-06#section-5.4.3
func (p ECVRFParams) hashPoints(pm ...*big.Int) (c *big.Int) {
	// 1.  two_string = 0x02 = int_to_string(2, 1), a single octet with value 2
	// 2.  Initialize str = suite_string || two_string
	str := []byte{p.suite, 0x02}

	// 3.  for PJ in [P1, P2, ... PM]:
	for i := 0; i < len(pm); i += 2 {
		// str = str || point_to_string(PJ)
		str = append(str, p.aux.PointToString(pm[i], pm[i+1])...)
	}

	// 4.  c_string = Hash(str)
	hc := p.hash.New()
	hc.Write(str)
	cString := hc.Sum(nil)

	// 5.  truncated_c_string = c_string[0]...c_string[n-1]
	n := p.fieldLen / 2 //   2n = fieldLen = 32
	// 6.  c = string_to_int(truncated_c_string)
	c = new(big.Int).SetBytes(cString[:n])
	return c
}
