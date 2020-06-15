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
