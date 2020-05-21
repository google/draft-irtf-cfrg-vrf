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
	suiteString []byte         // Single nonzero octet specifying the ECVRF ciphersuite
	ec          elliptic.Curve // Elliptic curve defined over F
	n           int            // 2n is the length, in bytes, of a field element in F
	ptLen       int            // Length, in octets, of an EC point encoded as an octet string
	qLen        int            // Length of the prime order of the EC group in octets. (Typically ~2n)
	cofactor    byte           // The number of points on EC divided by the prime order of the group
	hash        crypto.Hash    // Cryptographic hash function
	aux         ECVRFAux       // Suite specific helper functions
}

// ECVRFAux contains auxiliary functions nessesary for the computation of ECVRF.
type ECVRFAux interface {
	// PointToString converts an EC point to an octet string.
	PointToString(Px, Py *big.Int) []byte

	// StringToPoint converts an octet string to an EC point.
	// This function MUST output INVALID if the octet string does not decode to an EC point.
	StringToPoint(h []byte) (Px, Py *big.Int, err error)

	// ArbitraryStringToPoint converts an arbitrary 32 byte string s to an EC point.
	ArbitraryStringToPoint(s []byte) (Px, Py *big.Int, err error)
}
