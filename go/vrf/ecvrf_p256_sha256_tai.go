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
	"fmt"
	"math"
	"math/big"

	_ "crypto/sha256"
)

type (
	p256SHA256TAISuite struct{ *ECVRFParams }
	p256SHA256TAIAux   struct{ params *ECVRFParams }
)

var p256SHA256TAI p256SHA256TAISuite

func initP256SHA256TAI() {
	// https://tools.ietf.org/html/draft-irtf-cfrg-vrf-06#section-5.5
	p := &ECVRFParams{
		suite:    0x01,            // int_to_string(1, 1)
		ec:       elliptic.P256(), // NIST P-256 elliptic curve, [FIPS-186-4] (Section D.1.2.3).
		fieldLen: 32,              // Params().BitSize / 8 = 2n
		qLen:     32,              // Params().N.BitLen
		ptLen:    33,              // Size of encoded EC point
		cofactor: big.NewInt(1),
		hash:     crypto.SHA256,
	}
	p.aux = p256SHA256TAIAux{params: p}
	p256SHA256TAI.ECVRFParams = p
}

// Params returns the parameters for the ECVRF.
func (s p256SHA256TAISuite) Params() *ECVRFParams {
	return s.ECVRFParams
}

// PointToString converts an EC point to an octet string according to
// the encoding specified in Section 2.3.3 of [SECG1] with point
// compression on.  This implies ptLen = 2n + 1 = 33.
func (a p256SHA256TAIAux) PointToString(Px, Py *big.Int) []byte {
	return marshalCompressed(a.params.ec, Px, Py)
}

// String2Point converts an octet string to an EC point according to the
// encoding specified in Section 2.3.4 of [SECG1].  This function MUST output
// INVALID if the octet string does not decode to an EC point.
// http://www.secg.org/sec1-v2.pdf
func (a p256SHA256TAIAux) StringToPoint(s []byte) (x, y *big.Int, err error) {
	x, y, err = unmarshalCompressed(a.params.ec, s)
	if err != nil {
		return nil, nil, err
	} else if x == nil {
		return nil, nil, errInvalidPoint
	}
	return x, y, nil
}

// ArbitraryString2Point returns StringToPoint(0x02 || h).
// Attempts to interpret an arbitrary string as a compressed elliptic code point.
// The input h is a 32-octet string.  Returns either an EC point or "INVALID".
func (a p256SHA256TAIAux) ArbitraryStringToPoint(h []byte) (Px, Py *big.Int, err error) {
	if got, want := len(h), 32; got != want {
		return nil, nil, fmt.Errorf("len(s): %v, want %v", got, want)
	}
	return a.StringToPoint(append([]byte{0x02}, h...))
}

var zero big.Int
var one = big.NewInt(1)

// HashToCurve implements the HashToCurveTryAndIncrement algorithm from section 5.4.1.1.
//
// The running time of this algorithm depends on alpha. For the ciphersuites
// specified in Section 5.5, this algorithm is expected to find a valid curve
// point after approximately two attempts (i.e., when ctr=1) on average.
//
// However, because the running time of algorithm depends on alpha, this
// algorithm SHOULD be avoided in applications where it is important that the
// VRF input alpha remain secret.
//
// Inputs:
// - `suite` - a single octet specifying ECVRF ciphersuite.
// - `pub`   - public key, an EC point
// - `alpha` - value to be hashed, an octet string
// Output:
// - `H` - hashed value, a finite EC point in G
// - `ctr` - integer, number of suite byte, attempts to find a valid curve point
func (a p256SHA256TAIAux) HashToCurve(pub *PublicKey, alpha []byte) (Hx, Hy *big.Int) {
	Hx, Hy, _ = a.hashToCurve(pub, alpha)
	return
}

func (a p256SHA256TAIAux) hashToCurve(pub *PublicKey, alpha []byte) (Hx, Hy *big.Int, ctr uint8) {
	// 1.  ctr = 0
	ctr = 0
	// 2.  PK_string = point_to_string(pub)
	pkStr := a.PointToString(pub.X, pub.Y)

	// 3.  one_string = 0x01 = int_to_string(1, 1), a single octet with value 1
	oneStr := []byte{0x01}

	// 4.  H = "INVALID"
	h := a.params.hash.New()

	// 5.  While H is "INVALID" or H is EC point at infinity:
	var err error
	for Hx == nil || err != nil || (zero.Cmp(Hx) == 0 && zero.Cmp(Hy) == 0) {
		// A.  ctr_string = int_to_string(ctr, 1)
		ctrString := []byte{ctr}
		// B.  hash_string = Hash(suite_string || one_string ||
		//     PK_string || alpha_string || ctr_string)
		h.Reset()
		h.Write([]byte{a.params.suite})
		h.Write(oneStr)
		h.Write(pkStr)
		h.Write(alpha)
		h.Write(ctrString)
		hashString := h.Sum(nil)
		// C.  H = arbitrary_string_to_point(hash_string)
		Hx, Hy, err = a.ArbitraryStringToPoint(hashString)
		// D.  If H is not "INVALID" and cofactor > 1, set H = cofactor * H
		// Cofactor for prime ordered curves is 1.
		if err == nil && a.params.cofactor.Cmp(one) > 0 {
			Hx, Hy = a.params.ec.ScalarMult(Hx, Hy, a.params.cofactor.Bytes())
		}
		if ctr == math.MaxUint8 {
			panic("HashToCurveTAI ctr overflow")
		}
		ctr++
	}
	ctr--
	// 6.  Output H
	return Hx, Hy, ctr
}
