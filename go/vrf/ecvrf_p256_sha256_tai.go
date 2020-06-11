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
