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
	"crypto"
	"crypto/elliptic"
	"crypto/hmac"
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

func (a p256SHA256TAIAux) IntToString(x *big.Int, xLen uint) []byte {
	return i2osp(x, xLen) // RFC8017 Section 4.1 (big endian representation)
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

// GenerateNonce implements RFC 6979 section 3.2
//    Input:
//       sk - an ECVRF secret key
//       h  - an octet string
//
//    Output:
//       k - an integer between 1 and q-1
func (a p256SHA256TAIAux) GenerateNonce(sk *PrivateKey, h []byte) (k *big.Int) {
	m := h    // Input m is set equal to h_string
	x := sk.d // The secret key x is set equal to the VRF secret scalar x

	// The "suitable for DSA or ECDSA" check in step h.3 is omitted
	// The hash function H is Hash and its output length hlen is set as hLen*8
	hash := a.params.hash

	// The prime q is the same as in this specification
	q := sk.Params().N

	// qlen is the binary length of q, i.e., the smallest integer such that 2^qlen > q
	// All the other values and primitives as defined in [RFC6979]
	//
	// N, also known as q, is the order of the base point, which generates subgroup Gi.
	qlen := q.BitLen()

	//
	// RFC 6979 section 3.2
	//

	// a.  Process m through the hash function H, yielding: h1 = H(m)
	h1 := hash.New()
	h1.Write(m) // (h1 is a sequence of hlen bits).
	h1Digest := h1.Sum(nil)

	// b.  Set: V = 0x01 0x01 0x01 ... 0x01
	//     such that the length of V, in bits, is equal to 8*ceil(hlen/8).
	//     For instance, on an octet-based system, if H is SHA-256, then V
	//     is set to a sequence of 32 octets of value 1.
	V := bytes.Repeat([]byte{0x01}, hash.Size())

	// c.  Set: K = 0x00 0x00 0x00 ... 0x00
	//     such that the length of K, in bits, is equal to 8*ceil(hlen/8).
	K := make([]byte, hash.Size())

	// d.  Set: K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
	//     where '||' denotes concatenation.  In other words, we compute
	//     HMAC with key K, over the concatenation of the following, in
	//     order: the current value of V, a sequence of eight bits of value
	//     0, the encoding of the (EC)DSA private key x, and the hashed
	//     message (possibly truncated and extended as specified by the
	//     bits2octets transform).  The HMAC result is the new value of K.
	//     Note that the private key x is in the [1, q-1] range, hence a
	//     proper input for int2octets, yielding rlen bits of output, i.e.,
	//     an integral number of octets (rlen is a multiple of 8).
	hm := hmac.New(hash.New, K)
	hm.Write(V)
	hm.Write([]byte{0x00})
	hm.Write(int2octets(x, qlen))
	hm.Write(bits2octets(h1Digest, q))
	K = hm.Sum(nil)

	// e.  Set:
	//     V = HMAC_K(V)
	vm := hmac.New(hash.New, K)
	vm.Write(V)
	V = vm.Sum(nil)

	// f.  Set:
	//     K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
	//     Note that the "internal octet" is 0x01 this time.
	hm = hmac.New(hash.New, K)
	hm.Write(V)
	hm.Write([]byte{0x01})
	hm.Write(int2octets(x, qlen))
	hm.Write(bits2octets(h1Digest, q))
	K = hm.Sum(nil)

	// g.  Set:
	//     V = HMAC_K(V)
	vm = hmac.New(hash.New, K)
	vm.Write(V)
	V = vm.Sum(nil)

	// h.  Apply the following algorithm until a proper value is found for k:
	for {
		// 1.  Set T to the empty sequence.  The length of T (in bits) is
		//     denoted tlen; thus, at that point, tlen = 0.
		T := make([]byte, 0, qlen/8)
		//  2.  While tlen < qlen, do the following:
		for len(T) < qlen/8 {
			//         V = HMAC_K(V)
			vm = hmac.New(hash.New, K)
			vm.Write(V)
			V = vm.Sum(nil)
			//         T = T || V
			T = append(T, V...)
		}
		//  3.  Compute: k = bits2int(T)
		k := bits2int(T, qlen)
		one := big.NewInt(1)
		// If that value of k is within the [1,q-1] range, then the generation of k is finished.
		// (The "suitable for DSA or ECDSA" check in step h.3 is omitted.)
		if k.Cmp(one) >= 0 && k.Cmp(q) < 0 {
			return k
		}

		// Otherwise, compute:
		//    K = HMAC_K(V || 0x00)
		km := hmac.New(hash.New, K)
		km.Write(V)
		km.Write([]byte{0x00})
		K = km.Sum(nil)

		//    V = HMAC_K(V)
		km = hmac.New(hash.New, K)
		km.Write(V)
		V = km.Sum(nil)

		// and loop (try to generate a new T, and so on).
	}
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
