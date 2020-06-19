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

type (
	p256SHA256SWUSuite struct{ *ECVRFParams }
	p256SHA256SWUAux   struct {
		p256SHA256TAIAux
		params *ECVRFParams
	}
)

var p256SHA256SWU p256SHA256SWUSuite

func initP256SHA256SWU() {
	// https://tools.ietf.org/html/draft-irtf-cfrg-vrf-06#section-5.5
	// This ciphersuite is identical to ECVRF-P256-SHA256-TAI except that
	// the ECVRF_hash_to_curve function and suite_string = 0x02
	p := &ECVRFParams{
		suite:    0x02,            // int_to_string(1, 1)
		ec:       elliptic.P256(), // NIST P-256 elliptic curve, [FIPS-186-4] (Section D.1.2.3).
		fieldLen: 32,              // Params().BitSize / 8 = 2n. Must be a multiple of 2.
		qLen:     32,              // Params().N.BitLen
		ptLen:    33,              // Size of encoded EC point
		cofactor: big.NewInt(1),
		hash:     crypto.SHA256,
	}
	p.aux = p256SHA256SWUAux{
		p256SHA256TAIAux: p256SHA256TAIAux{params: p},
		params:           p,
	}
	p256SHA256SWU.ECVRFParams = p
}

// Params returns the parameters for the ECVRF.
func (s p256SHA256SWUSuite) Params() *ECVRFParams { return s.ECVRFParams }

// HashToCurve implements the Simplified SWU algorithm from section 5.4.1.3.
// SWU is implemented with running time that is independent of the input
// alpha (so-called "constant-time").
func (aux p256SHA256SWUAux) HashToCurve(pub *PublicKey, alpha []byte) (x, y *big.Int) {
	x, y, _, _ = aux.hashToCurve(pub, alpha)
	return
}

// hashToCurveSimplifiedSWU
// Input:
//    suite_string - a single octet specifying ECVRF ciphersuite.
//    pub - public key, an EC point
//    alpha_string - value to be hashed, an octet string
// Output:
//    Hx, Hy - hashed value, a finite EC point in G
//
// https://tools.ietf.org/html/draft-irtf-cfrg-vrf-06#section-5.4.1.3
func (aux *p256SHA256SWUAux) hashToCurve(pub *PublicKey, alpha []byte) (hx, hy, t, w *big.Int) {
	// Fixed options:
	// a and b, constants for the Weierstrass form elliptic curve
	// equation y^2 = x^3 + ax +b for the curve E
	p := aux.params.ec.Params().P
	a := big.NewInt(-3) // A Curve represents a short-form Weierstrass curve with a=-3.
	b := aux.params.ec.Params().B
	one := big.NewInt(1)
	two := big.NewInt(2)

	// 1.   PK_string = EC2OSP(Y)
	// 2.   one_string = 0x01 = I2OSP(1, 1), a single octet with value 1
	// 3.   t_string = Hash(suite_string || one_string || PK_string || alpha_string)
	th := aux.params.hash.New()
	th.Write([]byte{aux.params.suite, 0x01})
	th.Write(aux.PointToString(pub.X, pub.Y))
	th.Write(alpha)

	// 4.   t = string_to_int(t_string) mod p
	t = new(big.Int).SetBytes(th.Sum(nil))
	t.Mod(t, p)

	// 5.   r = -(t^2) mod p
	r := new(big.Int).Mul(t, t)
	r.Neg(r)
	r.Mod(r, p)

	// 6.   d = (r^2 + r) mod p   (d is t^4-t^2 mod p)
	d := new(big.Int).Mul(r, r)
	d.Add(d, r)
	d.Mod(d, p)

	// 7.   If d = 0 then d_inverse = 0; else d_inverse = 1/d mod p
	//      (as long as Hash is secure, the case of d = 0 is an utterly
	//      improbably occurrence;
	//      the two cases can be combined into one by computing d_inverse = d^(p-2) mod p)
	dI := new(big.Int).Exp(d, new(big.Int).Sub(p, two), p)

	// 8.   x = ((-b/a) * (1 + d_inverse)) mod p
	//      c = -b/a
	c := new(big.Int).Mul(new(big.Int).Neg(b), new(big.Int).ModInverse(a, p))
	c.Mod(c, p)
	//      x = (c * (1 + d_inverse)) mod p
	x := new(big.Int).Mul(c, new(big.Int).Add(one, dI))
	x.Mod(x, p)

	// 9.   w = (x^3 + a*x + b) mod p
	//      (this step evaluates the curve equation)
	w = new(big.Int).Mul(x, x)
	w.Mul(w, x)
	w.Add(w, new(big.Int).Mul(a, x))
	w.Add(w, b)
	w.Mod(w, p)

	// 10.  Let e equal the Legendre symbol of w and p (see note below on how to compute e)
	// 11.  If e is equal to 0 or 1 then final_x = x; else final_x = r * x mod p
	//	  (final_x is the x-coordinate of the output; see note below on how to compute it)
	//
	//   In order to make this algorithm run in time that is (almost)
	//   independent of the input (so-called "constant-time"), implementers
	//   should pay particular attention to Steps 10 and 11 above.  These
	//   steps can be implemented using the following approach:
	//
	//   If arithmetic and CMOV are implemented in constant time, then steps 9
	//   and 10 above can be implemented as follows:
	//
	//      e = (w ^ ((p-1)/2))+1 mod p
	//      (At this point, e is 0, 1, or 2, as an integer.)
	e := new(big.Int).Sub(p, one)
	e.Div(e, two)
	e.Exp(w, e, p)
	e.Add(e, one)
	e.Mod(e, p)

	//      Let b = (e+1) / 2, where / denotes integer division with rounding down.
	//      (Note carefully that this step is integer, not modular, division.
	//      Only the last byte of e is needed for this step.
	//      This step converts 0, 1, or 2 to 0 or 1.
	selector := new(big.Int).Add(e, one)
	selector.Div(selector, two)

	//      other_x = r * x mod p
	xOther := new(big.Int).Mul(r, x)
	xOther.Mod(xOther, p)

	//      final_x = CMOV(x, other_x, b)
	xFinal := cmov(x, xOther, selector)

	//   12.  H_prelim = arbitrary_string_to_point(int_to_string(final_x, 2n))
	//        (note: arbitrary_string_to_point will not return INVALID by
	//        correctness of Simple SWU)
	hx, hy, _ = aux.ArbitraryStringToPoint(aux.IntToString(xFinal, aux.params.fieldLen))

	//   13.  If cofactor > 1, set H = cofactor * H; else set H = H_prelim
	if aux.params.cofactor.Cmp(one) > 0 {
		hx, hy = aux.params.ec.ScalarMult(hx, hy, aux.params.cofactor.Bytes())
	}
	return
}

// cmov is a constant time function that returns resultIf1 when selector is 1
// and resultIf0 when selector is 0.
func cmov(resultIf1, resultIf0, selector *big.Int) *big.Int {
	// CMOV can be implemented in constant time a variety of ways; for
	// example, by expanding b from a single bit to an all-0 or all-1 string
	// (accomplished by negating b in standard two's-complement arithmetic)
	b := new(big.Int).Neg(selector)

	// and then applying bitwise XOR and AND operations as follows:
	// resultIf0 XOR ((resultIf1 XOR resultIf0) AND b)
	r := new(big.Int).Xor(resultIf1, resultIf0)
	r.And(r, b)
	r.Xor(resultIf0, r)
	return r
}
