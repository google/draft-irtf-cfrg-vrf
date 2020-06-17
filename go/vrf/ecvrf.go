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
	"fmt"
	"math/big"
	"sync"
)

var initonce sync.Once

func initAll() {
	initP256SHA256TAI()
}

// ECVRFP256SHA256TAI returns a elliptic curve based VRF instantiated with
// P256, SHA256, and the "Try And Increment" strategy for hashing to the curve.
func ECVRFP256SHA256TAI() ECVRF {
	initonce.Do(initAll)
	return p256SHA256TAI
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

type ECVRF interface {
	Params() *ECVRFParams

	// Prove returns proof pi that beta is the correct hash output.
	// beta is deterministic in the sense that it always
	// produces the same output beta given a pair of inputs (sk, alpha).
	Prove(sk *PrivateKey, alpha []byte) (pi []byte)

	// ProofToHash allows anyone to deterministically obtain the VRF hash
	// output beta directly from the proof value pi.
	//
	// ProofToHash should be run only on pi that is known to have been produced by Prove
	// Clients attempting to verify untrusted inputs should use Verify.
	ProofToHash(pi []byte) (beta []byte, err error)
}

// ECVRFParams holds shared values across ECVRF implementations.
// ECVRFParams also has generic algorithms that rely on ECVRFAux for specific sub algorithms.
type ECVRFParams struct {
	suite    byte           // Single nonzero octet specifying the ECVRF ciphersuite.
	ec       elliptic.Curve // Elliptic curve defined over F.
	fieldLen uint           // Length, in bytes, of a field element in F. Defined as 2n in spec.
	ptLen    uint           // Length, in bytes, of an EC point encoded as an octet string.
	qLen     uint           // Length, in bytes, of the prime order of the EC group (Typically ~fieldLen).
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

	// IntToString converts a nonnegative integer a to to octet string of length rLen.
	IntToString(x *big.Int, rLen uint) []byte

	// ArbitraryStringToPoint converts an arbitrary 32 byte string s to an EC point.
	ArbitraryStringToPoint(s []byte) (Px, Py *big.Int, err error)

	// HashToCurve is a collision resistant hash of VRF input alpha to H, an EC point in G.
	HashToCurve(Y *PublicKey, alpha []byte) (Hx, Hy *big.Int)

	// GenerateNonoce generates the nonce value k in a deterministic, pseudorandom fashion.
	GenerateNonce(sk *PrivateKey, h []byte) (k *big.Int)
}

// Prove returns proof pi that beta is the correct hash output.
// sk - VRF private key
// alpha - input alpha, an octet string
// Returns pi - VRF proof, octet string of length ptLen+n+qLen
func (p ECVRFParams) Prove(sk *PrivateKey, alpha []byte) []byte {
	// 1.  Use SK to derive the VRF secret scalar x and the VRF public key Y = x*B
	// 2.  H = ECVRF_hash_to_curve(suite_string, Y, alpha_string)
	Hx, Hy := p.aux.HashToCurve(sk.Public(), alpha) // suite_string is implicitly used in HashToCurve

	// 3.  h_string = point_to_string(H)
	hString := p.aux.PointToString(Hx, Hy)

	// 4.  Gamma = x*H
	Gx, Gy := p.ec.ScalarMult(Hx, Hy, sk.d.Bytes())

	// 5.  k = ECVRF_nonce_generation(SK, h_string)
	k := p.aux.GenerateNonce(sk, hString)

	// 6.  c = ECVRF_hash_points(H, Gamma, k*B, k*H)
	Ux, Uy := p.ec.ScalarBaseMult(k.Bytes())
	Vx, Vy := p.ec.ScalarMult(Hx, Hy, k.Bytes())
	c := p.hashPoints(Hx, Hy, Gx, Gy, Ux, Uy, Vx, Vy)

	// 7.  s = (k + c*x) mod q
	s := new(big.Int).Mul(c, sk.d)
	s.Add(k, s)
	s.Mod(s, p.ec.Params().N)

	// 8.  pi_string = point_to_string(Gamma) || int_to_string(c, n) || int_to_string(s, qLen)
	pi := new(bytes.Buffer)
	pi.Write(p.aux.PointToString(Gx, Gy))
	pi.Write(p.aux.IntToString(c, p.fieldLen/2)) // 2n = fieldLen
	pi.Write(p.aux.IntToString(s, p.qLen))

	return pi.Bytes()
}

// ProofToHash returns VRF hash output beta from VRF proof pi.
//
// Input: pi - VRF proof, octet string of length ptLen+n+qLen
// Output: beta - VRF hash output, octet string of length hLen or "INVALID"
//
// ProofToHash should be run only on pi that is known to have been produced by
// Prove, or from within Verify.
//
// https://tools.ietf.org/html/draft-irtf-cfrg-vrf-06#section-5.2
func (p ECVRFParams) ProofToHash(pi []byte) (beta []byte, err error) {
	// 1.  D = ECVRF_decode_proof(pi_string)
	Gx, Gy, _, _, err := p.decodeProof(pi)
	// 2.  If D is "INVALID", output "INVALID" and stop
	if err != nil {
		return nil, err
	}

	// 3.  (Gamma, c, s) = D
	// 4.  three_string = 0x03 = int_to_string(3, 1), a single octet with value 3

	// 5.  beta_string = Hash(suite_string || three_string || point_to_string(cofactor * Gamma))
	h := p.hash.New()
	h.Write([]byte{p.suite, 0x03})
	h.Write(p.aux.PointToString(p.ec.ScalarMult(Gx, Gy, p.cofactor.Bytes())))

	// 6.  Output beta_string
	return h.Sum(nil), nil
}

//
// Auxilary functions
//

// hashPoints accepts X,Y pairs of EC points in G and returns an hash value between 0 and 2^(8n)-1
//
// https://tools.ietf.org/html/draft-irtf-cfrg-vrf-06#section-5.4.3
func (p ECVRFParams) hashPoints(pm ...*big.Int) (c *big.Int) {
	if len(pm)%2 != 0 {
		panic("odd number of inputs")
	}
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

// decodeProof
//
// Input: pi_string - VRF proof, octet string (ptLen+n+qLen octets)
//
// Output:
//    Gx, Gy - Gamma - EC point
//    c - integer between 0 and 2^(8n)-1
//    s - integer between 0 and 2^(8qLen)-1
//    or "INVALID"
//
// https://tools.ietf.org/html/draft-irtf-cfrg-vrf-06#section-5.4.4
func (p ECVRFParams) decodeProof(pi []byte) (Gx, Gy, c, s *big.Int, err error) {
	n := p.fieldLen / 2
	if got, want := uint(len(pi)), p.ptLen+n+p.qLen; got != want {
		return nil, nil, nil, nil, fmt.Errorf("len(pi): %v, want %v", got, want)
	}

	//    1.  let gamma_string = pi_string[0]...p_string[ptLen-1]
	gStr := pi[:p.ptLen]
	//    2.  let c_string = pi_string[ptLen]...pi_string[ptLen+n-1]
	cStr := pi[p.ptLen : p.ptLen+n]
	//    3.  let s_string =pi_string[ptLen+n]...pi_string[ptLen+n+qLen-1]
	sStr := pi[p.ptLen+n:]

	//    4.  Gamma = string_to_point(gamma_string)
	Gx, Gy, err = p.aux.StringToPoint(gStr)
	//    5.  if Gamma = "INVALID" output "INVALID" and stop.
	if err != nil || Gx == nil || Gy == nil {
		return nil, nil, nil, nil, fmt.Errorf("aux.StringToPoint() failed: %w", err)
	}

	//    6.  c = string_to_int(c_string)
	c = new(big.Int).SetBytes(cStr)
	//    7.  s = string_to_int(s_string)
	s = new(big.Int).SetBytes(sStr)
	//    8.  Output Gamma, c, and s
	return Gx, Gy, c, s, nil
}
