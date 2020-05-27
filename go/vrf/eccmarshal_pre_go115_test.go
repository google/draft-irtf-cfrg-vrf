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

package vrf

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

func TestCompressedMarshalUnmarshal(t *testing.T) {
	c := elliptic.P256()
	_, Ax, Ay, err := elliptic.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	b := marshalCompressed(c, Ax, Ay)
	Bx, By, err := unmarshalCompressed(c, b)
	if err != nil {
		t.Fatal(err)
	}
	if Bx.Cmp(Ax) != 0 {
		t.Fatalf("Bx: %v, want %v", Bx, Ax)
	}
	if By.Cmp(Ay) != 0 {
		t.Fatalf("By: %v, want %v", By, Ay)
	}
}

func hexd(t testing.TB, h string) []byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// https://github.com/google/wycheproof/blob/master/testvectors/ecdh_secp256r1_test.json
func TestWycheproof(t *testing.T) {
	curve := elliptic.P256() //secp256r1
	for _, tc := range []struct {
		tcID    int
		comment string
		public  []byte
		private []byte
		shared  []byte
		result  error
	}{

		{
			tcID:    2,
			comment: "compressed public key",
			public:  hexd(t, "3039301306072a8648ce3d020106082a8648ce3d0301070322000362d5bd3372af75fe85a040715d0f502428e07046868b0bfdfa61d731afe44f26"),
			private: hexd(t, "0612465c89a023ab17855b0a6bcebfd3febb53aef84138647b5352e02c10c346"),
			shared:  hexd(t, "53020d908b0219328b658b525f26780e3ae12bcd952bb25a93bc0895e1714285"),
			result:  nil,
		},
		{
			tcID:    243,
			comment: "invalid public key",
			public:  hexd(t, "3039301306072a8648ce3d020106082a8648ce3d03010703220002fd4bf61763b46581fd9174d623516cf3c81edd40e29ffa2777fb6cb0ae3ce535"),
			private: hexd(t, "6f953faff3599e6c762d7f4cabfeed092de2add1df1bc5748c6cbb725cf35458"),
			result:  errInvalidPoint,
		},
		{
			tcID:    244,
			comment: "public key is a low order point on twist",
			public:  hexd(t, "3039301306072a8648ce3d020106082a8648ce3d03010703220003efdde3b32872a9effcf3b94cbf73aa7b39f9683ece9121b9852167f4e3da609b"),
			private: hexd(t, "00d27edf0ff5b6b6b465753e7158370332c153b468a1be087ad0f490bdb99e5f02"),
			result:  errInvalidPoint,
		},
		{
			tcID:    245,
			comment: "public key is a low order point on twist",
			public:  hexd(t, "3039301306072a8648ce3d020106082a8648ce3d03010703220002efdde3b32872a9effcf3b94cbf73aa7b39f9683ece9121b9852167f4e3da609b"),
			private: hexd(t, "00d27edf0ff5b6b6b465753e7158370332c153b468a1be087ad0f490bdb99e5f03"),
			result:  errInvalidPoint,
		},
		{
			tcID:    246,
			comment: "public key is a low order point on twist",
			public:  hexd(t, "3039301306072a8648ce3d020106082a8648ce3d03010703220002c49524b2adfd8f5f972ef554652836e2efb2d306c6d3b0689234cec93ae73db5"),
			private: hexd(t, "0095ead84540c2d027aa3130ff1b47888cc1ed67e8dda46156e71ce0991791e835"),
			result:  errInvalidPoint,
		},
		{
			tcID:    247,
			comment: "public key is a low order point on twist",
			public:  hexd(t, "3039301306072a8648ce3d020106082a8648ce3d0301070322000318f9bae7747cd844e98525b7ccd0daf6e1d20a818b2175a9a91e4eae5343bc98"),
			private: hexd(t, "00a8681ef67fb1f189647d95e8db00c52ceef6d41a85ba0a5bd74c44e8e62c8aa4"),
			result:  errInvalidPoint,
		},
		{
			tcID:    248,
			comment: "public key is a low order point on twist",
			public:  hexd(t, "3039301306072a8648ce3d020106082a8648ce3d0301070322000218f9bae7747cd844e98525b7ccd0daf6e1d20a818b2175a9a91e4eae5343bc98"),
			private: hexd(t, "00a8681ef67fb1f189647d95e8db00c52ceef6d41a85ba0a5bd74c44e8e62c8aa5"),
			result:  errInvalidPoint,
		},
		{
			tcID:    249,
			comment: "public key is a low order point on twist",
			public:  hexd(t, "3039301306072a8648ce3d020106082a8648ce3d03010703220003c49524b2adfd8f5f972ef554652836e2efb2d306c6d3b0689234cec93ae73db5"),
			private: hexd(t, "0095ead84540c2d027aa3130ff1b47888cc1ed67e8dda46156e71ce0991791e834"),
			result:  errInvalidPoint,
		},
	} {
		t.Run(fmt.Sprintf("%d", tc.tcID), func(t *testing.T) {
			t.Logf("comment: %s", tc.comment)

			// parse public key as x509 ASN.1
			var pki struct {
				Raw       asn1.RawContent
				Algorithm pkix.AlgorithmIdentifier
				PublicKey asn1.BitString
			}
			if _, err := asn1.Unmarshal(tc.public, &pki); err != nil {
				t.Fatal(err)
			}
			asn1Data := pki.PublicKey.RightAlign()
			t.Logf("public key: %x", asn1Data)

			x, y, err := unmarshalCompressed(curve, asn1Data)
			if !errors.Is(err, tc.result) {
				t.Errorf("got err %q, want %q", err, tc.result)
			}
			if err != nil {
				return
			}

			// Compute ECDH shared secret to complete the test
			Sx, _ := curve.ScalarMult(x, y, tc.private)
			if got := Sx.Bytes(); !bytes.Equal(got, tc.shared) {
				t.Errorf("shared secret: %x, want %x", got, tc.shared)
			}
		})
	}
}
