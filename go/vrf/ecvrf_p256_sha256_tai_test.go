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
	"crypto/elliptic"
	"encoding/hex"
	"math/big"
	"testing"
)

func hd(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// test vector from https://tools.ietf.org/html/rfc6979#appendix-A.2.5
func TestGenerateNonceRFC6979(t *testing.T) {
	initP256SHA256TAI()
	v := p256SHA256TAI

	SK := &PrivateKey{
		d: new(big.Int).SetBytes(hd(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721")),
		PublicKey: PublicKey{
			X:     new(big.Int).SetBytes(hd(t, "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6")),
			Y:     new(big.Int).SetBytes(hd(t, "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299")),
			Curve: elliptic.P256(),
		},
	}
	m := []byte("sample")

	if got, want := v.aux.GenerateNonce(SK, m).Bytes(),
		hd(t, "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60"); !bytes.Equal(got, want) {
		t.Errorf("k: %x, want %x", got, want)
	}
}
