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
	"crypto/elliptic"
	"crypto/rand"
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
