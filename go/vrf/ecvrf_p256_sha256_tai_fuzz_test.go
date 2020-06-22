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

// +build gofuzz

package vrf

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"reflect"
	"testing"
)

var writeCorpus = flag.Bool("writecorpus", false, "Write initial corpus from test vectors")

func TestInputMarshal(t *testing.T) {
	for _, i := range []Input{
		{SK: [skLen]byte{1, 1, 1, 1}, PI: [piLen]byte{2, 2, 2, 2}, Alpha: []byte{3, 3, 3, 3}},
	} {
		enc, err := i.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary(): %v", err)
		}
		t.Logf("MarshalBinary(): %x", enc)
		var j Input
		if err := j.UnmarshalBinary(enc); err != nil {
			t.Fatalf("UnmarshalBinary(): %v", err)
		}
		if !reflect.DeepEqual(i, j) {
			t.Errorf("Unmarshal: %#v, want %#v", j, i)
		}
	}
}

// go test ./vrf/  -tags gofuzz --writecorpus
func TestInitialCorpus(t *testing.T) {
	for i, tc := range P256SHA256TAITestVectors(t) {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			v := ECVRFP256SHA256TAI()
			sk := NewKey(v.Params().ec, tc.SK)

			pi := v.Prove(sk, tc.alpha)
			if !bytes.Equal(pi, tc.pi) {
				t.Errorf("Prove(%s): %x, want %x", tc.alpha, pi, tc.pi)
			}

			if _, err := v.Verify(sk.Public(), pi, tc.alpha); err != nil {
				t.Errorf("Verify(): %v", err)
			}

			t.Logf("Fuzz test vector: %x%x%x", tc.SK, tc.pi, tc.alpha)

			if *writeCorpus {
				input, err := NewInput(tc.SK, pi, tc.alpha)
				if err != nil {
					t.Fatal(err)
				}
				b, err := input.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				if err := ioutil.WriteFile(fmt.Sprintf("./corpus/P256SHA523TAI-%0d", i), b, 0644); err != nil {
					t.Fatal(err)
				}

			}
		})
	}
}
