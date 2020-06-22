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
	"encoding/binary"
	"fmt"
)

// To run the fuzzer:
// $ go get -u github.com/dvyukov/go-fuzz/go-fuzz github.com/dvyukov/go-fuzz/go-fuzz-build
// $ cd go/vrf
// $ go-fuzz-build
// $ go-fuzz

const (
	skLen = 32
	piLen = 33 + 16 + 32 // ptLen + fieldLen/2 + qLen
)

type Input struct {
	SK    [skLen]byte
	PI    [piLen]byte
	Alpha []byte
}

func NewInput(sk, pi, alpha []byte) (Input, error) {
	if got := len(sk); got != skLen {
		return Input{}, fmt.Errorf("len(sk): %v, want %v", got, skLen)
	}
	if got := len(pi); got != piLen {
		return Input{}, fmt.Errorf("len(pi): %v, want %v", got, piLen)
	}

	var i Input
	copy(i.SK[:], sk)
	copy(i.PI[:], pi)
	i.Alpha = alpha
	return i, nil
}

func (i Input) MarshalBinary() ([]byte, error) {
	b := new(bytes.Buffer)
	if err := binary.Write(b, binary.BigEndian, i.SK); err != nil {
		return nil, err
	}
	if err := binary.Write(b, binary.BigEndian, i.PI); err != nil {
		return nil, err
	}
	if err := binary.Write(b, binary.BigEndian, i.Alpha); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (i *Input) UnmarshalBinary(data []byte) error {
	b := bytes.NewBuffer(data)
	if err := binary.Read(b, binary.BigEndian, &i.SK); err != nil {
		return err
	}
	if err := binary.Read(b, binary.BigEndian, &i.PI); err != nil {
		return err
	}
	a := new(bytes.Buffer)
	if _, err := a.ReadFrom(b); err != nil {
		return err
	}
	i.Alpha = a.Bytes()
	return nil
}

// Fuzz returns 1 if the fuzzer should increase the priority of the input,
// -1 if the input must not be added to the corpus, and 0 otherwise.
func FuzzVerify(data []byte) int {
	var i Input
	if err := i.UnmarshalBinary(data); err != nil {
		return -1
	}

	v := ECVRFP256SHA256TAI()
	sk := NewKey(v.Params().ec, i.SK[:])
	_, err := v.Verify(sk.Public(), i.PI[:], i.Alpha)
	if err != nil {
		return 0
	}
	return 1
}

func FuzzProve(data []byte) int {
	var i Input
	if err := i.UnmarshalBinary(data); err != nil {
		return -1
	}

	v := ECVRFP256SHA256TAI()
	sk := NewKey(v.Params().ec, i.SK[:])

	// i.PI is unused, we generate it from SK and Alpha.
	pi := v.Prove(sk, i.Alpha)
	beta1, err := v.ProofToHash(pi)
	if err != nil {
		panic(err)
	}

	beta2, err := v.Verify(sk.Public(), pi, i.Alpha)
	if err != nil {
		panic(err)
	}

	if !bytes.Equal(beta1, beta2) {
		panic("beta1 != beta2")
	}
	return 1
}
