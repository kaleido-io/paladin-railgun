// Copyright © 2024 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package railgunnote

import (
	"crypto/ed25519"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// pubkeyToParts mirrors the reference test: masterPublicKey = hexToBigInt(pubkey)
// and viewingPublicKey = pubkey left-padded to 32 bytes.
func pubkeyToParts(t *testing.T, pubkeyHex string) (*big.Int, ed25519.PublicKey) {
	raw, err := hex.DecodeString(pubkeyHex)
	require.NoError(t, err)
	vpk := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(vpk[ed25519.PublicKeySize-len(raw):], raw)
	return new(big.Int).SetBytes(raw), vpk
}

// TestRailgunAddressReferenceVectors validates the codec against the official
// vectors from @railgun-community/engine (key-derivation/__tests__/bech32-encode.test.ts).
// Byte-identical output here proves interoperability with real Railgun wallets.
func TestRailgunAddressReferenceVectors(t *testing.T) {
	vectors := []struct {
		pubkey  string
		chain   *Chain
		address string
	}{
		{
			pubkey:  "00000000",
			chain:   &Chain{Type: 0, ID: 1}, // EVM
			address: "0zk1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqunpd9kxwatwqyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhshkca",
		},
		{
			pubkey:  "01bfd5681c0479be9a8ef8dd8baadd97115899a9af30b3d2455843afb41b",
			chain:   &Chain{Type: 0, ID: 56}, // EVM
			address: "0zk1qyqqqqdl645pcpreh6dga7xa3w4dm9c3tzv6ntesk0fy2kzr476pkunpd9kxwatw8qqqqqdl645pcpreh6dga7xa3w4dm9c3tzv6ntesk0fy2kzr476pkcsu8tp",
		},
		{
			pubkey:  "01bfd5681c0479be9a8ef8dd8baadd97115899a9af30b3d2455843afb41b",
			chain:   &Chain{Type: 1, ID: 56}, // non-EVM type
			address: "0zk1qyqqqqdl645pcpreh6dga7xa3w4dm9c3tzv6ntesk0fy2kzr476pkumpd9kxwatw8qqqqqdl645pcpreh6dga7xa3w4dm9c3tzv6ntesk0fy2kzr476pkwrfm4m",
		},
		{
			pubkey:  "ee6b4c702f8070c8ddea1cbb8b0f6a4a518b77fa8d3f9b68617b664550e75f64",
			chain:   nil, // chain-agnostic
			address: "0zk1q8hxknrs97q8pjxaagwthzc0df99rzmhl2xnlxmgv9akv32sua0kfrv7j6fe3z53llhxknrs97q8pjxaagwthzc0df99rzmhl2xnlxmgv9akv32sua0kg0zpzts",
		},
	}

	for i, v := range vectors {
		mpk, vpk := pubkeyToParts(t, v.pubkey)
		data := AddressData{MasterPublicKey: mpk, ViewingPublicKey: vpk, Chain: v.chain}

		encoded, err := EncodeRailgunAddress(data)
		require.NoError(t, err, "vector %d", i)
		require.Equal(t, v.address, encoded, "vector %d encode", i)
		require.Len(t, encoded, RailgunAddressLength, "vector %d length", i)

		decoded, err := DecodeRailgunAddress(v.address)
		require.NoError(t, err, "vector %d decode", i)
		require.Equal(t, 0, decoded.MasterPublicKey.Cmp(mpk), "vector %d mpk", i)
		require.Equal(t, vpk, decoded.ViewingPublicKey, "vector %d vpk", i)
		require.Equal(t, v.chain, decoded.Chain, "vector %d chain", i)
	}
}

// TestRailgunAddressIdentityRoundTrip encodes a real identity's address and
// decodes it back to the same masterPublicKey and Ed25519 viewing public key.
func TestRailgunAddressIdentityRoundTrip(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i*7 + 1)
	}
	id, err := IdentityFromSeed(seed)
	require.NoError(t, err)

	chain := &Chain{Type: 0, ID: 1337}
	addr, err := id.RailgunAddress(chain)
	require.NoError(t, err)
	require.Len(t, addr, RailgunAddressLength)

	decoded, err := DecodeRailgunAddress(addr)
	require.NoError(t, err)

	mpk, err := id.MasterPublicKey()
	require.NoError(t, err)
	require.Equal(t, 0, decoded.MasterPublicKey.Cmp(mpk))
	require.Equal(t, ed25519.PublicKey(id.ViewingPublicKey()), decoded.ViewingPublicKey)
	require.Equal(t, chain, decoded.Chain)
}

func TestRailgunAddressChainAgnosticRoundTrip(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(255 - i)
	}
	id, err := IdentityFromSeed(seed)
	require.NoError(t, err)

	addr, err := id.RailgunAddress(nil)
	require.NoError(t, err)

	decoded, err := DecodeRailgunAddress(addr)
	require.NoError(t, err)
	require.Nil(t, decoded.Chain, "chain-agnostic address must decode to a nil chain")
}

func TestDecodeRailgunAddressErrors(t *testing.T) {
	// Valid reference address, tampered last char -> bad checksum.
	valid := "0zk1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqunpd9kxwatwqyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhshkca"
	bad := valid[:len(valid)-1] + "b"
	_, err := DecodeRailgunAddress(bad)
	require.Error(t, err, "tampered checksum must fail")

	// Wrong prefix.
	_, err = DecodeRailgunAddress("rg1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqunpd9kxwatwqyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsfhuuw")
	require.Error(t, err, "wrong prefix must fail")

	// Not bech32 at all.
	_, err = DecodeRailgunAddress("not-an-address")
	require.Error(t, err)
}

func TestEncodeRailgunAddressValidation(t *testing.T) {
	_, vpk := pubkeyToParts(t, "00")
	// nil master public key
	_, err := EncodeRailgunAddress(AddressData{ViewingPublicKey: vpk})
	require.Error(t, err)
	// wrong viewing key length
	_, err = EncodeRailgunAddress(AddressData{MasterPublicKey: big.NewInt(1), ViewingPublicKey: []byte{1, 2, 3}})
	require.Error(t, err)
	// chain id too large (>56 bits)
	_, err = EncodeRailgunAddress(AddressData{MasterPublicKey: big.NewInt(1), ViewingPublicKey: vpk, Chain: &Chain{ID: uint64(1) << 56}})
	require.Error(t, err)
}

func TestIsRailgunAddress(t *testing.T) {
	require.True(t, IsRailgunAddress("0zk1qyqqqqqqqqqqqqqqq"))
	require.False(t, IsRailgunAddress("alice@node1"))
	require.False(t, IsRailgunAddress("0x1234"))
	require.False(t, IsRailgunAddress(""))
	require.False(t, IsRailgunAddress("0zk")) // no separator
}
