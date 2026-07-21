// Copyright © 2026 Kaleido, Inc.
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
	"fmt"
	"math/big"
	"strings"

	"github.com/btcsuite/btcd/btcutil/bech32"
)

// Railgun ("0zk") address codec — the canonical, interoperable address format
// used by Railgun wallets. An address is a bech32m string with human-readable
// prefix "0zk" encoding a 73-byte payload:
//
//	version(1) ‖ masterPublicKey(32) ‖ networkID(8) ‖ viewingPublicKey(32)
//
// where networkID = (chainType‖chainID) XOR "railgun", masterPublicKey is the
// BN254 field element addressing the recipient, and viewingPublicKey is the
// recipient's 32-byte Ed25519 public key. This matches the Railgun engine
// reference (@railgun-community/engine key-derivation/bech32.ts) byte-for-byte.
const (
	railgunAddressHRP     = "0zk"
	railgunAddressVersion = 0x01
	// RailgunAddressLength is the fixed character length of a "0zk" address.
	RailgunAddressLength = 127
)

// railgunNetworkXORMask is "railgun" (7 bytes) with a trailing zero byte. The
// reference XORs the 8-byte network id with this mask "to make the address
// prettier" (buffer-xor leaves the 8th byte unchanged as it XORs with nothing).
// XOR is an involution, so the same mask both encodes and decodes.
var railgunNetworkXORMask = [8]byte{'r', 'a', 'i', 'l', 'g', 'u', 'n', 0x00}

// allChainsNetworkID is the pre-XOR network id denoting a chain-agnostic address.
var allChainsNetworkID = [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// Chain identifies the network an address is scoped to: a 1-byte type (0 = EVM)
// and an id of at most 56 bits. A nil *Chain denotes a chain-agnostic address.
type Chain struct {
	Type uint8
	ID   uint64
}

// AddressData is the decoded content of a Railgun ("0zk") address.
type AddressData struct {
	MasterPublicKey  *big.Int
	ViewingPublicKey ed25519.PublicKey
	Chain            *Chain // nil => chain-agnostic ("all chains")
}

// EncodeRailgunAddress renders a "0zk" bech32m address from the given data.
func EncodeRailgunAddress(a AddressData) (string, error) {
	if a.MasterPublicKey == nil {
		return "", fmt.Errorf("master public key is required")
	}
	if a.MasterPublicKey.Sign() < 0 || a.MasterPublicKey.BitLen() > 256 {
		return "", fmt.Errorf("master public key out of range for 32 bytes")
	}
	if len(a.ViewingPublicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("viewing public key must be %d bytes, got %d", ed25519.PublicKeySize, len(a.ViewingPublicKey))
	}

	nid, err := chainToNetworkID(a.Chain)
	if err != nil {
		return "", err
	}
	xored := xorNetworkID(nid)

	buf := make([]byte, 73)
	buf[0] = railgunAddressVersion
	a.MasterPublicKey.FillBytes(buf[1:33])
	copy(buf[33:41], xored[:])
	copy(buf[41:73], a.ViewingPublicKey)

	words, err := bech32.ConvertBits(buf, 8, 5, true)
	if err != nil {
		return "", err
	}
	// EncodeM (bech32m) has no BIP-173 length cap, unlike Encode/Decode.
	return bech32.EncodeM(railgunAddressHRP, words)
}

// DecodeRailgunAddress parses a "0zk" bech32m address into its components.
func DecodeRailgunAddress(addr string) (AddressData, error) {
	// DecodeNoLimit* is required: a 0zk address is 127 chars, over the BIP-173
	// 90-char cap that Decode/DecodeGeneric enforce.
	hrp, words, version, err := bech32.DecodeNoLimitWithVersion(addr)
	if err != nil {
		return AddressData{}, err
	}
	if version != bech32.VersionM {
		return AddressData{}, fmt.Errorf("railgun address must be bech32m encoded")
	}
	if hrp != railgunAddressHRP {
		return AddressData{}, fmt.Errorf("invalid address prefix %q (want %q)", hrp, railgunAddressHRP)
	}

	buf, err := bech32.ConvertBits(words, 5, 8, false)
	if err != nil {
		return AddressData{}, err
	}
	if len(buf) != 73 {
		return AddressData{}, fmt.Errorf("invalid address length %d bytes (want 73)", len(buf))
	}
	if buf[0] != railgunAddressVersion {
		return AddressData{}, fmt.Errorf("unsupported address version %d (want %d)", buf[0], railgunAddressVersion)
	}

	var xored [8]byte
	copy(xored[:], buf[33:41])
	chain := networkIDToChain(xorNetworkID(xored))

	vpk := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(vpk, buf[41:73])

	return AddressData{
		MasterPublicKey:  new(big.Int).SetBytes(buf[1:33]),
		ViewingPublicKey: vpk,
		Chain:            chain,
	}, nil
}

// IsRailgunAddress reports whether s looks like a literal "0zk" Railgun address
// (bech32m with HRP "0zk", so it begins "0zk1"), as opposed to a Paladin identity.
func IsRailgunAddress(s string) bool {
	return strings.HasPrefix(s, railgunAddressHRP+"1")
}

// RailgunAddress builds this identity's "0zk" address for the given chain (pass
// nil for a chain-agnostic address).
func (id *Identity) RailgunAddress(chain *Chain) (string, error) {
	mpk, err := id.MasterPublicKey()
	if err != nil {
		return "", err
	}
	return EncodeRailgunAddress(AddressData{
		MasterPublicKey:  mpk,
		ViewingPublicKey: id.ViewingPublicKey(),
		Chain:            chain,
	})
}

// chainToNetworkID packs a chain into its 8-byte network id: 1 byte type then a
// 7-byte big-endian id. A nil chain yields the all-chains sentinel.
func chainToNetworkID(chain *Chain) ([8]byte, error) {
	if chain == nil {
		return allChainsNetworkID, nil
	}
	if chain.ID >= (uint64(1) << 56) {
		return [8]byte{}, fmt.Errorf("chain id %d exceeds 56 bits", chain.ID)
	}
	var nid [8]byte
	nid[0] = chain.Type
	for i := 0; i < 7; i++ {
		nid[7-i] = byte(chain.ID >> (8 * i))
	}
	return nid, nil
}

// networkIDToChain reverses chainToNetworkID; the all-chains sentinel returns nil.
func networkIDToChain(nid [8]byte) *Chain {
	if nid == allChainsNetworkID {
		return nil
	}
	var id uint64
	for _, b := range nid[1:8] {
		id = (id << 8) | uint64(b)
	}
	return &Chain{Type: nid[0], ID: id}
}

func xorNetworkID(nid [8]byte) [8]byte {
	var out [8]byte
	for i := 0; i < 8; i++ {
		out[i] = nid[i] ^ railgunNetworkXORMask[i]
	}
	return out
}
