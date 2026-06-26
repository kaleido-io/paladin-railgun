package railgunnote

import (
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/stretchr/testify/require"
)

func TestBuildWitnessDerivesConsistentValues(t *testing.T) {
	var sk babyjub.PrivateKey
	copy(sk[:], hexBytes("0x1111111111111111111111111111111111111111111111111111111111111111"))
	id := &Identity{SpendingKey: sk}
	copy(id.ViewingKey[:], hexBytes("0x2222222222222222222222222222222222222222222222222222222222222222"))

	mpk, err := id.MasterPublicKey()
	require.NoError(t, err)
	random := big.NewInt(0x33)
	npk, err := NotePublicKey(mpk, random)
	require.NoError(t, err)

	var addr [20]byte
	addr[19] = 0xaa
	token := TokenIDERC20(addr)
	value := big.NewInt(1000)

	// Build a tree with the input note's commitment
	commitment, err := Commitment(npk, token, value)
	require.NoError(t, err)
	tree, err := NewMerkleTree(MerkleDepth)
	require.NoError(t, err)
	leafIndex := tree.Insert(commitment)
	root := tree.Root()
	path := tree.Proof(leafIndex)

	w, err := BuildWitness(&WitnessInputs{
		Identity:        id,
		Token:           token,
		MerkleRoot:      root,
		BoundParamsHash: big.NewInt(42),
		Inputs:          []SpendInput{{Random: random, Value: value, LeafIndex: leafIndex, PathElements: path}},
		Outputs:         []SpendOutput{{NPK: npk, Value: value}}, // 1-in-1-out, balance holds
	})
	require.NoError(t, err)
	require.Len(t, w.Nullifiers, 1)
	require.Len(t, w.CommitmentsOut, 1)

	// Output commitment must equal the recomputed commitment
	require.Equal(t, 0, w.CommitmentsOut[0].Cmp(commitment))

	// The Merkle proof in the witness must reconstruct the root
	recomputed, err := VerifyProof(commitment, leafIndex, path)
	require.NoError(t, err)
	require.Equal(t, 0, root.Cmp(recomputed))

	// Witness has all circuit signals
	for _, sig := range []string{"merkleRoot", "boundParamsHash", "nullifiers", "commitmentsOut",
		"token", "publicKey", "signature", "randomIn", "valueIn", "pathElements", "leavesIndices",
		"nullifyingKey", "npkOut", "valueOut"} {
		require.Contains(t, w.Inputs, sig)
	}
}
