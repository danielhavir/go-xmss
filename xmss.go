package xmss

import (
	"bytes"
	"crypto/rand"
)

const (
	indexBytes = 4
	fullHeight = 16
	d          = 1
)

var (
	treeHeight = uint32(fullHeight / d)
	prvBytes   = uint32(indexBytes + 4*n)
	pubBytes   = uint32(2 * n)
	signBytes  = uint32(indexBytes + n + d*wotsSignLen + fullHeight*n)
)

// SignBytes denotes the length of the signature
var SignBytes = signBytes

// Section 4.1.5. Algorithm 8: ltree
// Computes a leaf node from a WOTS public key using an L-tree.
// Note that this destroys the used WOTS public key.
func lTree(leaf, seed []byte, wotsPub publicWOTS, a *address) {
	l := wlen
	var parentNodes uint32
	height := uint32(0)
	var idxIn, idxOut uint32

	a.setTreeHeight(height)

	for l > 1 {
		parentNodes = l >> 1
		for i := uint32(0); i < parentNodes; i++ {
			a.setTreeIndex(i)
			idxOut = i * n
			idxIn = i * 2 * n
			// Hashes the nodes at (i*2)*params->n and (i*2)*params->n + 1
			hashH(wotsPub[idxOut:idxOut+n], seed, wotsPub[idxIn:idxIn+2*n], a)
		}

		// If the row contained an odd number of nodes, the last node was not
		// hashed. Instead, we pull it up to the next layer.
		if l&1 == 1 {
			idxOut = (l >> 1) * n
			idxIn = (l - 1) * n
			copy(wotsPub[idxOut:idxOut+n], wotsPub[idxIn:idxIn+n])
			l = (l >> 1) + 1
		} else {
			l = l >> 1
		}
		height++
		a.setTreeHeight(height)
	}
	copy(leaf, wotsPub[:n])

}

// Section 4.1.10. Algorithm 13: XMSS_rootFromSig - Compute a root node from a tree signature
// Computes a root node given a leaf and an auth path
func computeRoot(root, leaf, authPath, pubSeed []byte, leafIdx uint32, a *address) {
	buf := make([]byte, 2*n)

	// If leafidx is odd (last bit = 1), current path element is a right child
	// and auth_path has to go left. Otherwise it is the other way around.
	if leafIdx&1 == 1 {
		copy(buf[n:], leaf)
		copy(buf[:n], authPath[:n])
	} else {
		copy(buf[:n], leaf)
		copy(buf[n:], authPath[:n])
	}
	authPath = authPath[n:]

	for i := uint32(0); i < treeHeight-1; i++ {
		a.setTreeHeight(i)
		leafIdx >>= 1
		a.setTreeIndex(leafIdx)

		// Pick the right or left neighbor, depending on parity of the node.
		if leafIdx&1 == 1 {
			hashH(buf[n:], pubSeed, buf, a)
			copy(buf[:n], authPath[:n])
		} else {
			hashH(buf[:n], pubSeed, buf, a)
			copy(buf[n:], authPath[:n])
		}

		authPath = authPath[n:]
	}

	a.setTreeHeight(treeHeight - 1)
	leafIdx >>= 1
	a.setTreeIndex(leafIdx)
	hashH(root, pubSeed, buf, a)
}

// Used for pseudo-random key generation.
// Generates the seed for the WOTS key pair at address a
// Takes n-byte prvSeed and returns n-byte seed using 32 byte address a
func getSeed(seed, prvSeed []byte, a *address) {
	a.setChainAddr(0)
	a.setHashAddr(0)
	a.setKeyAndMask(0)

	bytes := a.toByte()
	hashPRF(seed, prvSeed, bytes)
}

// Computes the leaf at a given address. First generates the WOTS key pair,
// then computes leaf using lTree. As this happens position independent, we
// only require that address encodes the right ltree-address.
func generateLeafWOTS(leaf, prvSeed, pubSeed []byte, ltreeA, otsA *address) {
	seed := make([]byte, n)

	getSeed(seed, prvSeed, otsA)
	prv := *generatePrivate(seed)
	pub := *prv.generatePublic(pubSeed, otsA)

	lTree(leaf, pubSeed, pub, ltreeA)
}

// Section 4.1.6. Algorithm 9: treeHash
// For a given leaf index, computes the authentication path and the resulting
// root node using Merkle's TreeHash algorithm.
// Expects the layer and tree parts of subtree_addr to be set.
func treehash(root, authPath, prvSeed, pubSeed []byte, leafIdx uint32, subtreeA address) {
	stack := make([]byte, (treeHeight+1)*n)
	heights := make([]uint32, treeHeight+1)
	offset := uint32(0)

	var otsA, ltreeA, nodeA address
	var treeIdx uint32

	otsA.copySubtreeAddr(subtreeA)
	ltreeA.copySubtreeAddr(subtreeA)
	nodeA.copySubtreeAddr(subtreeA)

	otsA.setType(xmssAddrTypeOTS)
	ltreeA.setType(xmssAddrTypeLTREE)
	nodeA.setType(xmssAddrTypeHASHTREE)

	for i := uint32(0); i < uint32(1<<treeHeight); i++ {
		// Add the next leaf node to the stack.
		ltreeA.setLTreeAddr(i)
		otsA.setOTSAddr(i)
		generateLeafWOTS(stack[offset*n:offset*n+n], prvSeed, pubSeed, &ltreeA, &otsA)
		heights[offset] = 0

		// If this is a node we need for the auth path..
		if (leafIdx ^ 1) == i {
			copy(authPath[:n], stack[offset*n:offset*n+n])
		}
		offset++

		// While the top-most nodes are of equal height..
		for offset >= 2 && (heights[offset-1] == heights[offset-2]) {
			// Compute index of the new node, in the next layer.
			treeIdx = (i >> (heights[offset-1] + 1))

			// Hash the top-most nodes from the stack together
			// Note that tree height is the 'lower' layer, even though we use
			// the index of the new node on the 'higher' layer. This follows
			// from the fact that we address the hash function calls.
			nodeA.setTreeHeight(heights[offset-1])
			nodeA.setTreeIndex(treeIdx)
			stackIdx := (offset - 2) * n
			hashH(stack[stackIdx:stackIdx+n], pubSeed, stack[stackIdx:stackIdx+2*n], &nodeA)

			offset--
			// Note that the top-most node is now one layer higher
			heights[offset-1]++

			if ((leafIdx >> heights[offset-1]) ^ 1) == treeIdx {
				authIdx := heights[offset-1] * n
				stackIdx = (offset - 1) * n
				copy(authPath[authIdx:authIdx+n], stack[stackIdx:stackIdx+n])
			}
		}
	}

	copy(root, stack[:n])
}

// PrivateXMSS key
type PrivateXMSS []byte

// PublicXMSS key
type PublicXMSS []byte

// SignatureXMSS struct
type SignatureXMSS []byte

// GenerateXMSSKeypair Section 4.1.7. Algorithm 10: XMSS_keyGen - Generate an XMSS key pair
// Generates a XMSS key pair for a given parameter set.
// Format private: [(32bit) index || prvSeed || seed || pubSeed || root]
// Format public: [root || pubSeed]
func GenerateXMSSKeypair() (*PrivateXMSS, *PublicXMSS) {
	var prv PrivateXMSS
	var pub PublicXMSS
	prv = make([]byte, prvBytes)
	pub = make([]byte, pubBytes)

	// We do not need the auth path in key generation, but it simplifies the
	// code to have just one treehash routine that computes both root and path
	// in one function
	authPath := make([]byte, treeHeight*n)
	var topTreeA address

	topTreeA.setLayerAddr(d - 1)
	copy(prv[:indexBytes], make([]byte, indexBytes))
	// Initialize prvSeed, prfSeed and pubSeed
	rand.Read(prv[indexBytes : indexBytes+3*n])
	copy(pub[n:2*n], prv[indexBytes+2*n:indexBytes+3*n])

	// Compute root node of the top-most subtree
	treehash(pub, authPath, prv[indexBytes:indexBytes+n], pub[n:2*n], 0, topTreeA)
	copy(prv[indexBytes+3*n:], pub[:n])

	return &prv, &pub
}

// Verify Section 4.1.10. Algorithm 14: XMSS_verify - Verify an XMSS signature using the corresponding XMSS public key and a message
// Verifies a given message signature pair under a given public key.
// Note that this assumes a pk without an OID, i.e. [root || pubSeed]
func Verify(m, signature []byte, pub PublicXMSS) (match bool) {
	pubRoot := pub[:n]
	pubSeed := pub[n:]
	var wotsSign signatureWOTS
	var wotsPub publicWOTS
	leaf := make([]byte, n)
	root := make([]byte, n)
	msgHash := make([]byte, n)
	msgLen := len(signature) - int(signBytes)

	var otsA, ltreeA, nodeA address
	otsA.setType(xmssAddrTypeOTS)
	ltreeA.setType(xmssAddrTypeLTREE)
	nodeA.setType(xmssAddrTypeHASHTREE)

	idx := fromByte(signature[:indexBytes], indexBytes)

	copy(m[signBytes:], signature[signBytes:])
	hashMsg(msgHash, signature[indexBytes:indexBytes+n], pubRoot, m[signBytes-4*n:], idx)
	copy(root, msgHash)

	signature = signature[indexBytes+n:]

	for i := uint32(0); i < d; i++ {
		idxLeaf := (uint32(idx) & ((1 << treeHeight) - 1))
		idx = idx >> treeHeight

		otsA.setLayerAddr(i)
		ltreeA.setLayerAddr(i)
		nodeA.setLayerAddr(i)

		ltreeA.setTreeAddr(idx)
		otsA.setTreeAddr(idx)
		nodeA.setTreeAddr(idx)

		// The WOTS public key is only correct if the signature was correct
		otsA.setOTSAddr(idxLeaf)

		wotsSign = signature[:wotsSignLen]
		// Initially, root = mhash, but on subsequent iterations it is the root
		// of the subtree below the currently processed subtree.
		wotsPub = *wotsSign.getPublic(root, pubSeed, &otsA)
		signature = signature[wotsSignLen:]

		// Compute the leaf node using the WOTS public key
		ltreeA.setLTreeAddr(idxLeaf)
		lTree(leaf, pubSeed, wotsPub, &ltreeA)

		// Compute the root node of this subtree
		computeRoot(root, leaf, signature[:treeHeight*n], pubSeed, idxLeaf, &nodeA)
		signature = signature[treeHeight*n:]
	}

	// Check if the root node equals the root node in the public key
	if !bytes.Equal(root, pubRoot) {
		// Zero the message
		copy(m[signBytes:], make([]byte, msgLen))
		match = false
	} else {
		copy(m[signBytes:], signature)
		match = true
	}
	return
}

// Sign Section 4.1.9. Algorithm 12: XMSS_sign - Generate an XMSS signature and update the XMSS private key
// Signs a message. Returns an array containing the signature followed by the
// message and an updated secret key.
func (prv PrivateXMSS) Sign(m []byte) *SignatureXMSS {
	var signature SignatureXMSS
	signature = make([]byte, int(signBytes)+len(m))

	prvSeed := prv[indexBytes : indexBytes+n]
	prfSeed := prv[indexBytes+n : indexBytes+2*n]
	pubSeed := prv[indexBytes+2*n : indexBytes+3*n]
	pubRoot := prv[indexBytes+3*n : indexBytes+4*n]

	root := make([]byte, n)
	msgHash := make([]byte, n)
	otsSeed := make([]byte, n)
	var idxLeaf uint32

	var otsA address
	otsA.setType(xmssAddrTypeOTS)

	// Already put the message in the right place, to make it easier to prepend
	// things when computing the hash over the message
	copy(signature[signBytes:], m)

	idx := fromByte(prv[:indexBytes], indexBytes)
	copy(signature[:indexBytes], prv[:indexBytes])

	// Increment the index in the private key
	copy(prv[:indexBytes], toByte(int(idx+1), indexBytes))

	// Compute the digest randomization value
	idxBytes := toByte(int(idx), 32)
	hashPRF(signature[indexBytes:indexBytes+n], prfSeed, idxBytes)

	// Compute the message hash
	hashMsg(msgHash, signature[indexBytes:indexBytes+n], pubRoot, signature[signBytes-4*n:], idx)
	copy(root, msgHash)

	for i := uint32(0); i < d; i++ {
		idxLeaf = uint32(idx) & ((1 << treeHeight) - 1)
		idx = idx >> treeHeight

		otsA.setLayerAddr(i)
		otsA.setTreeAddr(idx)
		otsA.setOTSAddr(idxLeaf)

		// Get a seed for the WOTS keypair
		getSeed(otsSeed, prvSeed, &otsA)

		wotsPrv := *generatePrivate(otsSeed)
		wotsSign := *wotsPrv.sign(root, pubSeed, &otsA)
		copy(signature[indexBytes+n:indexBytes+n+wotsSignLen], wotsSign)

		// Compute the authentication path for the used WOTS leaf
		treehash(root, signature[indexBytes+n+wotsSignLen:indexBytes+n+wotsSignLen+treeHeight*n], prvSeed, pubSeed, idxLeaf, otsA)
	}

	return &signature
}
