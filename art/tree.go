package art

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"gcrypt/x3dh"
	"math/bits"

	"github.com/cloudflare/circl/dh/x448"
)

type Node struct {
	Secret  []byte
	Public  []byte
	Message *x3dh.InitialMessage
	Index   uint
}

type CopathNode struct {
	Public []byte
	Index  uint
}

type Copath []CopathNode

type Path []Node

type Tree struct {
	Nodes []Node
	Self  uint
}

func log2(n uint16) (floored uint8, ceiled uint8) {
	floored = 15 - uint8(bits.LeadingZeros16(n))
	if n == (1 << floored) {
		ceiled = floored
	} else {
		ceiled = floored + 1
	}
	return
}

func sum512(src []byte) []byte {
	h := sha512.Sum512(src)
	return h[:]
}

func CreateTree(private []byte, peers []x3dh.PublicKeys, groupId []byte) Tree {
	len_cached := len(peers)
	initiator := x3dh.New(private)
	/*
		count of all nodes in a tree with n leaves is 2n+1
		2(n+1) - 1 = 2n+2-1 = 2n+1
		n for the peers, +1 for the initiator
	*/
	size := (2 * len_cached) + 1
	nodes := make([]Node, size)
	//messages := make([]x3dh.InitialMessage, len_cached)
	//filling leaves
	for i, peer := range peers {
		shared, message := initiator.PrepareInitialMessage(peer, groupId)
		//messages[i] = message
		shared = sum512(shared)[:56]
		public := x448.Key{}
		x448.KeyGen(&public, (*x448.Key)(shared))
		nodes[size-i-1] = Node{
			shared,
			public[:],
			&message,
			uint(size - i - 1),
		}
	}
	identity, _ := initiator.Identity_Converted()
	nodes[size-len_cached-1] = Node{
		private,
		identity,
		nil,
		uint(size - len_cached - 1),
	}
	//filling parents to the root
	for i := size - len_cached - 2; i >= 0; i-- {
		left := nodes[(2*i)+1]
		right := nodes[(2*i)+2]
		shared := x448.Key{}
		public := x448.Key{}
		x448.Shared(&shared, (*x448.Key)(left.Secret), (*x448.Key)(right.Public))
		x448.KeyGen(&public, &shared)
		nodes[i] = Node{
			shared[:],
			public[:],
			nil,
			uint(i),
		}
	}
	return Tree{
		Nodes: nodes,
		Self:  uint(size - len_cached - 1),
	}
}

func (tree Tree) GetCopath(node_index uint) Copath {
	level, ceiled := log2(uint16(node_index))
	//if node is the most left
	if 1<<ceiled == node_index+1 {
		level++
	}
	path := make(Copath, level)
	for node_index != 0 {
		sibling := getSibling(node_index)
		path[level-1] = CopathNode{
			Public: tree.Nodes[sibling].Public,
			Index:  sibling,
		}
		node_index = getParent(node_index)
		level--
	}
	return path
}

func (tree Tree) GetPath(node_index uint) Path {
	_, level := log2(uint16(node_index))
	path := make(Path, level)
	for node_index != 0 {
		path[level-1] = tree.Nodes[node_index]
		node_index = getParent(node_index)
		level--
	}
	return path
}

func getParent(index uint) uint {
	if isEven(index) {
		return (index / 2) - 1
	}
	return index / 2
}

func getSibling(leaf uint) uint {
	if isEven(leaf) {
		return leaf - 1
	}
	return leaf + 1
}

func isEven(n uint) bool { return ((n & 1) == 0) }

func SharedSecretFromMessage(x3dh x3dh.X3dh, initalMessage x3dh.InitialMessage) []byte {
	shared := x3dh.SharedKeyFromMessage(initalMessage)
	shared = sum512(shared)[:56]
	bson, _ := base64.RawStdEncoding.DecodeString(initalMessage.Path)
	v := Copath{}
	json.Unmarshal(bson, &v)
	for i := len(v) - 1; i >= 0; i-- {
		node_shared := x448.Key{}
		x448.Shared(&node_shared, (*x448.Key)(shared), (*x448.Key)(v[i].Public))
		shared = node_shared[:]
	}
	return shared
}
