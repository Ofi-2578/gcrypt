package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"gcrypt/art"
	"gcrypt/x3dh"
)

// testing only
func main() {
	init := make([]byte, 56)
	peers := make([]x3dh.X3dh, 6)
	peers_keys := make([]x3dh.PublicKeys, 6)
	for i := 0; i < 6; i++ {
		private := make([]byte, 56)
		rand.Read(private)
		peers[i] = x3dh.New(private)
		peers_keys[i] = peers[i].Keys()
	}

	tree := art.CreateTree(init, peers_keys, []byte{0})
	size := len(tree.Nodes)
	for i := 0; i < 6; i++ {
		copath := tree.GetCopath(tree.Nodes[size-i-1].Index)
		bson, _ := json.Marshal(copath)
		tree.Nodes[size-i-1].Message.Path = base64.RawStdEncoding.EncodeToString(bson)
		s := art.SharedSecretFromMessage(peers[i], *tree.Nodes[size-i-1].Message)
		fmt.Println(s)
		// s must be the same
	}

}
