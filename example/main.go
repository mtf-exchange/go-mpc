// This example demonstrates a complete 3-of-3 DKLS23 threshold ECDSA flow:
//
//  1. Key Generation  — Feldman VSS DKG, no trusted dealer
//  2. Pairwise Setup  — Base OT + OT Extension + VOLE + FZero
//  3. Signing         — 3-round threshold ECDSA
//  4. Key Refresh     — rotate shares without changing the public key
//
// Each Node is an independent party. The orchestrator here is a stand-in for
// whatever transport you use in production (HTTP, gRPC, message queue, etc.).
package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"dkls23-example/node"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/chrisalmeida/go-mpc/dkls23"
)

func main() {
	const threshold = 3
	allIDs := []int{1, 2, 3}

	fmt.Println("DKLS23 Threshold ECDSA — 3-of-3 Demo")
	fmt.Println()

	// ── Phase 1: Distributed Key Generation ─────────────────────────

	fmt.Println("Phase 1: Key Generation")

	nodes := make([]*node.Node, len(allIDs))
	for i, id := range allIDs {
		nodes[i] = node.New(id, allIDs, threshold)
	}

	// Round 1: sample polynomial, broadcast Feldman commitments.
	allRound1 := make(map[int]*dkls23.DKGRound1Output)
	for _, n := range nodes {
		out, err := n.DKGRound1()
		if err != nil {
			log.Fatalf("DKG round 1 node %d: %v", n.ID, err)
		}
		allRound1[n.ID] = out
	}

	// Round 2: decommit pairwise shares.
	allRound2 := make(map[int]*dkls23.DKGRound2Output)
	for _, n := range nodes {
		out, err := n.DKGRound2(allRound1)
		if err != nil {
			log.Fatalf("DKG round 2 node %d: %v", n.ID, err)
		}
		allRound2[n.ID] = out
	}

	// Finalize: verify commitments, compute Shamir share, derive public key.
	var pubKey []byte
	for _, n := range nodes {
		pk, err := n.DKGFinalize(allRound1, allRound2)
		if err != nil {
			log.Fatalf("DKG finalize node %d: %v", n.ID, err)
		}
		pubKey = pk
	}
	fmt.Printf("  public key: %s\n\n", hex.EncodeToString(pubKey))

	// ── Phase 2: Pairwise VOLE + FZero Setup ────────────────────────

	fmt.Println("Phase 2: Pairwise Setup (one-time)")

	for i := 0; i < len(nodes); i++ {
		for j := i + 1; j < len(nodes); j++ {
			if err := nodes[i].SetupPairwiseWith(nodes[j]); err != nil {
				log.Fatalf("pairwise setup %d↔%d: %v", nodes[i].ID, nodes[j].ID, err)
			}
			fmt.Printf("  node %d ↔ node %d: VOLE + FZero established\n", nodes[i].ID, nodes[j].ID)
		}
	}
	fmt.Println()

	// ── Phase 3: Threshold Signing ──────────────────────────────────

	message := []byte("hello threshold ECDSA")
	fmt.Println("Phase 3: Signing")
	fmt.Printf("  message: %q\n", message)

	r, s := sign(nodes, allIDs, message)

	fmt.Printf("  r: %s\n", hex.EncodeToString(r))
	fmt.Printf("  s: %s\n", hex.EncodeToString(s))

	if node.VerifySignature(pubKey, message, r, s) {
		fmt.Println("  signature valid")
	} else {
		log.Fatal("  signature verification FAILED")
	}

	// Verification data for https://emn178.github.io/online-tools/ecdsa/verify/
	// Settings: Curve=secp256k1, Hash=SHA-256, Input=UTF-8, Key format=Raw
	parsedPub, err := btcec.ParsePubKey(pubKey)
	if err != nil {
		log.Fatalf("parse pubkey: %v", err)
	}
	var rScalar, sScalar btcec.ModNScalar
	rScalar.SetByteSlice(r)
	sScalar.SetByteSlice(s)
	derSig := ecdsa.NewSignature(&rScalar, &sScalar).Serialize()

	fmt.Println()
	fmt.Println("  Verify at: https://emn178.github.io/online-tools/ecdsa/verify/")
	fmt.Printf("  Public key (uncompressed): %s\n", hex.EncodeToString(parsedPub.SerializeUncompressed()))
	fmt.Printf("  Signature (DER): %s\n", hex.EncodeToString(derSig))
	fmt.Printf("  Message: %s\n", message)
	fmt.Println()

	// ── Phase 4: Key Refresh ────────────────────────────────────────

	fmt.Println("Phase 4: Key Refresh")

	// Round 1: each node samples a zero-constant polynomial and commits.
	allRefR1 := make(map[int]*dkls23.RefreshRound1Output)
	for _, n := range nodes {
		out, err := n.RefreshRound1()
		if err != nil {
			log.Fatalf("refresh round 1 node %d: %v", n.ID, err)
		}
		allRefR1[n.ID] = out
	}

	// Round 2: decommit shares and reveal seeds.
	allRefR2 := make(map[int]*dkls23.RefreshRound2Output)
	for _, n := range nodes {
		out, err := n.RefreshRound2(allRefR1)
		if err != nil {
			log.Fatalf("refresh round 2 node %d: %v", n.ID, err)
		}
		allRefR2[n.ID] = out
	}

	// Finalize: verify, update shares, re-randomise VOLE/FZero.
	for _, n := range nodes {
		if err := n.RefreshFinalize(allRefR1, allRefR2); err != nil {
			log.Fatalf("refresh finalize node %d: %v", n.ID, err)
		}
	}
	fmt.Println("  shares rotated, public key unchanged")

	// Sign again with refreshed shares to prove correctness.
	refreshMsg := []byte("post-refresh signing works")
	r2, s2 := sign(nodes, allIDs, refreshMsg)

	if node.VerifySignature(pubKey, refreshMsg, r2, s2) {
		fmt.Println("  post-refresh signature valid")
	} else {
		log.Fatal("  post-refresh signature verification FAILED")
	}
	fmt.Println()

	fmt.Println("Done.")
}

// sign runs the 3-round signing protocol across all nodes and returns (r, s).
func sign(nodes []*node.Node, signers []int, message []byte) (r, s []byte) {
	nodeMap := make(map[int]*node.Node, len(nodes))
	for _, n := range nodes {
		nodeMap[n.ID] = n
	}

	sigID := node.SessionID()

	// Round 1: nonce commitments.
	r1States := make(map[int]*dkls23.Round1State)
	r1Msgs := make(map[int]map[int]*dkls23.Round1Msg)
	for _, n := range nodes {
		st, msgs, err := n.SignRound1(sigID, signers)
		if err != nil {
			log.Fatalf("sign round 1 node %d: %v", n.ID, err)
		}
		r1States[n.ID] = st
		r1Msgs[n.ID] = msgs
	}

	// Round 2: VOLE multiply, decommit nonces.
	r2States := make(map[int]*dkls23.Round2State)
	r2Msgs := make(map[int]map[int]*dkls23.Round2Msg)
	for _, n := range nodes {
		in := routeMsgs(signers, n.ID, r1Msgs)
		st, msgs, err := n.SignRound2(r1States[n.ID], in)
		if err != nil {
			log.Fatalf("sign round 2 node %d: %v", n.ID, err)
		}
		r2States[n.ID] = st
		r2Msgs[n.ID] = msgs
	}

	// Round 3: consistency checks, compute signature fragments.
	r3Frags := make(map[int]map[int]*dkls23.Round3Msg)
	for _, n := range nodes {
		in := routeMsgs(signers, n.ID, r2Msgs)
		frags, err := n.SignRound3(r2States[n.ID], message, in)
		if err != nil {
			log.Fatalf("sign round 3 node %d: %v", n.ID, err)
		}
		r3Frags[n.ID] = frags
	}

	// Combine: node 1 aggregates fragments into (r, s).
	combiner := nodeMap[1]
	rx := node.ComputeRx(signers, r2States)
	myFrag := r3Frags[1][1]
	var myW, myU btcec.ModNScalar
	myW.SetByteSlice(myFrag.W_i)
	myU.SetByteSlice(myFrag.U_i)

	allFrags := make(map[int]*dkls23.Round3Msg)
	for _, j := range signers {
		if j != 1 {
			allFrags[j] = r3Frags[j][1]
		}
	}

	r, s, err := combiner.SignCombine(&rx, &myW, &myU, allFrags, message)
	if err != nil {
		log.Fatalf("sign combine: %v", err)
	}
	return r, s
}

// routeMsgs collects inbound messages for myID from all other signers.
func routeMsgs[T any](signers []int, myID int, allMsgs map[int]map[int]T) map[int]T {
	m := make(map[int]T)
	for _, j := range signers {
		if j != myID {
			m[j] = allMsgs[j][myID]
		}
	}
	return m
}
