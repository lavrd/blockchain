package main

import (
	"fmt"
	"time"
)

type Block struct {
	Index     int       `json:"index"`
	Hash      string    `json:"hash"`
	PrevHash  string    `json:"prev_hash"`
	Timestamp time.Time `json:"timestamp"`
	Txs       []*Tx     `json:"txs,omitempty"`
	// mining complexity
	Complexity int `json:"complexity"`
	// random number to form a hash for successful mining
	Nonce string `json:"nonce"`
}

func (b *Block) String() string {
	txs := ""

	for _, tx := range b.Txs {
		txs += tx.ID
		txs += fmt.Sprint(tx.Data)
	}

	return b.PrevHash + b.Timestamp.String() + b.Nonce +
		fmt.Sprint(b.Index, txs, b.Complexity)
}

type Tx struct {
	ID   string      `json:"id"`
	Data interface{} `json:"data,omitempty"`
}
type Txs []*Tx

func CreateMiningBlock(txs Txs) *Block {
	info("Creating mining block")

	var (
		// get latest block
		latestBlk = latestBlock()

		// create new block
		blk = &Block{
			Index:     latestBlk.Index + 1,
			PrevHash:  latestBlk.Hash,
			Timestamp: time.Now(),
			Txs:       txs,
		}
	)

	// flush unconfirmed txs
	// now it's in new mining block
	// unconfirmedFacts = nil

	if time.Since(latestBlk.Timestamp) < time.Second*10 {
		// if time since create latest block < 10s
		// increase complexity
		blk.Complexity = latestBlk.Complexity + 1
	} else {
		// if < 10s -> decrease
		blk.Complexity = latestBlk.Complexity - 1
	}

	blk.Hash = calcHash(blk.String())

	info("Create new mining block", blk)

	return blk
}
