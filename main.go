package main

import (
	"golang.org/x/net/websocket"
)

// returns latest blockchain block
// func latestBlock() *Block {
// 	return blockchain[len(blockchain)-1]
// }

// receive data from node
func receive(ws *websocket.Conn) {
	info("Start receive data from", ws.RemoteAddr(), "node")

	for {
		t := &API{}

		err := websocket.JSON.Receive(ws, t)
		if err != nil {
			// if error -> node disconnect
			nodeRemove(ws)
			return
		}

		// switch data type
		switch t.Type {
		case VMBlock:
			// if block
			info("From", ws.RemoteAddr(), "node received VMBLOCKS", t.VMBlocks)

			// valid this block
			if isValidBlock(t.VMBlocks.ValidBlock) {
				// if valid -> append to blockchain
				blockchain = append(blockchain, t.VMBlocks.ValidBlock)
			} else {
				return
			}

			// update mining block
			miningBlock = t.VMBlocks.MiningBlock

			// check on the repetition of facts
			for _, tFact := range t.VMBlocks.ValidBlock.Facts {
				for i, lFact := range unconfirmedFacts {
					if tFact.ID == lFact.ID {
						// if found -> remove fact
						unconfirmedFacts = append(unconfirmedFacts[:i], unconfirmedFacts[i+1:]...)
					}
				}
			}

			break
		case FACT:
			// if fact
			info("From", ws.RemoteAddr(), "node received new fact", t.Fact.ID, *t.Fact.Fact)

			// append to unconfirmed facts
			unconfirmedFacts = append(unconfirmedFacts, t.Fact)
		}
	}
}

// remove node from nodes storage
func nodeRemove(ws *websocket.Conn) {
	info(ws.RemoteAddr(), "node disconnect")

	// search node id
	for i, addr := range nodes.IPs {
		// if found
		if ws.RemoteAddr().String() == addr {
			// remove from store
			nodes.IPs = append(nodes.IPs[:i], nodes.IPs[i+1:]...)
			nodes.Connections = append(nodes.Connections[:i], nodes.Connections[i+1:]...)
		}
	}
}

// block validation
func isValidBlock(unconfirmedBlk *Block) bool {
	info("Block validation")

	latestBlk := latestBlock()
	unconfirmedBlk.Nonce = ""

	if latestBlk.Index+1 != unconfirmedBlk.Index ||
		latestBlk.Hash != unconfirmedBlk.PrevHash ||
		calcHash(unconfirmedBlk.String()) != unconfirmedBlk.Hash {

		info("Block", unconfirmedBlk, "failed validation")

		return false
	}

	info("Block", unconfirmedBlk, "passed validation")

	return true
}

// notify the nodes of a successful mining or new fact
func notify() {
	info("Start notify nodes")

	for {
		select {
		case t, ok := <-miningSuccessNotice:
			// if successful mining
			if ok {
				info("Mining success notice", t)

				// update mining block
				miningBlock = t.MiningBlock

				// notify nodes
				for _, node := range nodes.Connections {
					err := websocket.JSON.Send(node, &API{
						Type: VMBlock,
						VMBlocks: &VMBlocks{
							ValidBlock:  t.ValidBlock,
							MiningBlock: t.MiningBlock,
						},
					})
					if err != nil {
						// if err -> node disconnect
						nodeRemove(node)
					}
				}
			}
		case fact, ok := <-newFactNotice:
			// if new fact
			if ok {
				info("New fact notice", fact.ID, *fact.Fact)

				// notify nodes
				for _, node := range nodes.Connections {
					err := websocket.JSON.Send(node, API{
						Type: FACT, Fact: fact,
					})
					if err != nil {
						// if err -> node disconnect
						nodeRemove(node)
					}
				}
			}
		}
	}
}

func main() {}
