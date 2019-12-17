package main

import (
	"time"
)

type MiningService struct {
	inWork     bool
	stop       chan struct{}
	minedBlock *Block
}

func NewMiningService() *MiningService {
	return &MiningService{
		inWork: false,
		stop:   make(chan struct{}),
	}
}

func (m *MiningService) process() {
	for range time.NewTicker(time.Millisecond * 50).C {
		info("Try to solve task")

		// update nonce
		// miningBlock.Nonce = m.generateNonce()

		// calc count first zeros
		// countZero := 0
		// for _, s := range calcHash(miningBlock.String()) {
		// 	if string(s) == "0" {
		// 		countZero++
		// 		continue
		// 	}
		// 	break
		// }

		// solve a task
		// if countZero >= miningBlock.Complexity {
		// 	if solved -> validate block
		// 	if isValidBlock(miningBlock) {
		// if block valid -> append to blockchain
		// and notify nodes
		// blockchain = append(blockchain, miningBlock)
		// miningSuccessNotice <- &VMBlocks{
		// 	ValidBlock:  miningBlock,
		// 	MiningBlock: createMiningBlock(),
		// }
		//
		// info("Task solved", miningBlock.Nonce)
		// }
		// }

		select {
		case <-m.stop:
			return
		}
	}
}

func (m *MiningService) generateNonce() string {
	// todo unimplemented
	return ""
}

func (m *MiningService) SetMinedBlock(minedBlock *Block) {
	m.minedBlock = minedBlock
}

func (m *MiningService) Start() {
	if m.inWork {
		return
	}
	go m.process()
}

func (m *MiningService) Stop() {
	m.stop <- struct{}{}
}
