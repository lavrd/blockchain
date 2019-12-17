package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/net/websocket"
)

const (
	// constants are used to understand
	// what data came from the node

	// VMBlock means that received valid / mining block
	VMBlock = iota
	// FACT means that received new fact
	FACT
)

// Nodes type for store current connections
type Nodes struct {
	// store to send data to the nodes
	Connections []*websocket.Conn `json:"connections"`
	// store to send the current node list to a new node
	IPs []string `json:"i_ps"`
}

// Fact type for store fact
type Fact struct {
	// has unique id for identify
	ID   string       `json:"id"`
	Fact *interface{} `json:"fact,omitempty"`
}

// Block type for store block
type Block struct {
	Index int `json:"index"`
	// calculated from block info
	Hash string `json:"hash"`
	// point to previous block hash
	PrevHash  string    `json:"prev_hash"`
	Timestamp time.Time `json:"timestamp"`
	Facts     []*Fact   `json:"facts,omitempty"`
	// mining complexity
	Complexity int `json:"complexity"`
	// random number to form a hash for successful mining
	Nonce string `json:"nonce"`
}

// VMBlocks type for send valid / mining block to other nodes
type VMBlocks struct {
	ValidBlock  *Block `json:"valid_block,omitempty"`
	MiningBlock *Block `json:"mining_block"`
}

// API type for communicate with other nodes or clients
type API struct {
	// information type
	// used only when send valid / mining block or new fact
	// to other nodes
	Type int `json:"type,omitempty"`
	// mining complexity
	Complexity int `json:"complexity,omitempty"`
	// error message
	Error    string    `json:"error,omitempty"`
	Fact     *Fact     `json:"fact,omitempty"`
	VMBlocks *VMBlocks `json:"vm_blocks,omitempty"`
	// nodes addresses
	Nodes      []string `json:"nodes,omitempty"`
	Facts      []*Fact  `json:"facts,omitempty"`
	Blockchain []*Block `json:"blockchain,omitempty"`
}

var (
	// blockchain
	blockchain []*Block
	// mining block
	miningBlock *Block
	// unconfirmed facts
	unconfirmedFacts []*Fact
	// nodes
	nodes = &Nodes{}

	// initial node addr
	iNode = flag.String("i", "", "set initial node address")
	// node http server port
	hPort = flag.String("h", "", "set node http server port")
	// node websocket server port
	wsPort = flag.String("ws", "", "set node websocket server port")
	// verbose output flag
	v = flag.Bool("v", false, "enable verbose output")

	// channel announcing nodes about successful mining
	miningSuccessNotice = make(chan *VMBlocks)
	// channel announcing nodes about new fact
	newFactNotice = make(chan *Fact)
)

func init() {
	// parse flags
	flag.Parse()

	// if have init node flag
	if *iNode != "" {
		// init new node
		initNode()
	} else {
		// init root node
		initRootNode()
	}
}

// init root node
func initRootNode() {
	info("Init root node")

	// init blockchain with genesis block
	blockchain = []*Block{{
		Timestamp: time.Now(),
	}}

	// calc hash for genesis block
	blockchain[0].Hash = calcHash(blockchain[0].String())

	// init mining block
	miningBlock = createMiningBlock()
}

// init node
func initNode() {
	info("Init node")

	var (
		t *API
		// origin node address
		// needed for send other nodes
		// that they know with which node to interact
		origin = "ws://localhost:" + *wsPort + "/p2p"
	)

	// get current nodes
	r, err := http.Get("http://" + *iNode + "/nodes")
	if err != nil {
		panic(err)
	}
	defer r.Body.Close()

	err = json.NewDecoder(r.Body).Decode(&t)
	if err != nil {
		panic(err)
	}

	// set current nodes addr
	nodes.IPs = t.Nodes

	info("Current nodes addrs", t.Nodes)

	// get current blockchain and mining block
	r, err = http.Get("http://" + *iNode + "/blockchain")
	if err != nil {
		panic(err)
	}
	defer r.Body.Close()

	err = json.NewDecoder(r.Body).Decode(&t)
	if err != nil {
		panic(err)
	}

	// set current mining block
	miningBlock = t.VMBlocks.MiningBlock
	// set current blockchain
	blockchain = t.Blockchain

	info("Current blockchain", t.Blockchain,
		"current mining block", t.VMBlocks.MiningBlock)

	// connect to each nodes
	for _, addr := range nodes.IPs {
		// dial to node
		ws, err := websocket.Dial(addr, "", origin)
		if err != nil {
			panic(err)
		}

		// start receiving node
		go receive(ws)

		// added to connections
		nodes.Connections = append(nodes.Connections, ws)
	}

	// dial to init node
	ws, err := websocket.Dial("ws://"+*iNode+"/p2p", "", origin)
	if err != nil {
		panic(err)
	}

	// start receiving init node
	go receive(ws)

	// added to connections and addrs
	nodes.IPs = append(nodes.IPs, ws.RemoteAddr().String())
	nodes.Connections = append(nodes.Connections, ws)
}

// returns latest blockchain block
func latestBlock() *Block {
	return blockchain[len(blockchain)-1]
}

// create next mining block
func createMiningBlock() *Block {
	info("Creating mining block")

	var (
		// get latest block
		latestBlk = latestBlock()

		// create new block
		blk = &Block{
			Index:     latestBlk.Index + 1,
			PrevHash:  latestBlk.Hash,
			Timestamp: time.Now(),
			Facts:     unconfirmedFacts,
		}
	)

	// flush unconfirmed facts
	// now he in new mining block
	unconfirmedFacts = nil

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

// String returns block data in string
func (b *Block) String() string {
	facts := ""

	for _, fact := range b.Facts {
		facts += fact.ID
		facts += fmt.Sprint(*fact.Fact)
	}

	return b.PrevHash + b.Timestamp.String() + b.Nonce +
		fmt.Sprint(b.Index, facts, b.Complexity)
}

// calc sha256 hash
func calcHash(data string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(data)))
}

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

// print info log in verbose mode
func info(info ...interface{}) {
	if *v {
		log.Println(info...)
	}
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

// handle new node
func p2pHandler(ws *websocket.Conn) {
	// add node to connections
	nodes.IPs = append(nodes.IPs, ws.RemoteAddr().String())
	nodes.Connections = append(nodes.Connections, ws)

	// start receiving data from node
	receive(ws)
}

// handle block request
// sending blockchain and mining block
func blockchainHandler(w http.ResponseWriter, r *http.Request) {
	info(r.RemoteAddr, "/blockchain")

	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(API{
		Blockchain: blockchain,
		VMBlocks: &VMBlocks{
			MiningBlock: miningBlock,
		},
	})
	if err != nil {
		panic(err)
	}
}

// handler, that when requested by method get,
// sends the facts of the specified block,
// and, if requested by method post, takes a new unconfirmed fact
func factHandler(w http.ResponseWriter, r *http.Request) {
	info(r.RemoteAddr, "/fact", r.Method)

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:

		id, err := strconv.Atoi(r.URL.Query().Get("id"))
		// send that received id is invalid
		if err != nil || id < 0 || id > len(blockchain)-1 {
			w.WriteHeader(http.StatusInternalServerError)
			err = json.NewEncoder(w).Encode(API{
				Error: "Invalid block id",
			})
			if err != nil {
				panic(err)
			}
			return
		}

		// send block facts
		err = json.NewEncoder(w).Encode(API{
			Facts: blockchain[id].Facts,
		})
		if err != nil {
			panic(err)
		}

		break
	case http.MethodPost:
		var (
			fact interface{}
		)

		err := json.NewDecoder(r.Body).Decode(&fact)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			err = json.NewEncoder(w).Encode(API{
				Error: "Invalid incoming data",
			})
			if err != nil {
				panic(err)
			}
			return
		}

		t := &Fact{ID: calcHash(time.Now().String()), Fact: &fact}
		// notify nodes of a new fact
		newFactNotice <- t
		// append to other unconfirmed facts
		unconfirmedFacts = append(unconfirmedFacts, t)
	}
}

// handle that try mining
func mineHandler(_ http.ResponseWriter, r *http.Request) {
	info(r.RemoteAddr, "/mine")

	// try mining
	go tryMining(r.URL.Query().Get("nonce"))
}

// handler that send nodes addresses
func nodesHandler(w http.ResponseWriter, r *http.Request) {
	info(r.RemoteAddr, "/nodes")

	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(API{Nodes: nodes.IPs})
	if err != nil {
		panic(err)
	}
}

// try mining
func tryMining(nonce string) {
	info("Try to solve task")

	// update nonce
	miningBlock.Nonce = nonce

	// calc count first zeros
	countZero := 0
	for _, s := range calcHash(miningBlock.String()) {
		if string(s) == "0" {
			countZero++
			continue
		}
		break
	}

	// solve a task
	if countZero >= miningBlock.Complexity {
		// if solved -> validate block
		if isValidBlock(miningBlock) {
			// if block valid -> append to blockchain
			// and notify nodes
			blockchain = append(blockchain, miningBlock)
			miningSuccessNotice <- &VMBlocks{
				ValidBlock:  miningBlock,
				MiningBlock: createMiningBlock(),
			}

			info("Task solved", nonce)
		}
	}
}

func main() {
	// start http server
	go func() {
		http.HandleFunc("/blockchain", blockchainHandler)
		http.HandleFunc("/fact", factHandler)
		http.HandleFunc("/mine", mineHandler)
		http.HandleFunc("/nodes", nodesHandler)

		info("Start http server on port", *hPort)
		panic(http.ListenAndServe(":"+*hPort, nil))
	}()

	// start websocket server
	go func() {
		http.Handle("/p2p", websocket.Handler(p2pHandler))

		info("Start websocket server on port", *wsPort)
		panic(http.ListenAndServe(":"+*wsPort, nil))
	}()

	// notify nodes
	notify()
}
