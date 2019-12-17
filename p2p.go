package main

import (
	"net"
)

const (
	// MessageBlock means that received new block
	MessageBlock MessageType = iota + 1
	// MessageTx means that received new tx
	MessageTx
)

type MessageType int

// Event type for communicate with other nodes
type Event struct {
	Type MessageType `json:"type"`
}

type Nodes struct {
	// stored to send data to the nodes
	Connections []net.Conn
	// stored to send the current node list to a new node
	IPs []string `json:"ips"`
}

type P2PService struct {
}

func (s *P2PService) InitNode() {
	// info("Init node")

	// var (
	// 	t *API
	// origin node address
	// needed for send other nodes
	// that they know with which node to interact
	// origin = "ws://localhost:" + *wsPort + "/p2p"
	// )

	// get current nodes
	// r, err := http.Get("http://" + *iNode + "/nodes")
	// if err != nil {
	// 	panic(err)
	// }
	// defer r.Body.Close()

	// err = json.NewDecoder(r.Body).Decode(&t)
	// if err != nil {
	// 	panic(err)
	// }

	// set current nodes addr
	// nodes.IPs = t.Nodes

	// info("Current nodes addrs", t.Nodes)

	// get current blockchain and mining block
	// r, err = http.Get("http://" + *iNode + "/blockchain")
	// if err != nil {
	// 	panic(err)
	// }
	// defer r.Body.Close()

	// err = json.NewDecoder(r.Body).Decode(&t)
	// if err != nil {
	// 	panic(err)
	// }
	//
	// set current mining block
	// miningBlock = t.VMBlocks.MiningBlock
	// set current blockchain
	// blockchain = t.Blockchain

	// info("Current blockchain", t.Blockchain,
	// 	"current mining block", t.VMBlocks.MiningBlock)
	//
	// connect to each nodes
	// for _, addr := range nodes.IPs {
	// dial to node
	// ws, err := websocket.Dial(addr, "", origin)
	// if err != nil {
	// 	panic(err)
	// }

	// start receiving node
	// go receive(ws)

	// added to connections
	// nodes.Connections = append(nodes.Connections, ws)
	// }

	// dial to init node
	// ws, err := websocket.Dial("ws://"+*iNode+"/p2p", "", origin)
	// if err != nil {
	// 	panic(err)
	// }

	// start receiving init node
	// go receive(ws)

	// added to connections and addrs
	// nodes.IPs = append(nodes.IPs, ws.RemoteAddr().String())
	// nodes.Connections = append(nodes.Connections, ws)
}

func (s *P2PService) InitBootstrapNode() {
	// info("Init root node")

	// init blockchain with genesis block
	// blockchain = []*Block{{
	// 	Timestamp: time.Now(),
	// }}

	// calc hash for genesis block
	// blockchain[0].Hash = calcHash(blockchain[0].String())

	// init mining block
	// miningBlock = createMiningBlock()
}

func handleConn() {
	// logger.Debug().Msg("new connection")
	//
	// defer func() {
	// 	s.logger.Debug().Msg("connection closed")
	//
	// 	if err := conn.Close(); err != nil {
	// 		s.logger.Error().Err(err)
	// 	}
	// }()
	//
	// reader := bufio.NewReader(conn)
	// scanner := bufio.NewScanner(reader)
	// for scanner.Scan() {
	// 	err := scanner.Err()
	// 	if err != nil {
	// 		s.logger.Error().Err(err)
	// 		return
	// 	}
	//
	// 	log := scanner.Text()
	// 	s.logger.Debug().Msgf("received message from | %s", log)
	// 	s.ws.PrepareAndSend(log)
	// }
}
