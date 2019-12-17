# Blockchain
A blockchain - is a continuously growing list of records, called blocks,
which are linked and secured using cryptography.
Each block typically contains a cryptographic hash of the previous block,
a timestamp and transaction data. By design,
a blockchain is inherently resistant to modification of the data.
Once recorded, the data in any given block
cannot be altered retroactively without the alteration of all subsequent blocks.

## How it work
### Root node
It initializes blockchain and mining block.
First block is genesis block.

###### Genesis block
```
{
    "index": 0,
    "hash": "3368823cb6d6fab32c4535265579f83ed79830664dc346ea4f9acddc21ebf02a",
    "prev_hash": "",
    "timestamp": "2017-06-09T23:19:33.2947309+03:00",
    "complexity": 0,
    "nonce": ""
}
```

### Other nodes
First, node requests the initialization node for following information:
1. Current blockchain
2. Current mining block
3. List of current nodes

Then node connects to each node by WebSockets.

### HTTP and WebSocket
Nodes raises the HTTP and WebSocket server to work with other nodes
(`WebSocket`) and (`HTTP`) to view information about blockchain and mining:
1. Blockchain
2. Current mining block
3. Block facts
4. Nodes
5. Block mining

### Block
#### Block contains following data
- Index `- block index`
- Hash `- calculated from block data (sha256)`
- Previous block hash `- latest block hash`
- Timestamp `- created time`
- Facts `- confirmed facts`
- Complexity `- solution complexity`
- Nonce `- number to solve block`

Each block contains hash of previous block to preserve chain integrity.

#### Block has been validated if
1. its `index` is <b>equal</b> to latest block `index + 1`
2. latest block `hash` is <b>equal</b> to `previous hash` of current block
3. `calculation of hash` of block data is <b>equal</b> to its `hash`

#### Creation of the next block is
1. Index `= latest block index + 1`
2. Previous hash `= latest block hash`
3. Timestamp `= current time`
4. Facts `= take unconfirmed facts`
5. Complexity `= increase if more than 10 seconds have passed since creation of previous block, otherwise decrease`
6. Nonce `= ""`
7. Hash `= calculated from block data`

#### Decision of block
To <b>solve</b> block, it is necessary to <b>find</b> such a
<b>number</b> `nonce` that this <b>number + hash</b> of block contained number of
<b>leading zeros</b> <b>greater</b> than or <b>equal</b> to <b>complexity</b> of block.

### Work process
When node is initialized, it will be connected to others via a WebSockets,
and node is ready to receive a new block or fact.

#### Facts
When a node accepts a new fact:
1. node adds the fact to unconfirmed facts
2. node sends it to other nodes

When fact came from another node:
1. add it to unconfirmed facts

#### Mining
Node that solved block
1. node creates a new block for solution on the basis of newly solved
2. than sends solved block to other nodes for verification
3. send new mining block to other nodes

Node that took resolved block
1. if it passes check, it is added to chain, if not, following instructions are not met
2. look through list of block confirmed facts, if a fact is found
that equal with fact from unconfirmed, it is removed therefrom
3. update mining block
