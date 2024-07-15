# Blockchain

Simple blockchain implementation for demo purposes.

## Usage

```shell
make format
make build
make test
mame test_one name=test_rpc_packet_encode_decode
make run
```

```shell
# First node.
PORT=33400 GENESIS=00000000000000000000000000000000c4a55b5a7d0d89586e37238ca05362389e0dd85157d8652bd24fc483f66c22c0000000000000000000000000000000000000000000000000000000000000000003068fab900100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 \
  make run
# Second node.
MINING=1 NODES=127.0.0.1:33400 GENESIS=00000000000000000000000000000000c4a55b5a7d0d89586e37238ca05362389e0dd85157d8652bd24fc483f66c22c0000000000000000000000000000000000000000000000000000000000000000003068fab900100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 \
  make run
```

### Docker

```shell
make build_docker
# -it to use ctrl+c
docker run --rm -it blockchain
```

```shell
make build_docker && docker run --rm -it -e PORT=33400 -e GENESIS=00000000000000000000000000000000c4a55b5a7d0d89586e37238ca05362389e0dd85157d8652bd24fc483f66c22c0000000000000000000000000000000000000000000000000000000000000000003068fab900100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 \
  --name light-node --net host blockchain

make build_docker && docker run --rm -it -e MINING=1 -e NODES=127.0.0.1:33400 -e GENESIS=00000000000000000000000000000000c4a55b5a7d0d89586e37238ca05362389e0dd85157d8652bd24fc483f66c22c0000000000000000000000000000000000000000000000000000000000000000003068fab900100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 \
  --name full-node --net host blockchain
```

## Troubleshooting

To test UDP server use following command: `echo "test" | nc -u -w 1 127.0.0.1 44600`.
