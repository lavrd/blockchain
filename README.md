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
MINING=1 PORT=44400 NODES=127.0.0.1:46400 make run
```

## Troubleshooting

To test UDP server use following command: `echo "test" | nc -u -w 1 127.0.0.1 44600`.
