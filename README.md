# Blockchain

Simple blockchain implementation for demo purposes.

## Usage

```shell
make build
make test
mame test_one name=test_rpc_packet_encode_decode
make run
```

## Troubleshooting

To test UDP server use following command: `echo "test" | nc -u -w 1 127.0.0.1 44600`.
