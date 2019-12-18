#!/usr/bin/env bash

BIN_NAME=./blkchn

go build -o $BIN_NAME main.go

NODE_1_HTTP_PORT=7001
NODE_2_HTTP_PORT=7002
NODE_3_HTTP_PORT=7003

NODE_1_WS_PORT=8881
NODE_2_WS_PORT=8882
NODE_3_WS_PORT=8883

if [ $1 == 1 ]; then
  $BIN_NAME -h $NODE_1_HTTP_PORT -ws $NODE_1_WS_PORT -v || exit
fi

if [ $1 == 2 ]; then
  $BIN_NAME -h $NODE_2_HTTP_PORT -i 127.0.0.1:$NODE_1_HTTP_PORT -ws $NODE_2_WS_PORT -v || exit
fi

if [ $1 == 3 ]; then
  $BIN_NAME -h $NODE_3_HTTP_PORT -i 127.0.0.1:$NODE_2_HTTP_PORT -ws $NODE_3_WS_PORT -v || exit
fi

echo "no such node number"
