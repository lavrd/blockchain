build:
	zig build-exe -femit-bin=target/blockchain src/main.zig

run: build
	target/blockchain
