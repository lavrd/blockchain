format:
	zig fmt src/main.zig

build: format
	zig build --summary all

test: format
	zig test src/main.zig

test_one: format
	zig test src/main.zig --test-filter $(name)

run: build
	zig-out/bin/blockchain
