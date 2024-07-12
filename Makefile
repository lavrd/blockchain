build:
	zig build --summary all

test:
	zig test src/main.zig

test_one:
	zig test src/main.zig --test-filter $(name)

run: build
	zig-out/bin/blockchain
