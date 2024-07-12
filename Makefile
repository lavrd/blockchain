build:
	zig build-exe -femit-bin=target/blockchain src/main.zig

test:
	zig test src/main.zig

test_one:
	zig test src/main.zig --test-filter $(name)

run: build
	target/blockchain
