format:
	zig fmt src/main.zig

build: format
	zig build --summary all

build_linux: format
	mkdir -p zig-out/linux/bin
	zig build-exe src/main.zig -target aarch64-linux --library c -femit-bin=zig-out/linux/bin/blockchain

build_docker: build_linux
	docker build -t blockchain -f Dockerfile .

test: format
	zig test src/main.zig

test_one: format
	zig test src/main.zig --test-filter $(name)

run: build
	zig-out/bin/blockchain
