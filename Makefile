.PHONY: all clean build-all checksums

# Define platforms and output settings
OUTPUT_DIR=bin

all: build-all checksums

build-all:
	mkdir -p $(OUTPUT_DIR)
	# Linux AMD64
	GOOS=linux GOARCH=amd64 go build -o $(OUTPUT_DIR)/darkflare-client-linux-amd64 client/main.go
	GOOS=linux GOARCH=amd64 go build -o $(OUTPUT_DIR)/darkflare-server-linux-amd64 server/main.go
	
	# Linux ARM64 (aarch64)
	GOOS=linux GOARCH=arm64 go build -o $(OUTPUT_DIR)/darkflare-client-linux-arm64 client/main.go
	GOOS=linux GOARCH=arm64 go build -o $(OUTPUT_DIR)/darkflare-server-linux-arm64 server/main.go
	
	# macOS AMD64 (Intel)
	GOOS=darwin GOARCH=amd64 go build -o $(OUTPUT_DIR)/darkflare-client-darwin-amd64 client/main.go
	GOOS=darwin GOARCH=amd64 go build -o $(OUTPUT_DIR)/darkflare-server-darwin-amd64 server/main.go
	
	# macOS ARM64 (Apple Silicon)
	GOOS=darwin GOARCH=arm64 go build -o $(OUTPUT_DIR)/darkflare-client-darwin-arm64 client/main.go
	GOOS=darwin GOARCH=arm64 go build -o $(OUTPUT_DIR)/darkflare-server-darwin-arm64 server/main.go
	
	# Windows AMD64
	GOOS=windows GOARCH=amd64 go build -o $(OUTPUT_DIR)/darkflare-client-windows-amd64.exe client/main.go
	GOOS=windows GOARCH=amd64 go build -o $(OUTPUT_DIR)/darkflare-server-windows-amd64.exe server/main.go

checksums:
	cd $(OUTPUT_DIR) && \
	echo "# DarkFlare Binary Checksums" > checksums.txt && \
	echo "# Generated: $$(date -u)" >> checksums.txt && \
	echo "" >> checksums.txt && \
	( \
		if command -v sha256sum >/dev/null 2>&1; then \
			echo "Using sha256sum" && \
			sha256sum * >> checksums.txt; \
		else \
			echo "Using shasum" && \
			shasum -a 256 * >> checksums.txt; \
		fi \
	)

clean:
	rm -rf $(OUTPUT_DIR)
