# Makefile for sharesecret Go application

# Default variables
BINARY_NAME = sharesecret
GO_CMD = go
BUILD_FLAGS = -ldflags="-s -w"

# Detect current architecture
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
    DEFAULT_ARCH = amd64
else ifeq ($(UNAME_M),aarch64)
    DEFAULT_ARCH = arm64
else ifeq ($(UNAME_M),arm64)
    DEFAULT_ARCH = arm64
else
    DEFAULT_ARCH = amd64
endif

# Default target - build for current architecture
.PHONY: build
build:
	GOOS=linux GOARCH=$(DEFAULT_ARCH) $(GO_CMD) build $(BUILD_FLAGS) -o $(BINARY_NAME) .

# Cross-compilation targets
.PHONY: build-linux-amd64
build-linux-amd64:
	GOOS=linux GOARCH=amd64 $(GO_CMD) build $(BUILD_FLAGS) -o $(BINARY_NAME)-linux-amd64 .

.PHONY: build-linux-arm64
build-linux-arm64:
	GOOS=linux GOARCH=arm64 $(GO_CMD) build $(BUILD_FLAGS) -o $(BINARY_NAME)-linux-arm64 .

# Build all architectures
.PHONY: build-all
build-all: build-linux-amd64 build-linux-arm64

# Clean build artifacts
.PHONY: clean
clean:
	rm -f $(BINARY_NAME) $(BINARY_NAME)-*

# Run the application
.PHONY: run
run: build
	./$(BINARY_NAME)

# Help target
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build              - Build for current architecture ($(DEFAULT_ARCH))"
	@echo "  build-linux-amd64  - Build for Linux x86_64"
	@echo "  build-linux-arm64  - Build for Linux ARM64"
	@echo "  build-all          - Build for all architectures"
	@echo "  clean              - Clean build artifacts"
	@echo "  run                - Build and run the application"
	@echo "  help               - Show this help message"

# Default target
.DEFAULT_GOAL := build
