# List all the Go CLI tools to be rebuilt
TOOLS = bootstrap cubbyhole service token

.PHONY: all $(TOOLS) clean


# Default target: rebuild all the Go CLI tools
all: myvault $(TOOLS)


myvault:
		go build -o bin/$@ cmd/cli/myvault.go

# Build the Go CLI tools
$(TOOLS):
		env GOOS=darwin GOARCH=arm64 go build -o bin/darwin/$@ cmd/$@/$@.go
		#env GOOS=linux GOARCH=amd64 go build -o bin/linux/$@ cmd/$@/$@.go
		#env GOOS=windows GOARCH=amd64 go build -o bin/windows/$@ cmd/$@/$@.go
# Clean up the Go CLI tools
clean:
		rm -rf bin/*

