GO := go
BIN := ../../bin/

main: rulegen.go
	$(GO) build -o $(BIN)/ github.com/rssys/syscall-sanitizer/src/rulegen

.PHONY: clean

clean:
	rm -f $(BIN)/rulegen