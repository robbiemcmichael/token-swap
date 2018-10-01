BINARY := token-swap

$(BINARY): main.go
	go build -o $(BINARY) main.go

.PHONY: clean
clean:
	-rm $(BINARY)
