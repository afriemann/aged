.PHONY: build install clean

BINARY  = aged
DESTDIR ?=
PREFIX  ?= /usr/local

build:
	go build -o $(BINARY) ./cmd/$(BINARY)

install: build
	install -Dm755 $(BINARY) $(DESTDIR)$(PREFIX)/bin/$(BINARY)

clean:
	rm -f $(BINARY)
