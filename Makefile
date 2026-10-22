PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
CARGO ?= cargo

.PHONY: all build release test check install uninstall install-user

all: release

build:
	$(CARGO) build

release:
	$(CARGO) build --release -p bootlegger-cli

test:
	$(CARGO) test --workspace

check:
	$(CARGO) check --workspace

install: release
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 target/release/bootlegger $(DESTDIR)$(BINDIR)/bootlegger
	@echo "✓ Bootlegger installed to $(DESTDIR)$(BINDIR)/bootlegger"

install-user: release
	install -d $(HOME)/.local/bin
	install -m 755 target/release/bootlegger $(HOME)/.local/bin/bootlegger
	@echo "✓ Bootlegger installed to $(HOME)/.local/bin/bootlegger"
	@if ! echo "$$PATH" | grep -q "$(HOME)/.local/bin"; then \
		echo "⚠️  Note: Make sure $(HOME)/.local/bin is in your PATH (e.g. in ~/.bashrc or ~/.zshrc)"; \
	fi

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/bootlegger
	@echo "✓ Bootlegger uninstalled from $(DESTDIR)$(BINDIR)"

uninstall-user:
	rm -f $(HOME)/.local/bin/bootlegger
	@echo "✓ Bootlegger uninstalled from $(HOME)/.local/bin"
