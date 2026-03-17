.PHONY: build release install clean test run

# Build debug
build:
	cargo build

# Build optimized release
release:
	cargo build --release

# Install to /usr/local/bin (requires sudo)
install: release
	sudo cp target/release/do-sentinel /usr/local/bin/do-sentinel
	sudo chmod +x /usr/local/bin/do-sentinel

# Install systemd service (requires sudo)
install-service: install
	@if [ ! -f /etc/systemd/system/do-sentinel.service ]; then \
		sudo cp contrib/do-sentinel.service /etc/systemd/system/; \
		sudo systemctl daemon-reload; \
		sudo systemctl enable do-sentinel; \
		echo "Service installed. Start with: sudo systemctl start do-sentinel"; \
	else \
		echo "Service file already exists. Stop, copy, reload, start manually."; \
	fi

# Run locally (no persistence, debug mode)
run:
	cargo run -- --no-store --debug

# Clean build artifacts
clean:
	cargo clean

# Deploy to a remote host (set DEPLOY_HOST)
# Usage: make deploy DEPLOY_HOST=root@your-server
deploy: release
	@if [ -z "$(DEPLOY_HOST)" ]; then echo "Usage: make deploy DEPLOY_HOST=root@your-server"; exit 1; fi
	ssh $(DEPLOY_HOST) "systemctl stop do-sentinel 2>/dev/null; true"
	scp target/release/do-sentinel $(DEPLOY_HOST):/usr/local/bin/do-sentinel
	ssh $(DEPLOY_HOST) "systemctl start do-sentinel 2>/dev/null; true"
	@echo "Deployed to $(DEPLOY_HOST)"

# Show binary size
size: release
	@ls -lh target/release/do-sentinel | awk '{print $$5, $$9}'
	@echo "Stripped:"
	@cp target/release/do-sentinel /tmp/do-sentinel-stripped
	@strip /tmp/do-sentinel-stripped
	@ls -lh /tmp/do-sentinel-stripped | awk '{print $$5}'
	@rm /tmp/do-sentinel-stripped
