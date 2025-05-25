.PHONY: build test reports clean init-hosts copy-hosts validate-hosts help

help:
	@echo "Available targets:"
	@echo "  init-hosts    - Create template hosts file"
	@echo "  copy-hosts    - Copy system hosts file to project (for reference)"
	@echo "  validate-hosts- Validate hosts file format"
	@echo "  build         - Build the Docker image"
	@echo "  test          - Run security tests (set URLS environment variable)"
	@echo "  reports       - Start web server for reports"
	@echo "  clean         - Clean up containers and images"
	@echo ""
	@echo "CI/CD workflow:"
	@echo "  1. Edit ./hosts file with your internal mappings"
	@echo "  2. make validate-hosts"
	@echo "  3. make build"
	@echo "  4. URLS='https://myapp https://api' make test"

init-hosts:
	@if [ -f ./hosts ]; then \
		echo "hosts file already exists. Use 'copy-hosts' to overwrite with system hosts."; \
	else \
		echo "Creating template hosts file..."; \
		printf "%s\n" "\
# Project hosts file for security testing\n\
# This file will be copied into the Docker container\n\
# Format: IP_ADDRESS HOSTNAME [ALIAS...]\n\
\n\
# Standard localhost entries\n\
127.0.0.1   localhost\n\
::1         localhost ip6-localhost ip6-loopback\n\
fe00::0     ip6-localnet\n\
ff00::0     ip6-mcastprefix\n\
ff02::1     ip6-allnodes\n\
ff02::2     ip6-allrouters\n\
\n\
# Add your internal application mappings here:\n\
# 192.168.1.100   myapp.local myapp\n\
# 192.168.1.101   api.local api\n\
# 192.168.1.102   admin.local admin\n\
# 10.0.1.50       staging-app.local staging\n" > ./hosts; \
		echo "Template hosts file created. Edit ./hosts to add your mappings."; \
	fi

copy-hosts:
	@if [ -f /etc/hosts ]; then \
		cp /etc/hosts ./hosts; \
		echo "System hosts file copied to ./hosts"; \
		echo "You can now edit ./hosts for your project needs."; \
	else \
		echo "Error: /etc/hosts not found"; \
		exit 1; \
	fi

validate-hosts:
	@if [ ! -f ./hosts ]; then \
		echo "Error: ./hosts file not found. Run 'make init-hosts' first."; \
		exit 1; \
	fi
	@echo "Validating hosts file format..."
	@awk '/^[^#]/ { \
		if (NF < 2) { \
			print "Error: Line " NR " has invalid format: " $0; \
			exit 1; \
		} \
		if ($1 !~ /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/ && $1 !~ /^[0-9a-fA-F:]+$/) { \
			print "Error: Line " NR " has invalid IP format: " $1; \
			exit 1; \
		} \
	}' ./hosts
	@echo "hosts file validation passed!"
	@echo "Found entries:"
	@grep -v "^#" ./hosts | grep -v "^$" | awk '{print "  " $1 " -> " $2}' || true

build:
	@if [ ! -f ./hosts ]; then \
		echo "Error: ./hosts file not found. Run 'make init-hosts' or 'make copy-hosts' first."; \
		exit 1; \
	fi
	docker-compose build security-tester

test:
	@if [ -z "$(URLS)" ]; then \
		echo "Error: Please set URLS environment variable"; \
		echo "Example: URLS='https://myapp https://api' make test"; \
		exit 1; \
	fi
	docker-compose run --rm security-tester $(URLS)

reports:
	docker-compose up -d report-server
	@echo "Reports available at: http://localhost:8080"

clean:
	docker-compose down
	docker-compose rm -f

# Helper target to show current hosts configuration
show-hosts:
	@if [ -f ./hosts ]; then \
		echo "Current hosts configuration:"; \
		echo "============================"; \
		cat ./hosts; \
	else \
		echo "No hosts file found. Run 'make init-hosts' to create one."; \
	fi

