.PHONY: setup test lint clean demo

setup:
	docker compose build
	cd sdks/python && pip install -e .
	cd sdks/nodejs && npm install
	cd dashboard && npm install

test:
	cd core/verifier && cargo test
	cd sdks/python && pytest
	cd dashboard && npm run lint

lint:
	cd core/proxy && cargo fmt --check
	cd core/verifier && cargo fmt --check
	cd dashboard && npm run lint

demo:
	docker compose up -d verifier proxy web prometheus grafana
	@echo "See docs/demo/getting-started.md"

clean:
	docker compose down
	rm -f sdks/python/aegis-trace-wal.jsonl core/verifier/policies.db
