.PHONY: lint format check install-dev setup-pre-commit test test-cov

# Install development dependencies
install-dev:
	poetry install --with dev

# Setup pre-commit hooks
setup-pre-commit: install-dev
	poetry run pre-commit install

# Run linting
lint:
	poetry run ruff check traefiktounifi/
	poetry run black --check traefiktounifi/

# Format code
format:
	poetry run ruff check --fix traefiktounifi/
	poetry run black traefiktounifi/

# Run all checks (lint + format check)
check: lint

# Run pre-commit on all files
pre-commit:
	poetry run pre-commit run --all-files

# Run tests
test:
	poetry run pytest

# Run tests with coverage report
test-cov:
	poetry run pytest --cov=traefiktounifi --cov-report=term-missing --cov-report=html

# Run CI checks locally (same as GitHub Actions)
ci: lint test
	@echo "✅ All CI checks passed locally!"

# Complete setup for development
dev-setup: install-dev setup-pre-commit
	@echo "Development environment setup complete!"
	@echo "Run 'make lint' to check code style"
	@echo "Run 'make format' to format code"
	@echo "Run 'make test' to run tests"
	@echo "Run 'make ci' to run the same checks as CI"
