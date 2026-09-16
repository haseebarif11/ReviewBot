.PHONY: help install run test lint clean docker-build docker-up docker-down

help: ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

install: ## Install Python dependencies
	pip install -r requirements.txt

run: ## Start the FastAPI development server with hot-reload
	uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

test: ## Run the full test suite with pytest
	pytest -v

lint: ## Run syntax and code quality checks
	python -m py_compile app/**/*.py tests/**/*.py

clean: ## Remove temporary files, caches, and build artifacts
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

docker-build: ## Build Docker container image
	docker-compose build

docker-up: ## Start services with Docker Compose in the background
	docker-compose up -d

docker-down: ## Stop Docker Compose services
	docker-compose down
