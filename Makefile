.PHONY: deploy format check-undefined increment-version release trigger-workflow get-version

# Default Python interpreter
PYTHON := uv run python
GIT_FILES := $(shell git ls-files "./morphcloud")

# Helper function to extract the version, defined once and reusable
get_current_version = $(shell grep -oP 'version = "\K[^"]+' pyproject.toml)

deploy: format check-undefined increment-version release trigger-workflow

# Format code with black and isort
format:
	@echo "Formatting code with black and isort..."
	uv run black ./morphcloud
	uv run isort ./morphcloud

# Check for undefined variables in all git-tracked files
check-undefined:
	@echo "Checking for undefined variables..."
	@for file in $(GIT_FILES); do \
		echo "Checking $$file"; \
		UNDEFINED=$$(ruff check "$$file" | grep ndefined || true); \
		if [ ! -z "$$UNDEFINED" ]; then \
			echo "Undefined variables found in $$file:"; \
			echo "$$UNDEFINED"; \
			exit 1; \
		fi; \
	done
	@echo "No undefined variables found!"

# Increment version if current is less than the latest on PyPI
increment-version:
	@echo "Checking current version against PyPI..."
	@chmod +x ./scripts/increment_version.py
	@./scripts/increment_version.py

# Display the current version
get-version:
	@echo "Current version is: $(call get_current_version)"

# Push to GitHub, create tag and GitHub release
release:
	@echo "Pushing to GitHub and creating release..."
	$(eval VERSION := $(get_current_version))
	@echo "Version to release: $(VERSION)"
	git diff --quiet pyproject.toml || git add pyproject.toml
	git diff --quiet --cached || git commit -m "Bump version to $(VERSION)"
	git push origin main || true

        # Create git tag if it doesn't exist
	git tag -l "v$(VERSION)" | grep -q . || git tag -a "v$(VERSION)" -m "Release v$(VERSION)" 
	git push origin "v$(VERSION)" || true

        # Create GitHub release if it doesn't exist
	@if command -v gh &> /dev/null; then \
		if ! gh release view "v$(VERSION)" &>/dev/null; then \
			echo "Creating GitHub release v$(VERSION)..."; \
			gh release create "v$(VERSION)" \
				--title "v$(VERSION)" \
				--notes "Release v$(VERSION) of morphcloud." \
				--target main; \
		else \
			echo "GitHub release v$(VERSION) already exists, skipping creation."; \
		fi; \
	else \
		echo "GitHub CLI not found. Please create the release manually at:"; \
		echo "https://github.com/$(shell git config --get remote.origin.url | sed -e 's/.*github.com[:\/]\(.*\)\.git/\1/')/releases/new"; \
	fi

	@echo "Release created!"

# Trigger the GitHub workflow manually on the tagged release
trigger-workflow:
	$(eval VERSION := $(get_current_version))
	@echo "Triggering GitHub publish workflow for tag v$(VERSION)..."
	@if command -v gh &> /dev/null; then \
		echo "Running workflow publish.yaml on tag v$(VERSION)"; \
		gh workflow run publish.yaml --ref "v$(VERSION)" || \
		echo "Please trigger the workflow manually on the tag v$(VERSION)"; \
	else \
		echo "GitHub CLI not found. Please trigger the workflow manually at:"; \
		echo "https://github.com/$(shell git config --get remote.origin.url | sed -e 's/.*github.com[:\/]\(.*\)\.git/\1/')/actions/workflows/publish.yaml"; \
		echo "Be sure to select the 'v$(VERSION)' tag when triggering the workflow!"; \
	fi
	@echo "Deployment complete!"
