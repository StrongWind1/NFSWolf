.PHONY: fmt fmt-fix lint lint-fix doc dev build check \
        test test-matrix \
        audit machete \
        ascii-check lf-check hygiene \
        build-linux-musl build-linux-x86-full \
        build-linux-arm-musl build-linux-arm-full \
        build-macos-arm build-macos-x86 build-macos-universal \
        build-windows \
        dist size \
        fix hooks clean check-all all

# Default target -- running bare `make` builds dist artifacts for the current platform.
.PHONY: all
all: dist

CARGO := cargo
DIST  := dist
BIN   := nfswolf

# -- OS / architecture detection -----------------------------------------------
# uname -s: Linux | Darwin | MINGW*/MSYS* (Windows Git Bash)
# uname -m: x86_64 | aarch64 (Linux ARM64) | arm64 (macOS M-series)
UNAME_S := $(shell uname -s 2>/dev/null)
UNAME_M := $(shell uname -m 2>/dev/null)

ifeq ($(findstring Linux,$(UNAME_S)),Linux)
  PLATFORM := linux
else ifeq ($(findstring Darwin,$(UNAME_S)),Darwin)
  PLATFORM := macos
else
  PLATFORM := windows
endif

# Normalise: macOS reports arm64, Linux ARM reports aarch64  --  unify to arm64.
ifneq (,$(filter arm64 aarch64,$(UNAME_M)))
  ARCH := arm64
else
  ARCH := x86_64
endif

# -- Rust target triples --------------------------------------------------------
TARGET_LINUX_X86_MUSL := x86_64-unknown-linux-musl
TARGET_LINUX_X86_GNU  := x86_64-unknown-linux-gnu
TARGET_LINUX_ARM_MUSL := aarch64-unknown-linux-musl
TARGET_LINUX_ARM_GNU  := aarch64-unknown-linux-gnu
TARGET_MACOS_ARM      := aarch64-apple-darwin
TARGET_MACOS_X86      := x86_64-apple-darwin
TARGET_WIN_X86_MSVC   := x86_64-pc-windows-msvc
TARGET_WIN_X86_GNU    := x86_64-pc-windows-gnu
TARGET_WIN_ARM_MSVC   := aarch64-pc-windows-msvc

# -- Formatting ---------------------------------------------------------------

# Fail if any file would change.
fmt:
	$(CARGO) fmt --all -- --check

# Apply in-place.
fmt-fix:
	$(CARGO) fmt --all

# -- Linting ------------------------------------------------------------------

# Lint levels are defined in Cargo.toml [lints.clippy] and clippy.toml.
lint:
	$(CARGO) clippy --all-targets --all-features

lint-fix:
	$(CARGO) clippy --fix --allow-dirty --all-targets --all-features

# -- Documentation ------------------------------------------------------------

# Build docs for the public API; treat rustdoc warnings as errors.
doc:
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --all-features --no-deps

# -- Build ---------------------------------------------------------------------

# Debug build on the native target  --  fastest compile-check.
dev:
	$(CARGO) build --all-features

# Optimized build for the native target. Use before dist to verify locally.
build:
	$(CARGO) build --profile release --all-features

# Alias so `make release` builds the native release binary.
.PHONY: release
release: build

# Fast type-check, no codegen.
check:
	$(CARGO) check --all-targets --all-features

# -- Tests ---------------------------------------------------------------------

# Full test suite (all features). Use for quick local runs.
.PHONY: test
test:
	$(CARGO) test --all-targets --all-features

# Feature matrix: all-features / no-features (no fuse) / fuse only.
test-matrix:
	@echo "==> test-matrix: --all-features"
	$(CARGO) test --all-targets --all-features
	@echo "==> test-matrix: --no-default-features"
	$(CARGO) test --all-targets --no-default-features
	@echo "==> test-matrix: --features fuse"
	$(CARGO) test --all-targets --features fuse

# -- Dependency auditing --------------------------------------------------------

audit:
	$(CARGO) deny check

machete:
	$(CARGO) machete

# -- File hygiene --------------------------------------------------------------

# Repository paths excluded from all hygiene checks.
#   vendor/**  - third-party code, not our policy to enforce
#   ref/**     - reference material / external docs
HYGIENE_EXCLUDES := ':!vendor/**' ':!ref/**' ':!docs/**' ':!Makefile'

# Files held to strict ASCII: TAB, LF, printable ASCII only. Nothing else.
HYGIENE_STRICT_GLOBS := \
    '*.toml' '*.yml' '*.yaml' '*.json' '*.sh' '*.lock' \
     'LICENSE' '.editorconfig' '.gitignore' '.gitattributes'

# Files allowed the project allowlist (§) on top of strict ASCII.
#   .rs  - § in RFC-section comments
#   .md  - § for protocol references
HYGIENE_ALLOWLIST_GLOBS := '*.rs' '*.md'

HYGIENE_ALL_GLOBS := $(HYGIENE_STRICT_GLOBS) $(HYGIENE_ALLOWLIST_GLOBS)

# PCRE codepoint classes (codepoint-aware under LC_ALL=C.UTF-8).
#    \x{0A} LF, \x{20}-\x{7E} printable ASCII (excludes DEL).
# CR (\x{0D}) intentionally not allowed; the project is LF-only and lf-check
# enforces that separately.
HYGIENE_STRICT_CLASS    := [^\x{0A}\x{20}-\x{7E}]

# Allowlist adds:
#   §  U+00A7 SECTION SIGN
HYGIENE_ALLOWLIST_CLASS := [^\x{0A}\x{20}-\x{7E}\x{A7}]

ascii-check:
	@echo "Checking for non-ASCII code points in tracked source files..."
	@fail=0; \
	for f in $$(git ls-files -- $(HYGIENE_STRICT_GLOBS) $(HYGIENE_EXCLUDES)); do \
		if LC_ALL=C.UTF-8 grep -aPn '$(HYGIENE_STRICT_CLASS)' "$$f" > /dev/null 2>&1; then \
			echo "  NON-ASCII: $$f"; \
			LC_ALL=C.UTF-8 grep -aPn '$(HYGIENE_STRICT_CLASS)' "$$f"; \
			fail=1; \
		fi; \
	done; \
	for f in $$(git ls-files -- $(HYGIENE_ALLOWLIST_GLOBS) $(HYGIENE_EXCLUDES)); do \
		if LC_ALL=C.UTF-8 grep -aPn '$(HYGIENE_ALLOWLIST_CLASS)' "$$f" > /dev/null 2>&1; then \
			echo "  NON-ASCII (outside allowlist): $$f"; \
			LC_ALL=C.UTF-8 grep -aPn '$(HYGIENE_ALLOWLIST_CLASS)' "$$f"; \
			fail=1; \
		fi; \
	done; \
	if [ "$$fail" -eq 1 ]; then echo "FAIL: non-ASCII bytes found"; exit 1; fi
	@echo "OK: tracked files conform to ASCII / allowlisted-UTF-8 policy."

lf-check:
	@echo "Checking for CRLF line endings in tracked files..."
	@fail=0; \
	for f in $$(git ls-files -- $(HYGIENE_ALL_GLOBS) $(HYGIENE_EXCLUDES)); do \
		if grep -Pq '\r$$' "$$f" 2>/dev/null; then \
			echo "  CRLF: $$f"; \
			fail=1; \
		fi; \
	done; \
	if [ "$$fail" -eq 1 ]; then echo "FAIL: CRLF line endings found"; exit 1; fi
	@echo "OK: all source files use LF."

.PHONY: hygiene
hygiene: ascii-check lf-check

# -- Platform-specific build targets -------------------------------------------
#
# Targets install their required rustup target if missing (idempotent, no-op
# if already present). The caller is responsible for system-level deps:
#
#   Linux musl:     apt install musl-tools
#   Linux glibc+FUSE: apt install libfuse3-dev pkg-config
#   macOS:          no extra deps (lipo is part of Xcode Command Line Tools)
#   Windows:        CI-only  --  native runners have MSVC + MinGW available

# -- Linux x86_64 --------------------------------------------------------------

# Static binary  --  no glibc dep, no FUSE (libfuse3 cannot be statically linked via musl).
build-linux-musl:
	@if ! command -v musl-gcc > /dev/null 2>&1; then \
		echo "WARNING: musl-gcc not found  --  skipping $(TARGET_LINUX_X86_MUSL)."; \
		echo "  Install: apt install musl-tools && rustup target add $(TARGET_LINUX_X86_MUSL)"; \
	else \
		rustup target add $(TARGET_LINUX_X86_MUSL) 2>/dev/null || true; \
		$(CARGO) build --profile release --no-default-features --target $(TARGET_LINUX_X86_MUSL); \
	fi

# glibc dynamic  --  full feature set including FUSE mount.
build-linux-x86-full:
	@if ! pkg-config --exists fuse3 2>/dev/null; then \
		echo "WARNING: fuse3 not found  --  skipping linux-x86_64-full."; \
		echo "  Install: apt install libfuse3-dev pkg-config"; \
	else \
		rustup target add $(TARGET_LINUX_X86_GNU) 2>/dev/null || true; \
		$(CARGO) build --profile release --all-features --target $(TARGET_LINUX_X86_GNU); \
	fi

# -- Linux arm64 ---------------------------------------------------------------
#
# Run these on an ARM64 Linux machine (or the ubuntu-24.04-arm CI runner).
# The musl-gcc from musl-tools on ARM64 Ubuntu targets aarch64, not x86_64.

# Static binary  --  no FUSE.
build-linux-arm-musl:
	@if ! command -v musl-gcc > /dev/null 2>&1; then \
		echo "WARNING: musl-gcc not found  --  skipping $(TARGET_LINUX_ARM_MUSL)."; \
		echo "  Install: apt install musl-tools && rustup target add $(TARGET_LINUX_ARM_MUSL)"; \
	else \
		rustup target add $(TARGET_LINUX_ARM_MUSL) 2>/dev/null || true; \
		$(CARGO) build --profile release --no-default-features --target $(TARGET_LINUX_ARM_MUSL); \
	fi

# glibc dynamic  --  full feature set including FUSE mount (aarch64-linux-gnu is native on ARM64).
build-linux-arm-full:
	@if ! pkg-config --exists fuse3 2>/dev/null; then \
		echo "WARNING: fuse3 not found  --  skipping linux-arm64-full."; \
		echo "  Install: apt install libfuse3-dev pkg-config"; \
	else \
		rustup target add $(TARGET_LINUX_ARM_GNU) 2>/dev/null || true; \
		$(CARGO) build --profile release --all-features --target $(TARGET_LINUX_ARM_GNU); \
	fi

# -- macOS ---------------------------------------------------------------------
#
# Cross-compilation between arm64 and x86_64 is trivial within macOS  --  both
# targets can be built from either Apple Silicon or Intel without extra tools.
# No FUSE: macFUSE is not installed by default; users install it separately.

# Apple Silicon (M-series) binary.
build-macos-arm:
	rustup target add $(TARGET_MACOS_ARM) 2>/dev/null || true
	$(CARGO) build --profile release --no-default-features --target $(TARGET_MACOS_ARM)

# Intel binary (cross-compiles from Apple Silicon or builds natively on Intel).
build-macos-x86:
	rustup target add $(TARGET_MACOS_X86) 2>/dev/null || true
	$(CARGO) build --profile release --no-default-features --target $(TARGET_MACOS_X86)

# Universal binary: merge arm64 + x86_64 slices with lipo.
# Prerequisite: both build-macos-arm and build-macos-x86 must have run first.
build-macos-universal:
	@if ! command -v lipo > /dev/null 2>&1; then \
		echo "WARNING: lipo not found  --  skipping universal binary (macOS only)."; \
	elif [ ! -f target/$(TARGET_MACOS_ARM)/release/$(BIN) ] \
	  || [ ! -f target/$(TARGET_MACOS_X86)/release/$(BIN) ]; then \
		echo "WARNING: one or both macOS binaries missing  --  run build-macos-arm and build-macos-x86 first."; \
	else \
		mkdir -p $(DIST); \
		lipo -create \
			-output $(DIST)/$(BIN)-macos-universal \
			target/$(TARGET_MACOS_ARM)/release/$(BIN) \
			target/$(TARGET_MACOS_X86)/release/$(BIN); \
		lipo -info $(DIST)/$(BIN)-macos-universal; \
	fi

# -- Windows -------------------------------------------------------------------
#
# All Windows variants are built on native GitHub Actions runners.
# MSVC builds run on windows-latest / windows-11-arm.
# GNU (MinGW) build runs on ubuntu-latest  --  simpler than cross from Windows.
build-windows:
	@echo "Windows builds require native CI runners:"
	@echo "  windows-x86_64-msvc.exe   --  windows-latest    (MSVC)"
	@echo "  windows-x86_64-gnu.exe    --  ubuntu-latest     (MinGW, apt install gcc-mingw-w64-x86-64)"
	@echo "  windows-arm64-msvc.exe    --  windows-11-arm    (MSVC)"
	@echo "Trigger: git tag vX.Y.Z && git push --tags"

# -- Distribution --------------------------------------------------------------
#
# 'make dist' (and 'make all') detects the current OS and architecture, builds
# the appropriate release artifacts, and collects them into dist/.
#
#   Linux  x86_64 -> linux-x86_64 (musl)  +  linux-x86_64-full (glibc+FUSE)
#   Linux  arm64  -> linux-arm64  (musl)  +  linux-arm64-full  (glibc+FUSE)
#   macOS  any    -> macos-arm64  +  macos-x86_64  +  macos-universal (lipo)
#   Windows       -> CI-only (run git tag to trigger release workflow)
#
# Full multi-platform release: git tag vX.Y.Z && git push --tags
#   -> triggers .github/workflows/release.yml on native runners for all targets

ifeq ($(PLATFORM)-$(ARCH),linux-x86_64)
  DIST_DEPS := build-linux-musl build-linux-x86-full
else ifeq ($(PLATFORM)-$(ARCH),linux-arm64)
  DIST_DEPS := build-linux-arm-musl build-linux-arm-full
else ifeq ($(PLATFORM),macos)
  DIST_DEPS := build-macos-arm build-macos-x86 build-macos-universal
else
  DIST_DEPS := build-windows
endif

.PHONY: dist
dist: $(DIST_DEPS)
	@mkdir -p $(DIST)
	@built=0; \
	if [ -f target/$(TARGET_LINUX_X86_MUSL)/release/$(BIN) ]; then \
		cp target/$(TARGET_LINUX_X86_MUSL)/release/$(BIN) $(DIST)/$(BIN)-linux-x86_64; \
		echo "  $(DIST)/$(BIN)-linux-x86_64  (musl static)"; \
		built=$$((built+1)); \
	fi; \
	if [ -f target/$(TARGET_LINUX_X86_GNU)/release/$(BIN) ]; then \
		cp target/$(TARGET_LINUX_X86_GNU)/release/$(BIN) $(DIST)/$(BIN)-linux-x86_64-full; \
		echo "  $(DIST)/$(BIN)-linux-x86_64-full  (glibc+FUSE)"; \
		built=$$((built+1)); \
	fi; \
	if [ -f target/$(TARGET_LINUX_ARM_MUSL)/release/$(BIN) ]; then \
		cp target/$(TARGET_LINUX_ARM_MUSL)/release/$(BIN) $(DIST)/$(BIN)-linux-arm64; \
		echo "  $(DIST)/$(BIN)-linux-arm64  (musl static)"; \
		built=$$((built+1)); \
	fi; \
	if [ -f target/$(TARGET_LINUX_ARM_GNU)/release/$(BIN) ]; then \
		cp target/$(TARGET_LINUX_ARM_GNU)/release/$(BIN) $(DIST)/$(BIN)-linux-arm64-full; \
		echo "  $(DIST)/$(BIN)-linux-arm64-full  (glibc+FUSE)"; \
		built=$$((built+1)); \
	fi; \
	if [ -f target/$(TARGET_MACOS_ARM)/release/$(BIN) ]; then \
		cp target/$(TARGET_MACOS_ARM)/release/$(BIN) $(DIST)/$(BIN)-macos-arm64; \
		echo "  $(DIST)/$(BIN)-macos-arm64"; \
		built=$$((built+1)); \
	fi; \
	if [ -f target/$(TARGET_MACOS_X86)/release/$(BIN) ]; then \
		cp target/$(TARGET_MACOS_X86)/release/$(BIN) $(DIST)/$(BIN)-macos-x86_64; \
		echo "  $(DIST)/$(BIN)-macos-x86_64"; \
		built=$$((built+1)); \
	fi; \
	if [ -f $(DIST)/$(BIN)-macos-universal ]; then \
		echo "  $(DIST)/$(BIN)-macos-universal  (lipo)"; \
		built=$$((built+1)); \
	fi; \
	echo "$$built artifact(s) in $(DIST)/  |  Other platforms: git tag vX.Y.Z && git push --tags"

# -- Size reporting -------------------------------------------------------------

# Show sizes for all artifacts present in dist/ (local + any from CI).
size: build
	@echo "Binary sizes:"
	@ls -lh $(DIST)/$(BIN)-linux-x86_64 2>/dev/null \
		| awk '{print "  linux-x86_64 (musl):            " $$5}' || true
	@ls -lh $(DIST)/$(BIN)-linux-x86_64-full 2>/dev/null \
		| awk '{print "  linux-x86_64-full (glibc+FUSE): " $$5}' || true
	@ls -lh $(DIST)/$(BIN)-linux-arm64 2>/dev/null \
		| awk '{print "  linux-arm64 (musl):             " $$5}' || true
	@ls -lh $(DIST)/$(BIN)-linux-arm64-full 2>/dev/null \
		| awk '{print "  linux-arm64-full (glibc+FUSE):  " $$5}' || true
	@ls -lh $(DIST)/$(BIN)-macos-arm64 2>/dev/null \
		| awk '{print "  macos-arm64:                    " $$5}' || true
	@ls -lh $(DIST)/$(BIN)-macos-x86_64 2>/dev/null \
		| awk '{print "  macos-x86_64:                   " $$5}' || true
	@ls -lh $(DIST)/$(BIN)-macos-universal 2>/dev/null \
		| awk '{print "  macos-universal (lipo):         " $$5}' || true
	@ls -lh $(DIST)/$(BIN)-windows-x86_64-msvc.exe 2>/dev/null \
		| awk '{print "  windows-x86_64-msvc:            " $$5}' || true
	@ls -lh $(DIST)/$(BIN)-windows-x86_64-gnu.exe 2>/dev/null \
		| awk '{print "  windows-x86_64-gnu:             " $$5}' || true
	@ls -lh $(DIST)/$(BIN)-windows-arm64-msvc.exe 2>/dev/null \
		| awk '{print "  windows-arm64-msvc:             " $$5}' || true

# -- Convenience ---------------------------------------------------------------

.PHONY: fix
fix: fmt-fix lint-fix

hooks:
	git config core.hooksPath .githooks
	@echo "Git hooks installed (.githooks/pre-commit)"

.PHONY: clean
clean:
	$(CARGO) clean
	rm -rf $(DIST)
	# Note: ~/.cargo/advisory-db is intentionally preserved so `make audit`
	# remains usable after a clean. Remove it manually if you need a fresh
	# advisory fetch.

# -- Gates ---------------------------------------------------------------------

# Full verification gate  --  run before every push.
.PHONY: check-all
check-all: fmt lint audit check test-matrix doc hygiene machete
