# depsec

> **Dependency Security Gate** — intercept, validate, and scan packages before they touch your `node_modules`.

## The Problem

Modern software supply chains are under constant attack:

- **Typosquats & hallucinated packages**: AI coding assistants ("vibe coders") suggest package names that don't exist. Attackers register these names and wait for installs.
- **Install-time malware**: Packages like the **Mini Shai-Hulud** campaign execute malicious `postinstall` scripts, persist malware in `.claude/` and `.vscode/` directories, and survive `npm uninstall`.
- **Dependency tree blindness**: Most tools scan your `package-lock.json` *after* install. By then, 50+ sub-dependencies have already executed arbitrary code on your machine.

Existing tools (Snyk, Dependabot, OSV) focus on **known CVEs** — version bumps for disclosed vulnerabilities. They don't catch:
- Valid packages with valid provenance that contain novel malware
- Typosquats with zero CVEs
- Install-time persistence mechanisms

## What depsec Does

depsec is a **command wrapper** that sits between you and the package manager. It intercepts `npm install`, resolves what *would* be installed, validates every name, downloads every tarball to a quarantined temp directory, scans it for malicious patterns, verifies checksums, and only then allows the real install to proceed.

### Two-Layer Defense

```
┌─────────────────────────────────────────┐
│  depsec npm install express           │
│                                         │
│  ┌─────────────┐   ┌───────────────┐   │
│  │  FAST GATE  │   │   SCANNER     │   │
│  │  (< 50ms)   │   │  (concurrent) │   │
│  │             │   │               │   │
│  │ • Registry  │   │ • Install     │   │
│  │   existence │   │   scripts     │   │
│  │ • Typosquat │   │ • Persistence │   │
│  │   detection │   │   paths       │   │
│  │ • Project   │   │ • Network     │   │
│  │   context   │   │   beacons     │   │
│  └──────┬──────┘   └───────┬───────┘   │
│         │                  │           │
│         └────────┬─────────┘           │
│                  ▼                      │
│         ┌─────────────┐                 │
│         │  ALLOW or   │                 │
│         │  BLOCK       │                 │
│         └─────────────┘                 │
└─────────────────────────────────────────┘
```

## Features

### Feature 1: Dependency Validation (Anti-Typosquatting)

Before any tarball is downloaded, depsec validates the requested package name against three checks:

1. **Registry Existence** — Queries the live registry (npm, pypi, crates.io). If the package doesn't exist, it blocks immediately and suggests the closest popular match.
   ```bash
   $ depsec install npm express-fake-package-12345
   [depsec] BLOCKED: package "express-fake-package-12345" not found in registry
              Did you mean: express?
   ```

2. **Typosquat Detection** — Uses Levenshtein distance, homoglyph normalization (Cyrillic `е` vs Latin `e`), and common prefix/suffix swaps against a local database of top-10,000 packages. If a new, low-download package is one edit away from `lodash`, it warns loudly.

3. **Project Context** — Checks if the package already exists in your `package.json` / `requirements.txt` / `Cargo.toml`. New dependencies in a mature project are higher-risk and get stricter scrutiny.

### Feature 2: Malicious Code Scanning

For every package that passes the gate — including all sub-dependencies in the tree — depsec:

1. **Downloads the tarball** to a temporary quarantine directory (never touches `node_modules`)
2. **Verifies the checksum** against the registry's declared hash (SHA1 for npm, SHA256 for cargo/pip)
3. **Scans the extracted contents** with a rule engine:
   - Install scripts (`preinstall`, `postinstall`) containing network calls (`curl`, `fetch`, `wget`)
   - File writes to persistence directories (`.claude/`, `.vscode/`, `.github/workflows/`, `~/.ssh/`)
   - Obfuscated payloads (`eval(atob(...))`, high-entropy strings)
   - Import-time execution in Python (`__init__.py` with `requests.get` at module load)
4. **Blocks the entire install** if any package in the tree hits Critical or High severity

### Multi-Language Support (In Progress)

| Language | Registry | Gate | Tree Scan | Checksum |
|----------|----------|------|-----------|----------|
| npm / Node.js | ✅ | ✅ | ✅ | SHA1 |
| Python (pip) | 🚧 | 🚧 | 🚧 | SHA256 |
| Rust (cargo) | 🚧 | 🚧 | 🚧 | SHA256 |

## Installation

### From Source

Requires Go 1.22+.

```bash
git clone https://github.com/yourusername/depsec.git
cd depsec
go build ./cmd/depsec
```

### Alias Your Package Manager (Recommended)

Add to your shell profile (`.bashrc`, `.zshrc`, etc.):

```bash
alias npm="depsec npm"
alias pip="depsec pip"
alias cargo="depsec cargo"
```

This makes depsec transparent — you type `npm install express` and depsec intercepts it automatically.

## Usage

### Intercept Mode

```bash
# This runs depsec validation + scanning, then real npm install if clean
depsec install npm express

# Same for dev dependencies
depsec install npm --save-dev jest
```

### Scan an Existing Lockfile (Offline)

```bash
depsec scan package-lock.json
```

### Update the Typosquat Database

```bash
depsec update-db
```

## Architecture

```
depsec/
├── cmd/depsec/
│   └── main.go              # CLI entrypoint
├── internal/
│   ├── cli/
│   │   └── install.go       # Command parsing, passthrough logic
│   ├── registry/
│   │   ├── client.go        # Registry interface + factory
│   │   ├── npm.go           # npm registry client + tree resolver
│   │   ├── pip.go           # PyPI stub
│   │   └── cargo.go         # crates.io stub
│   ├── typosquat/
│   │   └── engine.go        # Levenshtein + homoglyph detection
│   ├── project/
│   │   └── detector.go      # Manifest parsing (package.json, etc.)
│   ├── gate/
│   │   └── gate.go          # Orchestrates checks 1-3
│   ├── quarantine/
│   │   └── manager.go       # Temp dir, tarball extraction, checksum verification
│   ├── scanner/
│   │   ├── engine.go        # Rule engine + concurrent worker pool
│   │   ├── tree_scanner.go  # Full dependency tree scanning
│   │   └── npm_rules.go     # npm-specific malicious patterns
│   └── analyst/             # (Future) AI explanation layer
```

### Design Decisions

- **Deterministic gate, not AI**: The blocking decision is made by fast, auditable Go code (regex, AST traversal, path matching). No LLM hallucinations can accidentally allow malware through.
- **Wrapper, not proxy**: A local registry proxy (Verdaccio-style) requires background daemons and breaks private registry auth. A CLI wrapper is stateless, respects your existing `.npmrc`, and works offline after scanning.
- **Tree-wide scanning**: We resolve the full dependency graph and scan every unique package, not just the top-level request. A malicious package at depth 3 is still caught.
- **Checksum verification**: Every downloaded tarball is verified against the registry's declared hash before extraction. Prevents CDN compromise or man-in-the-middle substitution attacks.

## Scanner Rules (Current)

| Rule ID | Severity | What it detects |
|---------|----------|-----------------|
| `npm-postinstall-network` | **Critical** | `preinstall`/`postinstall` scripts containing `http`, `curl`, `wget`, `fetch`, or `node -e` |
| `npm-persistence-path` | **Critical** | Files in tarball targeting `.claude/`, `.vscode/`, or `.github/workflows/` |

More rules coming: obfuscation detection, Python import-time execution, Rust `build.rs` analysis.

## Roadmap

- [x] npm registry client with tree resolution
- [x] Typosquat engine (Levenshtein + homoglyphs)
- [x] Concurrent tarball scanner with worker pool
- [x] SHA1/SHA256 checksum verification
- [x] Quarantine extraction with path-traversal protection
- [ ] PyPI registry client + wheel/sdist scanning
- [ ] crates.io registry client + `build.rs` analysis
- [ ] Obfuscation detection (entropy analysis, `eval(atob(...))`)
- [ ] AI analyst layer (local LLM explaining blocked packages)
- [ ] Disk-persistent registry metadata cache
- [ ] `package-lock.json` / `Cargo.lock` exact-version parsing
- [ ] CI mode (`--ci`) with JSON report output

## Why "depsec"?

Because "depguard" was already taken. And because this is **dependency security**, not just dependency management.

## License

MIT

## Acknowledgments

Built in response to the **Mini Shai-Hulud** supply chain campaign (May 2026) and the ongoing wave of Next.js ecosystem attacks. Deterministic security tools for deterministic threats.
