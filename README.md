# github-reae

Reverse-engineer any GitHub repo: infer architecture, data models, and key flows.

## Install

```bash
pip install git+https://github.com/JovianOps/github-reae.git
```

## Usage

```bash
github-reae owner/repo
github-reae https://github.com/owner/repo
github-reae owner/repo --max-files 300
```

Set `GITHUB_TOKEN` to raise API rate limits or to analyze private repos.

Output is plain markdown on stdout (progress and warnings go to stderr).

## What it does

- Fetches the file tree via the GitHub REST API
- Detects language and frameworks (package.json, pyproject.toml, Cargo.toml, go.mod, ...)
- Finds entry points (main.py, index.js, main.go, src/main.rs, App.jsx, ...)
- Builds an internal import graph for Python, JS/TS, Rust and Go
- Infers data models (dataclasses, pydantic/ORM models, TS interfaces, Rust/Go structs, SQL tables)
- Traces key flows outward from each entry point

Stdlib only. No LLM, no tree-sitter: parsing is regex-based and best-effort.

## License

MIT
