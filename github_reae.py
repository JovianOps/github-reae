#!/usr/bin/env python3
"""Reverse-engineer any GitHub repo: infer architecture, data models, and key flows."""

from __future__ import annotations

import argparse
import json
import os
import posixpath
import re
import sys
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import PurePosixPath
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

__version__ = "1.0.0"

GITHUB_API = "https://api.github.com/repos"
RAW_BASE = "https://raw.githubusercontent.com"
HTTP_TIMEOUT = 20
MAX_FILE_BYTES = 200_000
DEFAULT_MAX_FILES = 150

SOURCE_EXTS = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".rs": "Rust",
    ".go": "Go",
}
MODEL_ONLY_EXTS = {".sql"}
JS_EXTS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
SKIP_DIRS = {
    "node_modules", "vendor", "dist", "build", "target", ".git", "__pycache__",
    "venv", ".venv", "site-packages", ".next", "coverage", ".tox", ".mypy_cache",
}
MANIFESTS = ("pyproject.toml", "requirements.txt", "setup.py", "package.json",
             "Cargo.toml", "go.mod", "composer.json")

FRAMEWORKS = {
    # Python
    "django": "Django", "flask": "Flask", "fastapi": "FastAPI", "starlette": "Starlette",
    "pydantic": "Pydantic", "sqlalchemy": "SQLAlchemy", "celery": "Celery",
    "pytest": "pytest", "click": "Click", "typer": "Typer", "aiohttp": "aiohttp",
    # JS / TS
    "react": "React", "next": "Next.js", "vue": "Vue", "nuxt": "Nuxt", "svelte": "Svelte",
    "express": "Express", "fastify": "Fastify", "koa": "Koa", "nestjs": "NestJS",
    "@nestjs/core": "NestJS", "electron": "Electron", "vite": "Vite", "webpack": "Webpack",
    "jest": "Jest", "vitest": "Vitest", "prisma": "Prisma", "typescript": "TypeScript",
    "@angular/core": "Angular", "tailwindcss": "Tailwind CSS",
    # Rust
    "tokio": "Tokio", "actix-web": "Actix Web", "axum": "Axum", "rocket": "Rocket",
    "serde": "Serde", "clap": "Clap", "wgpu": "wgpu", "bevy": "Bevy", "diesel": "Diesel",
    "sqlx": "SQLx",
    # Go
    "gin-gonic/gin": "Gin", "labstack/echo": "Echo", "gofiber/fiber": "Fiber",
    "spf13/cobra": "Cobra", "gorilla/mux": "gorilla/mux", "gorm.io/gorm": "GORM",
    # PHP
    "laravel/framework": "Laravel", "symfony/symfony": "Symfony",
}

DIR_HINTS = {
    "api": "API layer", "routes": "routing", "router": "routing", "controllers": "request controllers",
    "handlers": "request handlers", "views": "views/templates", "models": "data models",
    "schemas": "schemas/data models", "entities": "domain entities", "db": "database access",
    "database": "database access", "migrations": "schema migrations", "services": "business logic",
    "core": "core logic", "lib": "library code", "utils": "shared helpers", "helpers": "shared helpers",
    "middleware": "middleware", "config": "configuration", "cli": "command-line interface",
    "cmd": "executables (Go)", "pkg": "public packages (Go)", "internal": "private packages (Go)",
    "components": "UI components", "pages": "UI pages/routes", "app": "application code",
    "src": "main source", "public": "static assets", "static": "static assets",
    "assets": "static assets", "scripts": "tooling scripts", "tests": "tests", "test": "tests",
    "__tests__": "tests", "docs": "documentation", "examples": "examples", ".github": "CI/workflows",
    "bin": "executables", "crates": "workspace crates", "packages": "workspace packages",
}

_PY_STDLIB_FALLBACK = {
    "abc", "argparse", "asyncio", "base64", "collections", "contextlib", "copy", "csv",
    "dataclasses", "datetime", "decimal", "enum", "functools", "glob", "hashlib", "http",
    "importlib", "inspect", "io", "itertools", "json", "logging", "math", "multiprocessing",
    "os", "pathlib", "pickle", "platform", "queue", "random", "re", "shutil", "signal",
    "socket", "sqlite3", "string", "struct", "subprocess", "sys", "tempfile", "threading",
    "time", "traceback", "types", "typing", "unittest", "urllib", "uuid", "warnings",
    "weakref", "xml", "zipfile", "__future__",
}
PY_STDLIB: Set[str] = set(getattr(sys, "stdlib_module_names", _PY_STDLIB_FALLBACK)) | {"__future__"}

Fetcher = Callable[[str], Optional[str]]


# --------------------------------------------------------------------------- #
# Networking
# --------------------------------------------------------------------------- #

def _parse_repo_arg(arg: str) -> str:
    """Parse 'owner/repo' or a full GitHub URL to 'owner/repo'."""
    arg = arg.strip()
    for prefix in ("https://github.com/", "http://github.com/", "https://www.github.com/",
                   "github.com/"):
        if arg.startswith(prefix):
            parts = arg[len(prefix):].strip("/").split("/")
            result = "/".join(parts[:2])
            break
    else:
        result = arg.rstrip("/")
    if result.endswith(".git"):
        result = result[: -len(".git")]
    return result


def _headers(accept: str) -> Dict[str, str]:
    headers = {"User-Agent": f"github-reae/{__version__}", "Accept": accept}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _fetch_json(url: str) -> dict:
    """Fetch JSON from URL, exit with a readable message on error."""
    req = Request(url, headers=_headers("application/vnd.github+json"))
    try:
        with urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            return json.loads(resp.read())
    except HTTPError as e:
        hint = ""
        if e.code == 404:
            hint = " (repo not found, or private: set GITHUB_TOKEN)"
        elif e.code in (403, 429):
            hint = " (rate limited: set GITHUB_TOKEN to raise the limit)"
        raise SystemExit(f"Error: HTTP {e.code} fetching {url}{hint}")
    except URLError as e:
        raise SystemExit(f"Error: cannot reach {url} - {e.reason}")
    except (ValueError, TimeoutError, OSError) as e:
        raise SystemExit(f"Error: bad response from {url} - {e}")


def _get_repo_tree(owner_repo: str) -> dict:
    """Fetch repo metadata and file tree via GitHub API."""
    meta = _fetch_json(f"{GITHUB_API}/{owner_repo}")
    default_branch = meta.get("default_branch")
    if not default_branch:
        raise SystemExit(f"Error: no default branch reported for {owner_repo}")
    tree = _fetch_json(
        f"{GITHUB_API}/{owner_repo}/git/trees/{quote(default_branch, safe='')}?recursive=1"
    )
    if "tree" not in tree:
        raise SystemExit(f"Error: unexpected tree response for {owner_repo}")
    if tree.get("truncated"):
        print("Warning: tree truncated (repo too large), analysis may be incomplete",
              file=sys.stderr)
    return {"meta": meta, "tree": tree}


def _make_raw_fetcher(owner_repo: str, branch: str) -> Fetcher:
    """Return a function path -> file text (None on any failure)."""
    def fetch(path: str) -> Optional[str]:
        url = f"{RAW_BASE}/{owner_repo}/{quote(branch, safe='')}/{quote(path)}"
        req = Request(url, headers=_headers("text/plain"))
        try:
            with urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except (HTTPError, URLError, TimeoutError, OSError):
            return None
    return fetch


# --------------------------------------------------------------------------- #
# Tree helpers
# --------------------------------------------------------------------------- #

def _blobs(file_tree: dict) -> List[dict]:
    return [i for i in file_tree["tree"] if i.get("type") == "blob"]


def _is_skipped(path: str) -> bool:
    return any(part in SKIP_DIRS for part in path.split("/")[:-1])


def _is_test(path: str) -> bool:
    p = PurePosixPath(path)
    name = p.name
    if any(part in ("tests", "test", "__tests__", "spec", "testdata") for part in p.parts[:-1]):
        return True
    return bool(re.search(r"(^test_.*\.py$|_test\.(py|go)$|\.(test|spec)\.[jt]sx?$|^conftest\.py$)", name))


def _detect_language(file_tree: dict) -> str:
    """Detect primary language from root config files."""
    paths = {item["path"] for item in file_tree["tree"]}
    signals = {
        "pyproject.toml": "Python",
        "package.json": "Node.js",
        "Cargo.toml": "Rust",
        "go.mod": "Go",
        "setup.py": "Python",
        "build.gradle": "Java/Kotlin (Gradle)",
        "pom.xml": "Java (Maven)",
        "CMakeLists.txt": "C/C++",
        "composer.json": "PHP",
    }
    for signal, lang in signals.items():
        if signal in paths:
            return lang
    ext_count: Dict[str, int] = {}
    for item in file_tree["tree"]:
        if item.get("type") == "blob":
            ext = PurePosixPath(item["path"]).suffix
            if ext:
                ext_count[ext] = ext_count.get(ext, 0) + 1
    if ext_count:
        top_ext = max(ext_count, key=lambda k: ext_count[k])
        return f"Unknown (most common extension: {top_ext})"
    return "Unknown"


_EXACT_ENTRIES = ["main.py", "index.js", "main.js", "main.go", "src/main.rs", "lib.rs",
                  "app.py", "run.py", "cli.js", "bin.js"]
_ENTRY_PATTERNS = [
    re.compile(r"^(?:[\w.-]+/)?src/lib\.rs$"),
    re.compile(r"^(?:[\w.-]+/)?src/main\.rs$"),
    re.compile(r"^(?:[\w.-]+/)?src/bin/[\w.-]+\.rs$"),
    re.compile(r"^cmd/[\w.-]+/main\.go$"),
    re.compile(r"^(?:[\w.-]+/)?__main__\.py$"),
    re.compile(r"^src/(?:index|main)\.(?:js|jsx|ts|tsx|mjs)$"),
    re.compile(r"^(?:src/|app/)?App\.(?:jsx|tsx|js|ts)$"),
    re.compile(r"^src/[\w.-]+/(?:main|app|cli)\.py$"),
    re.compile(r"^(?:src/)?(?:server|app)\.(?:js|ts)$"),
    re.compile(r"^bin/[\w.-]+\.(?:js|py)$"),
]


def _find_entry_points(file_tree: dict) -> list:
    """Find likely entry points in the repo tree."""
    paths = {item["path"] for item in file_tree["tree"] if item.get("type", "blob") == "blob"}
    found = [s for s in _EXACT_ENTRIES if s in paths]
    for path in sorted(paths):
        if path in found or _is_skipped(path):
            continue
        if any(p.match(path) for p in _ENTRY_PATTERNS):
            found.append(path)
    return found


def _declared_entry_points(manifests: Dict[str, str], paths: Set[str]) -> List[str]:
    """Entry points declared in package.json (main/bin) and pyproject [project.scripts]."""
    found: List[str] = []

    def add(p: str) -> None:
        p = posixpath.normpath(p)
        if p in paths and p not in found:
            found.append(p)

    pkg = manifests.get("package.json")
    if pkg:
        try:
            data = json.loads(pkg)
            if isinstance(data, dict):
                if isinstance(data.get("main"), str):
                    add(data["main"])
                bins = data.get("bin")
                if isinstance(bins, str):
                    add(bins)
                elif isinstance(bins, dict):
                    for v in bins.values():
                        if isinstance(v, str):
                            add(v)
        except ValueError:
            pass
    pyproject = manifests.get("pyproject.toml")
    if pyproject:
        section = re.search(r"^\[project\.scripts\]\s*\n(.*?)(?=^\[|\Z)", pyproject, re.M | re.S)
        if section:
            for mod in re.findall(r'=\s*["\']([\w.]+)(?::[\w.]+)?["\']', section.group(1)):
                base = mod.replace(".", "/")
                for cand in (f"{base}.py", f"{base}/__init__.py", f"src/{base}.py",
                             f"src/{base}/__init__.py"):
                    add(cand)
    return found


def _detect_frameworks(manifests: Dict[str, str]) -> List[str]:
    """Detect frameworks/libraries by scanning manifest dependency text."""
    found: List[str] = []
    for text in manifests.values():
        lower = text.lower()
        for key, label in FRAMEWORKS.items():
            if label in found:
                continue
            if re.search(r"(?<![\w@./-])" + re.escape(key) + r"(?![\w-])", lower):
                found.append(label)
    return sorted(found)


# --------------------------------------------------------------------------- #
# Import extraction
# --------------------------------------------------------------------------- #

def _norm(path: str) -> Optional[str]:
    n = posixpath.normpath(path)
    if n.startswith("..") or n.startswith("/"):
        return None
    return "" if n == "." else n


_PY_FROM = re.compile(r"^[ \t]*from[ \t]+(\.*)([\w.]*)[ \t]+import[ \t]+([^\n#]*)", re.M)
_PY_IMPORT = re.compile(r"^[ \t]*import[ \t]+([^\n#]+)", re.M)


def _resolve_python(module: str, level: int, current: str, paths: Set[str]) -> Optional[str]:
    cur_dir = posixpath.dirname(current)
    if level:
        base = cur_dir
        for _ in range(level - 1):
            base = posixpath.dirname(base)
        roots = [base]
    else:
        roots = ["", "src", cur_dir]
    parts = module.split(".") if module else []
    for root in roots:
        stem = posixpath.join(root, *parts) if parts else root
        cands = [f"{stem}/__init__.py"]
        if parts:
            cands.insert(0, f"{stem}.py")
        for cand in cands:
            n = _norm(cand)
            if n and n in paths:
                return n
    return None


def _extract_python(path: str, text: str, paths: Set[str]) -> Tuple[Set[str], Set[str]]:
    internal: Set[str] = set()
    external: Set[str] = set()

    def link(module: str, level: int, names: Iterable[str] = ()) -> bool:
        hit = False
        for name in names:
            sub = f"{module}.{name}" if module else name
            r = _resolve_python(sub, level, path, paths)
            if r and r != path:
                internal.add(r)
                hit = True
        if module or not names:
            r = _resolve_python(module, level, path, paths)
            if r and r != path:
                internal.add(r)
                hit = True
        return hit

    for m in _PY_FROM.finditer(text):
        dots, module, rest = m.group(1), m.group(2), m.group(3)
        names = [n for n in re.findall(r"\w+", rest) if n != "as"]
        hit = link(module, len(dots), names)
        if not dots and not hit and module:
            top = module.split(".")[0]
            if top not in PY_STDLIB:
                external.add(top)
    for m in _PY_IMPORT.finditer(text):
        for chunk in m.group(1).split(","):
            module = chunk.strip().split(" as ")[0].strip()
            if not re.fullmatch(r"[\w.]+", module):
                continue
            if not link(module, 0):
                top = module.split(".")[0]
                if top not in PY_STDLIB:
                    external.add(top)
    internal.discard(path)
    return internal, external


_JS_IMPORT = re.compile(
    r"""(?:import|export)\s+(?:[^'"()]*?\s+from\s+)?['"]([^'"]+)['"]"""
    r"""|require\(\s*['"]([^'"]+)['"]\s*\)"""
    r"""|import\(\s*['"]([^'"]+)['"]\s*\)"""
)


def _resolve_js(spec: str, current: str, paths: Set[str]) -> Optional[str]:
    target = _norm(posixpath.join(posixpath.dirname(current), spec))
    if not target:
        return None
    cands = [target]
    if target.endswith((".js", ".jsx", ".mjs", ".cjs")):
        stem = target.rsplit(".", 1)[0]
        cands += [stem + ".ts", stem + ".tsx"]
    cands += [target + ext for ext in JS_EXTS]
    cands += [f"{target}/index{ext}" for ext in JS_EXTS]
    for cand in cands:
        if cand in paths:
            return cand
    return None


def _extract_js(path: str, text: str, paths: Set[str]) -> Tuple[Set[str], Set[str]]:
    internal: Set[str] = set()
    external: Set[str] = set()
    for m in _JS_IMPORT.finditer(text):
        spec = m.group(1) or m.group(2) or m.group(3)
        if not spec:
            continue
        if spec.startswith("."):
            r = _resolve_js(spec, path, paths)
            if r and r != path:
                internal.add(r)
        elif spec.startswith(("node:", "/", "data:", "http:", "https:")):
            continue
        else:
            segs = spec.split("/")
            external.add("/".join(segs[:2]) if spec.startswith("@") else segs[0])
    return internal, external


_RS_MOD = re.compile(r"^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?mod[ \t]+(\w+)[ \t]*;", re.M)
_RS_USE = re.compile(r"^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?use[ \t]+(?:::)?(\w+)(?:::(\w+))?", re.M)
_RS_BUILTIN = {"crate", "self", "super", "std", "core", "alloc", "proc_macro", "test"}


def _extract_rust(path: str, text: str, paths: Set[str]) -> Tuple[Set[str], Set[str]]:
    internal: Set[str] = set()
    external: Set[str] = set()
    p = PurePosixPath(path)
    cur_dir = str(p.parent) if str(p.parent) != "." else ""
    base = cur_dir if p.name in ("lib.rs", "main.rs", "mod.rs") else posixpath.join(cur_dir, p.stem)
    idx = path.find("src/")
    crate_root = path[: idx + 3] if idx != -1 else cur_dir

    def first_existing(*cands: str) -> Optional[str]:
        for c in cands:
            n = _norm(c)
            if n and n in paths:
                return n
        return None

    declared: Set[str] = set()
    for m in _RS_MOD.finditer(text):
        name = m.group(1)
        declared.add(name)
        r = first_existing(f"{base}/{name}.rs", f"{base}/{name}/mod.rs")
        if r:
            internal.add(r)
    for m in _RS_USE.finditer(text):
        head, second = m.group(1), m.group(2)
        if head == "crate" and second:
            r = first_existing(f"{crate_root}/{second}.rs", f"{crate_root}/{second}/mod.rs")
            if r:
                internal.add(r)
        elif head not in _RS_BUILTIN and head not in declared:
            external.add(head)
    internal.discard(path)
    return internal, external


_GO_BLOCK = re.compile(r"^[ \t]*import[ \t]*\((.*?)\)", re.M | re.S)
_GO_SINGLE = re.compile(r'^[ \t]*import[ \t]+(?:[\w.]+[ \t]+)?"([^"]+)"', re.M)
_GO_QUOTED = re.compile(r'^[ \t]*(?:[\w.]+[ \t]+)?"([^"]+)"', re.M)


def _go_module(manifests: Dict[str, str]) -> str:
    m = re.search(r"^module[ \t]+(\S+)", manifests.get("go.mod", ""), re.M)
    return m.group(1) if m else ""


def _go_dirs(paths: Iterable[str]) -> Dict[str, List[str]]:
    dirs: Dict[str, List[str]] = {}
    for p in sorted(paths):
        if p.endswith(".go") and not p.endswith("_test.go") and not _is_skipped(p):
            dirs.setdefault(posixpath.dirname(p), []).append(p)
    return dirs


def _extract_go(path: str, text: str, go_module: str,
                go_dirs: Dict[str, List[str]]) -> Tuple[Set[str], Set[str]]:
    internal: Set[str] = set()
    external: Set[str] = set()
    imports: List[str] = []
    for block in _GO_BLOCK.finditer(text):
        imports += _GO_QUOTED.findall(block.group(1))
    imports += _GO_SINGLE.findall(text)
    for imp in imports:
        if go_module and (imp == go_module or imp.startswith(go_module + "/")):
            rel = imp[len(go_module):].strip("/")
            for f in go_dirs.get(rel, [])[:3]:
                if f != path:
                    internal.add(f)
        elif "." in imp.split("/")[0]:
            external.add("/".join(imp.split("/")[:3]))
    return internal, external


def _extract_imports(path: str, text: str, paths: Set[str], go_module: str = "",
                     go_dirs: Optional[Dict[str, List[str]]] = None) -> Tuple[Set[str], Set[str]]:
    """Return (internal file paths imported, external package names) for one file."""
    ext = PurePosixPath(path).suffix.lower()
    if ext == ".py":
        return _extract_python(path, text, paths)
    if ext in JS_EXTS:
        return _extract_js(path, text, paths)
    if ext == ".rs":
        return _extract_rust(path, text, paths)
    if ext == ".go":
        return _extract_go(path, text, go_module, go_dirs or {})
    return set(), set()


# --------------------------------------------------------------------------- #
# Data model extraction
# --------------------------------------------------------------------------- #

_PY_CLASS = re.compile(r"^((?:@[^\n]+\n)*)class[ \t]+(\w+)[ \t]*(?:\(([^)]*)\))?[ \t]*:", re.M)
_PY_MODEL_BASES = re.compile(
    r"\b(\w*Model|Base|DeclarativeBase|SQLModel|TypedDict|NamedTuple|Schema|Document|Enum|"
    r"IntEnum|StrEnum|Struct)\b"
)
_TS_DECL = re.compile(r"^[ \t]*(?:export[ \t]+)?(?:declare[ \t]+)?(interface|enum)[ \t]+(\w+)|"
                      r"^[ \t]*(?:export[ \t]+)?type[ \t]+(\w+)(?:<[^>\n]*>)?[ \t]*=[ \t]*\{", re.M)
_RS_DECL = re.compile(r"^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?(struct|enum)[ \t]+(\w+)", re.M)
_GO_DECL = re.compile(r"^type[ \t]+(\w+)[ \t]+(struct|interface)\b", re.M)
_SQL_DECL = re.compile(r"CREATE[ \t]+TABLE[ \t]+(?:IF[ \t]+NOT[ \t]+EXISTS[ \t]+)?[\"`\[]?([\w.]+)",
                       re.I)


def _py_fields(text: str, start: int, limit: int = 8) -> List[str]:
    """Collect up to `limit` field names from the indented class body starting at `start`."""
    fields: List[str] = []
    for line in text[start:].split("\n")[1:]:
        if line.strip() and not line.startswith((" ", "\t")):
            break
        m = re.match(r"^[ \t]{1,8}(\w+)[ \t]*(?::[^=\n]+)?=?[ \t]*(?:models\.|Column\(|Field\()?", line)
        if m and not line.lstrip().startswith(("def ", "class ", "@", "#", '"""', "'''", "return", "pass")):
            name = m.group(1)
            if (re.match(r"^[ \t]+\w+[ \t]*:", line) or re.match(r"^[ \t]+\w+[ \t]*=[ \t]*[\w.]*(Field|Column|ForeignKey|Key)\b", line)) \
                    and name not in fields and not name.startswith("__"):
                fields.append(name)
        if len(fields) >= limit:
            break
    return fields


def _extract_models(path: str, text: str) -> List[dict]:
    """Infer data models declared in one file."""
    ext = PurePosixPath(path).suffix.lower()
    models: List[dict] = []
    if ext == ".py":
        for m in _PY_CLASS.finditer(text):
            decorators, name, bases = m.group(1) or "", m.group(2), m.group(3) or ""
            kind = None
            if re.search(r"@(?:dataclasses\.)?dataclass", decorators):
                kind = "dataclass"
            elif _PY_MODEL_BASES.search(bases):
                kind = "enum" if re.search(r"Enum", bases) else "model"
            if kind:
                models.append({"name": name, "kind": kind, "file": path,
                               "fields": _py_fields(text, m.end())})
    elif ext in (".ts", ".tsx"):
        for m in _TS_DECL.finditer(text):
            if m.group(1):
                models.append({"name": m.group(2), "kind": m.group(1), "file": path, "fields": []})
            else:
                models.append({"name": m.group(3), "kind": "type", "file": path, "fields": []})
    elif ext == ".rs":
        for m in _RS_DECL.finditer(text):
            models.append({"name": m.group(2), "kind": m.group(1), "file": path, "fields": []})
    elif ext == ".go":
        for m in _GO_DECL.finditer(text):
            if m.group(2) == "struct":
                models.append({"name": m.group(1), "kind": "struct", "file": path, "fields": []})
    elif ext == ".sql":
        for m in _SQL_DECL.finditer(text):
            models.append({"name": m.group(1), "kind": "table", "file": path, "fields": []})
    return models


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #

def _select_source_files(file_tree: dict, limit: int = DEFAULT_MAX_FILES) -> List[str]:
    """Choose which files to download: entry points first, then shallow files."""
    entries = set(_find_entry_points(file_tree))
    cands: List[str] = []
    for item in _blobs(file_tree):
        p = item["path"]
        ext = PurePosixPath(p).suffix.lower()
        if _is_skipped(p) or _is_test(p):
            continue
        if ext not in SOURCE_EXTS and ext not in MODEL_ONLY_EXTS:
            continue
        if item.get("size", 0) > MAX_FILE_BYTES:
            continue
        cands.append(p)
    cands.sort(key=lambda p: (p not in entries, p.count("/"), p))
    return cands[: max(limit, 0)]


def _fetch_many(fetch: Fetcher, paths: List[str], workers: int = 8) -> Dict[str, Optional[str]]:
    if not paths:
        return {}

    def safe(p: str) -> Optional[str]:
        try:
            return fetch(p)
        except Exception:  # a single bad file must never abort the analysis
            return None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return dict(zip(paths, pool.map(safe, paths)))


def _analyze(repo_data: dict, fetch: Fetcher, max_files: int = DEFAULT_MAX_FILES) -> dict:
    """Download key files and build frameworks, import graph, and data models."""
    tree = repo_data["tree"]
    all_paths = {i["path"] for i in _blobs(tree)}

    root_manifests = [m for m in MANIFESTS if m in all_paths]
    fetched_manifests = _fetch_many(fetch, root_manifests)
    manifests = {k: v for k, v in fetched_manifests.items() if v}

    sources = _select_source_files(tree, max_files)
    total_candidates = len(_select_source_files(tree, 10 ** 9))
    contents = _fetch_many(fetch, sources)

    go_module = _go_module(manifests)
    go_dirs = _go_dirs(all_paths)

    graph: Dict[str, List[str]] = {}
    externals: Counter = Counter()
    models: List[dict] = []
    analyzed = 0
    for path in sources:
        text = contents.get(path)
        if text is None:
            continue
        analyzed += 1
        try:
            internal, external = _extract_imports(path, text, all_paths, go_module, go_dirs)
            models.extend(_extract_models(path, text))
        except Exception as exc:  # regex edge cases must not kill the run
            print(f"Warning: failed to analyze {path}: {exc}", file=sys.stderr)
            continue
        graph[path] = sorted(internal)
        externals.update(external)

    return {
        "frameworks": _detect_frameworks(manifests),
        "declared_entries": _declared_entry_points(manifests, all_paths),
        "graph": graph,
        "externals": dict(externals),
        "models": models,
        "analyzed": analyzed,
        "candidates": total_candidates,
    }


def _key_flows(graph: Dict[str, List[str]], entries: List[str], max_depth: int = 3,
               max_per_level: int = 6) -> Dict[str, List[List[str]]]:
    """Breadth-first walk of the import graph from each entry point."""
    flows: Dict[str, List[List[str]]] = {}
    for entry in entries:
        if entry not in graph:
            continue
        seen = {entry}
        frontier = [entry]
        levels: List[List[str]] = []
        for _ in range(max_depth):
            nxt: List[str] = []
            for node in frontier:
                for dep in graph.get(node, []):
                    if dep not in seen:
                        seen.add(dep)
                        nxt.append(dep)
            if not nxt:
                break
            levels.append(nxt[:max_per_level] + ([f"... +{len(nxt) - max_per_level} more"]
                                                 if len(nxt) > max_per_level else []))
            frontier = nxt
        if levels:
            flows[entry] = levels
    return flows


def _components(file_tree: dict) -> List[dict]:
    """Summarize each top-level directory: file count, dominant language, role hint."""
    stats: Dict[str, Counter] = {}
    for item in _blobs(file_tree):
        parts = item["path"].split("/")
        if len(parts) < 2:
            continue
        ext = PurePosixPath(item["path"]).suffix.lower()
        stats.setdefault(parts[0], Counter())[SOURCE_EXTS.get(ext, "other")] += 1
    result = []
    for name in sorted(stats):
        counter = stats[name]
        langs = [(l, c) for l, c in counter.most_common() if l != "other"]
        result.append({
            "name": name,
            "files": sum(counter.values()),
            "language": langs[0][0] if langs else None,
            "hint": DIR_HINTS.get(name.lower()),
        })
    return result


# --------------------------------------------------------------------------- #
# Markdown rendering
# --------------------------------------------------------------------------- #

def _summarize(repo_data: dict, analysis: Optional[dict] = None) -> str:
    """Generate markdown summary of the repo. `analysis` comes from _analyze (optional)."""
    meta = repo_data["meta"]
    tree = repo_data["tree"]
    analysis = analysis or {}
    lines: List[str] = []

    lines += [f"# {meta.get('full_name', 'unknown/unknown')}", ""]
    if meta.get("html_url"):
        lines += [meta["html_url"], ""]
    lines += ["## Description", meta.get("description") or "No description provided.", ""]

    lang = _detect_language(tree)
    lines += [f"## Language: {lang}", ""]
    frameworks = analysis.get("frameworks") or []
    if frameworks:
        lines += ["**Frameworks/libraries detected:** " + ", ".join(frameworks), ""]

    blob_count = len(_blobs(tree))
    lines += [
        "## Stats",
        f"- Stars: {meta.get('stargazers_count', 0)}",
        f"- Fork: {meta.get('fork', False)}",
        f"- Open issues: {meta.get('open_issues_count', 0)}",
        f"- File count: {blob_count}",
        "",
    ]

    entries = list(_find_entry_points(tree))
    for e in analysis.get("declared_entries", []):
        if e not in entries:
            entries.append(e)
    lines.append("## Entry Points")
    lines += [f"- `{e}`" for e in entries] if entries else ["- None found"]
    lines.append("")

    top_dirs: Set[str] = set()
    top_files: Set[str] = set()
    for item in tree["tree"]:
        parts = item["path"].split("/")
        if len(parts) > 1 or item.get("type") == "tree":
            top_dirs.add(parts[0])
        elif item.get("type") == "blob":
            top_files.add(parts[0])
    lines.append("## Top-Level Structure")
    lines += [f"- 📁 {d}/" for d in sorted(top_dirs)]
    lines += [f"- 📄 {f}" for f in sorted(top_files)]
    lines.append("")

    components = _components(tree)
    if components:
        lines.append("## Components")
        for c in components:
            detail = [f"{c['files']} files"]
            if c["language"]:
                detail.append(c["language"])
            if c["hint"]:
                detail.append(c["hint"])
            lines.append(f"- `{c['name']}/` - " + ", ".join(detail))
        lines.append("")

    graph: Dict[str, List[str]] = analysis.get("graph", {})
    if analysis:
        edge_count = sum(len(v) for v in graph.values())
        lines += ["## Dependency Graph", f"- Files analyzed: {analysis.get('analyzed', 0)} "
                  f"of {analysis.get('candidates', 0)} source files",
                  f"- Internal import edges: {edge_count}"]
        indegree: Counter = Counter()
        for deps in graph.values():
            indegree.update(deps)
        if indegree:
            lines += ["", "**Most depended-on modules (core candidates):**"]
            lines += [f"- `{p}` ({n} importers)" for p, n in indegree.most_common(8)]
        externals: Dict[str, int] = analysis.get("externals", {})
        if externals:
            top = sorted(externals.items(), key=lambda kv: (-kv[1], kv[0]))[:15]
            lines += ["", "**External packages (by import count):**",
                      ", ".join(f"`{name}` ({n})" for name, n in top)]
        lines.append("")

        models: List[dict] = analysis.get("models", [])
        lines.append("## Data Models")
        if models:
            for m in models[:40]:
                fields = f" - fields: {', '.join(m['fields'])}" if m.get("fields") else ""
                lines.append(f"- `{m['name']}` ({m['kind']}) in `{m['file']}`{fields}")
            if len(models) > 40:
                lines.append(f"- ... and {len(models) - 40} more")
        else:
            lines.append("- None detected")
        lines.append("")

        lines.append("## Key Flows")
        flows = _key_flows(graph, entries)
        if flows:
            for entry, levels in flows.items():
                lines.append(f"- `{entry}`")
                for depth, level in enumerate(levels, 1):
                    rendered = ", ".join(x if x.startswith("...") else f"`{x}`" for x in level)
                    lines.append(f"  - depth {depth}: {rendered}")
        else:
            lines.append("- No import flows traced from entry points")
        lines.append("")

    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="github-reae",
        description="Reverse-engineer any GitHub repo: infer architecture, data models, and key flows.",
    )
    parser.add_argument("repo", help="owner/repo or https://github.com/owner/repo")
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES,
                        help=f"max source files to download (default {DEFAULT_MAX_FILES})")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    owner_repo = _parse_repo_arg(args.repo)
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", owner_repo):
        print(f"Error: invalid repo '{args.repo}', expected owner/repo or a GitHub URL",
              file=sys.stderr)
        return 1

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass

    try:
        print(f"Analyzing {owner_repo}...", file=sys.stderr)
        repo_data = _get_repo_tree(owner_repo)
        fetch = _make_raw_fetcher(owner_repo, repo_data["meta"]["default_branch"])
        try:
            analysis: Optional[dict] = _analyze(repo_data, fetch, args.max_files)
        except Exception as exc:
            print(f"Warning: deep analysis failed ({exc}); showing structure only", file=sys.stderr)
            analysis = None
        print(_summarize(repo_data, analysis))
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        return 130
    except BrokenPipeError:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
