"""Tests for github_reae."""
import json

import pytest

import github_reae
from github_reae import (
    _analyze,
    _detect_frameworks,
    _detect_language,
    _extract_imports,
    _extract_models,
    _find_entry_points,
    _key_flows,
    _parse_repo_arg,
    _summarize,
)


def _tree(*paths):
    return {"tree": [{"path": p, "type": "blob", "size": 100} for p in paths]}


# --- _parse_repo_arg -------------------------------------------------------

def test_parse_repo_arg_short():
    assert _parse_repo_arg("owner/repo") == "owner/repo"


def test_parse_repo_arg_url():
    assert _parse_repo_arg("https://github.com/owner/repo") == "owner/repo"


def test_parse_repo_arg_url_with_trailing_slash():
    assert _parse_repo_arg("https://github.com/owner/repo/") == "owner/repo"


def test_parse_repo_arg_url_with_path():
    assert _parse_repo_arg("https://github.com/owner/repo/blob/main/README.md") == "owner/repo"


def test_parse_repo_arg_git_suffix():
    assert _parse_repo_arg("https://github.com/owner/repo.git") == "owner/repo"


def test_parse_repo_arg_no_scheme():
    assert _parse_repo_arg("github.com/owner/repo") == "owner/repo"


# --- language / entry points ----------------------------------------------

def test_detect_language_python():
    tree = {"tree": [{"path": "pyproject.toml", "type": "blob"}, {"path": "main.py", "type": "blob"}]}
    assert _detect_language(tree) == "Python"


def test_detect_language_node():
    tree = {"tree": [{"path": "package.json", "type": "blob"}, {"path": "index.js", "type": "blob"}]}
    assert _detect_language(tree) == "Node.js"


def test_detect_language_fallback():
    tree = {"tree": [{"path": "foo.txt", "type": "blob"}, {"path": "bar.txt", "type": "blob"}]}
    assert _detect_language(tree) == "Unknown (most common extension: .txt)"


def test_detect_language_empty():
    assert _detect_language({"tree": []}) == "Unknown"


def test_find_entry_points():
    tree = {"tree": [{"path": "main.py", "type": "blob"}, {"path": "index.js", "type": "blob"}]}
    assert _find_entry_points(tree) == ["main.py", "index.js"]


def test_find_entry_points_none():
    tree = {"tree": [{"path": "README.md", "type": "blob"}]}
    assert _find_entry_points(tree) == []


def test_find_entry_points_patterns():
    tree = _tree("src/main.rs", "src/lib.rs", "cmd/tool/main.go", "src/App.jsx",
                 "node_modules/x/index.js", "pkg/__main__.py")
    found = _find_entry_points(tree)
    assert "src/main.rs" in found
    assert "src/lib.rs" in found
    assert "cmd/tool/main.go" in found
    assert "src/App.jsx" in found
    assert "pkg/__main__.py" in found
    assert "node_modules/x/index.js" not in found


# --- frameworks -------------------------------------------------------------

def test_detect_frameworks():
    manifests = {
        "package.json": '{"dependencies": {"react": "^18", "express": "^4"}}',
        "pyproject.toml": 'dependencies = ["fastapi>=0.100", "pydantic"]',
        "Cargo.toml": "[dependencies]\ntokio = \"1\"\n",
    }
    found = _detect_frameworks(manifests)
    for name in ("React", "Express", "FastAPI", "Pydantic", "Tokio"):
        assert name in found


def test_detect_frameworks_no_substring_false_positive():
    assert "React" not in _detect_frameworks({"package.json": '{"dependencies": {"preact-x": "1"}}'})


# --- imports -----------------------------------------------------------------

def test_python_imports_internal_and_external():
    paths = {"app/main.py", "app/utils.py", "app/models/__init__.py", "app/models/user.py"}
    text = (
        "import os\nimport requests\nfrom app import utils\nfrom .models import user\n"
        "from app.models import User\n"
    )
    internal, external = _extract_imports("app/main.py", text, paths)
    assert internal == {"app/utils.py", "app/models/__init__.py", "app/models/user.py"}
    assert external == {"requests"}


def test_python_relative_import_levels():
    paths = {"pkg/a/x.py", "pkg/b.py", "pkg/a/__init__.py"}
    internal, _ = _extract_imports("pkg/a/x.py", "from .. import b\nfrom . import x\n", paths)
    assert internal == {"pkg/b.py"}


def test_js_imports():
    paths = {"src/index.ts", "src/lib/util.ts", "src/components/index.tsx"}
    text = (
        "import React from 'react';\n"
        "import { u } from './lib/util.js';\n"
        "export * from './components';\n"
        "const fs = require('node:fs');\n"
        "const s = require('@scope/pkg/deep');\n"
    )
    internal, external = _extract_imports("src/index.ts", text, paths)
    assert internal == {"src/lib/util.ts", "src/components/index.tsx"}
    assert external == {"react", "@scope/pkg"}


def test_rust_imports():
    paths = {"src/main.rs", "src/config.rs", "src/db/mod.rs", "src/db/pool.rs"}
    text = "mod config;\nmod db;\nuse serde::Serialize;\nuse crate::db::pool;\nuse std::fmt;\n"
    internal, external = _extract_imports("src/main.rs", text, paths)
    assert internal == {"src/config.rs", "src/db/mod.rs"}
    assert external == {"serde"}


def test_go_imports():
    paths = {"main.go", "internal/store/store.go", "internal/store/store_test.go"}
    text = 'package main\n\nimport (\n\t"fmt"\n\t"example.com/app/internal/store"\n\t"github.com/spf13/cobra"\n)\n'
    internal, external = _extract_imports(
        "main.go", text, paths, "example.com/app", github_reae._go_dirs(paths)
    )
    assert internal == {"internal/store/store.go"}
    assert external == {"github.com/spf13/cobra"}


def test_unknown_extension_has_no_imports():
    assert _extract_imports("README.md", "import x", {"README.md"}) == (set(), set())


# --- models ---------------------------------------------------------------

def test_python_models():
    text = (
        "from dataclasses import dataclass\n\n"
        "@dataclass\nclass Point:\n    x: int\n    y: int\n\n"
        "class User(BaseModel):\n    id: int\n    name: str = 'a'\n\n"
        "class Post(models.Model):\n    title = models.CharField(max_length=10)\n\n"
        "class Plain:\n    pass\n"
    )
    models = {m["name"]: m for m in _extract_models("m.py", text)}
    assert set(models) == {"Point", "User", "Post"}
    assert models["Point"]["kind"] == "dataclass"
    assert models["Point"]["fields"] == ["x", "y"]
    assert models["User"]["fields"] == ["id", "name"]
    assert models["Post"]["fields"] == ["title"]


def test_other_language_models():
    ts = _extract_models("a.ts", "export interface A { x: number }\nexport type B = {\n a: 1 }\ntype C = string;\n")
    assert [m["name"] for m in ts] == ["A", "B"]
    rs = _extract_models("a.rs", "pub struct S { a: u8 }\nenum E { A }\n")
    assert [m["name"] for m in rs] == ["S", "E"]
    go = _extract_models("a.go", "type T struct {\n}\ntype I interface {\n}\n")
    assert [m["name"] for m in go] == ["T"]
    sql = _extract_models("a.sql", "CREATE TABLE IF NOT EXISTS users (id int);")
    assert sql[0]["name"] == "users" and sql[0]["kind"] == "table"


# --- flows ---------------------------------------------------------------

def test_key_flows_bfs_and_cycles():
    graph = {"main.py": ["a.py", "b.py"], "a.py": ["c.py", "main.py"], "b.py": [], "c.py": []}
    flows = _key_flows(graph, ["main.py", "missing.py"])
    assert flows == {"main.py": [["a.py", "b.py"], ["c.py"]]}


# --- analysis & summary ------------------------------------------------------

class FakeRepo:
    files = {
        "pyproject.toml": '[project]\nname="demo"\ndependencies=["fastapi"]\n'
                          '[project.scripts]\ndemo = "demo.cli:main"\n',
        "main.py": "from demo import service\nimport requests\n",
        "demo/__init__.py": "",
        "demo/cli.py": "from . import service\n",
        "demo/service.py": "from .models import Item\n",
        "demo/models.py": "from dataclasses import dataclass\n\n@dataclass\nclass Item:\n    id: int\n",
        "tests/test_x.py": "import demo\n",
    }

    @classmethod
    def repo_data(cls):
        tree = [{"path": p, "type": "blob", "size": len(t)} for p, t in cls.files.items()]
        tree.append({"path": "demo", "type": "tree"})
        meta = {"full_name": "o/demo", "description": "Demo", "stargazers_count": 1,
                "fork": False, "open_issues_count": 0, "default_branch": "main"}
        return {"meta": meta, "tree": {"tree": tree, "truncated": False}}

    @classmethod
    def fetch(cls, path):
        return cls.files.get(path)


def test_analyze_end_to_end_with_fake_fetcher():
    analysis = _analyze(FakeRepo.repo_data(), FakeRepo.fetch)
    assert "FastAPI" in analysis["frameworks"]
    assert "demo/cli.py" in analysis["declared_entries"]
    assert analysis["graph"]["main.py"] == ["demo/__init__.py", "demo/service.py"]
    assert analysis["graph"]["demo/service.py"] == ["demo/models.py"]
    assert analysis["externals"] == {"requests": 1}
    assert [m["name"] for m in analysis["models"]] == ["Item"]
    assert "tests/test_x.py" not in analysis["graph"]


def test_analyze_survives_failing_fetcher():
    def boom(path):
        raise RuntimeError("network down")

    analysis = _analyze(FakeRepo.repo_data(), boom)
    assert analysis["analyzed"] == 0 and analysis["graph"] == {}


def test_summarize_with_mock_data():
    meta = {"full_name": "owner/repo", "description": "A test repo", "stargazers_count": 42,
            "fork": False, "open_issues_count": 3, "default_branch": "main"}
    tree = {"tree": [{"path": "pyproject.toml", "type": "blob"},
                     {"path": "main.py", "type": "blob"},
                     {"path": "src", "type": "tree"},
                     {"path": "src/app.py", "type": "blob"}],
            "truncated": False}
    summary = _summarize({"meta": meta, "tree": tree})
    assert "owner/repo" in summary
    assert "Python" in summary
    assert "main.py" in summary
    assert "- 📁 src/" in summary
    assert "Dependency Graph" not in summary  # no analysis supplied


def test_summarize_full_analysis_sections():
    data = FakeRepo.repo_data()
    summary = _summarize(data, _analyze(data, FakeRepo.fetch))
    for heading in ("## Entry Points", "## Components", "## Dependency Graph",
                    "## Data Models", "## Key Flows"):
        assert heading in summary
    assert "`Item` (dataclass) in `demo/models.py`" in summary
    assert "`main.py`" in summary


# --- CLI -----------------------------------------------------------------

def test_main_runs_with_patched_network(monkeypatch, capsys):
    monkeypatch.setattr(github_reae, "_get_repo_tree", lambda _r: FakeRepo.repo_data())
    monkeypatch.setattr(github_reae, "_make_raw_fetcher", lambda _r, _b: FakeRepo.fetch)
    assert github_reae.main(["https://github.com/o/demo"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("# o/demo")
    assert "## Key Flows" in out


def test_main_rejects_invalid_repo(capsys):
    assert github_reae.main(["not-a-repo"]) == 1
    assert "invalid repo" in capsys.readouterr().err


def test_main_requires_argument():
    with pytest.raises(SystemExit) as exc:
        github_reae.main([])
    assert exc.value.code == 2


def test_fetch_json_http_error(monkeypatch):
    from urllib.error import HTTPError

    def fake_urlopen(req, timeout=None):
        raise HTTPError(req.full_url, 404, "nf", {}, None)

    monkeypatch.setattr(github_reae, "urlopen", fake_urlopen)
    with pytest.raises(SystemExit) as exc:
        github_reae._fetch_json("https://api.github.com/repos/a/b")
    assert "HTTP 404" in str(exc.value)


def test_get_repo_tree_uses_default_branch(monkeypatch):
    calls = []

    def fake_fetch(url):
        calls.append(url)
        if url.endswith("/a/b"):
            return {"default_branch": "dev"}
        return {"tree": [], "truncated": False}

    monkeypatch.setattr(github_reae, "_fetch_json", fake_fetch)
    result = github_reae._get_repo_tree("a/b")
    assert result["meta"]["default_branch"] == "dev"
    assert calls[1].endswith("/git/trees/dev?recursive=1")
    assert json.dumps(result)  # serializable
