# STACK.md — Tech Stack & Dependencies

## Stack Choices

| Layer | Choice | Why |
|-------|--------|-----|
| Language | **Python 3.11+** | Most mature Selenium bindings, largest security ecosystem, lowest barrier for open-source contributors |
| Browser Automation | **Selenium 4 + Chrome DevTools Protocol (CDP)** | CDP gives us direct access to Network, Console, Storage, and Security domains — no proxy needed for most inspections |
| GUI Server | **FastAPI + WebSockets** | Async-native, fast, WebSocket support for live scan progress streaming |
| GUI Frontend | **Vanilla HTML/CSS/JS (served by FastAPI)** | No build step, no Node.js required. Served on `localhost:3001`. Hacker-themed control center aesthetic |
| Real-time Updates | **WebSockets** | Stream scan progress, findings, and logs to the dashboard in real time |
| Report Generator | **Jinja2 → single-file HTML** | Exportable self-contained report (same data as dashboard, but portable) |
| Configuration | **`.env` + `vibe-iterator.config.yaml`** | `.env` for secrets (test credentials, API keys), YAML for scan scope and stage settings |
| CLI | **Click** | Dual-mode: `vibe-iterator` launches the GUI, `vibe-iterator scan --headless` runs CLI-only |
| Package Distribution | **pip / PyPI** | `pip install vibe-iterator` for end users |

## Dependencies

```
selenium>=4.15.0
python-dotenv>=1.0.0
click>=8.1.0
pyyaml>=6.0
jinja2>=3.1.0
fastapi>=0.104.0
uvicorn>=0.24.0
websockets>=12.0
pytest>=7.4.0
```

## Dependency Rules

- No heavy frameworks on the frontend — vanilla HTML/CSS/JS only
- No Node.js, no npm, no webpack, no React — `pip install vibe-iterator` must be the ONLY install step
- Keep the dependency list minimal — a vibe coder should install and run this in under 2 minutes
- Pin minimum versions, not exact versions — allow flexibility for users' environments
- All dependencies must be pip-installable (no system-level packages beyond Chrome/ChromeDriver)

---

## `pyproject.toml` Spec

```toml
[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "vibe-iterator"
version = "0.1.0"
description = "Runtime security testing for vibe-coded web apps"
readme = "README.md"
license = { text = "MIT" }
requires-python = ">=3.11"
keywords = ["security", "testing", "supabase", "selenium", "pentesting"]
classifiers = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: Developers",
    "Topic :: Security",
    "Programming Language :: Python :: 3.11",
]
dependencies = [
    "selenium>=4.15.0",
    "python-dotenv>=1.0.0",
    "click>=8.1.0",
    "pyyaml>=6.0",
    "jinja2>=3.1.0",
    "fastapi>=0.104.0",
    "uvicorn[standard]>=0.24.0",
    "websockets>=12.0",
]

[project.optional-dependencies]
dev = ["pytest>=7.4.0", "pytest-asyncio>=0.23.0", "pytest-cov>=4.1.0", "httpx>=0.26.0"]

[project.scripts]
vibe-iterator = "vibe_iterator.cli:cli"

[project.urls]
Homepage = "https://github.com/francisN21/vibe-iterator"
Issues = "https://github.com/francisN21/vibe-iterator/issues"

[tool.setuptools.packages.find]
where = ["."]
include = ["vibe_iterator*"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
```

**Notes:**
- `uvicorn[standard]` includes `uvloop` and `httptools` for better async performance
- `httpx` is a dev dependency used for testing FastAPI routes without a live server
- `pytest-asyncio` is required because engine tests involve `async` functions
- ChromeDriver is managed automatically by Selenium Manager (Selenium 4.6+) — no separate chromedriver install needed
