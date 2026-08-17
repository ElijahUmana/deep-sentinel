"""Every module must import from a clean install with no credentials set.

This is a deliberately boring test, and it is here because the failure it
guards against already happened: `anthropic` was a hard import in
src/llm/truefoundry_gateway.py but absent from requirements.txt, so a fresh
clone following the README could not import the analyzer at all. Nothing
caught it, because importing the package was never exercised anywhere.

It also pins the weaker invariant that matters for a CLI security tool:
importing a module must not require credentials, reach the network, or have
side effects. Configuration errors belong at call time, not import time.
"""

import importlib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"

# src/overclaw_agent.py drives the Overmind optimization harness and needs the
# `overclaw` package, which is deliberately not a core dependency — installing
# it upgrades opentelemetry-semantic-conventions past the pin overmind-sdk
# requires. See requirements-optimization.txt.
OPTIONAL_MODULES = {"src.overclaw_agent"}


def _module_names() -> list[str]:
    names = []
    for path in sorted(SRC.rglob("*.py")):
        rel = path.relative_to(REPO_ROOT)
        parts = rel.parent.parts if rel.name == "__init__.py" else rel.with_suffix("").parts
        names.append(".".join(parts))
    return names


MODULES = [m for m in _module_names() if m not in OPTIONAL_MODULES]


def test_module_discovery_found_something():
    """Guard against the parametrized test silently covering nothing."""
    assert len(MODULES) > 10, f"expected the full src tree, found {MODULES}"


@pytest.mark.parametrize("module", MODULES)
def test_module_imports_without_credentials(module, monkeypatch):
    """Import each module with every known credential removed from the env."""
    for var in (
        "AUTH0_DOMAIN",
        "AUTH0_CLIENT_ID",
        "AUTH0_CLIENT_SECRET",
        "AUTH0_DEVICE_CLIENT_ID",
        "GITHUB_TOKEN",
        "SLACK_BOT_TOKEN",
        "MACROSCOPE_API_KEY",
        "MACROSCOPE_WORKSPACE_ID",
        "GHOST_CONNECTION_STRING",
        "GHOST_DB_ID",
        "TRUEFOUNDRY_API_KEY",
        "OVERMIND_API_KEY",
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
    ):
        monkeypatch.delenv(var, raising=False)

    importlib.import_module(module)


def test_entrypoint_imports():
    """scan.py is what the README tells people to run."""
    importlib.import_module("scan")


def test_declared_requirements_cover_hard_imports():
    """Every third-party module imported unguarded must be installable.

    Catches the exact regression above: a hard import that no requirements
    file declares.
    """
    missing = []
    for module in MODULES:
        try:
            importlib.import_module(module)
        except ModuleNotFoundError as exc:
            missing.append((module, exc.name))
    assert not missing, f"undeclared dependencies: {missing}"
