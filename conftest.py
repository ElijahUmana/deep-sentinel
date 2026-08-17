"""Put the repository root on sys.path for the test session.

The project is a script-style layout rather than an installed package, so
`import src.…` and `import scan` only resolve when the repo root is importable.
pytest inserts the *test* directory, not the rootdir, which is why the suite can
pass locally from a shell that happens to have the root on the path and then
fail in CI with ModuleNotFoundError.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
