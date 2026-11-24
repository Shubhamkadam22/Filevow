"""Start the API, the agent and the built dashboard against the demo environment.

    .venv\\Scripts\\python scripts\\run_dev.py
Then open http://127.0.0.1:8443 (run seed_dev.py first).
"""

from __future__ import annotations

import sys

from dev_env import apply_environment

apply_environment()

from filevow.cli.main import app  # noqa: E402 - settings must see the environment first

if __name__ == "__main__":
    sys.argv = ["filevow", "serve", *sys.argv[1:]]
    app()
