"""Create a demo environment: accounts, and a workspace that protects a sample website.

.venv\\Scripts\\python scripts\\seed_dev.py          (add --reset to start over)
"""

from __future__ import annotations

import shutil
import sys

from dev_env import DEMO_SITE, DEV_HOME, DEV_KEY_PASSPHRASE, DEV_USERS, apply_environment

apply_environment()

from filevow.config import Settings  # noqa: E402 - settings must see the environment first
from filevow.db.enums import Role, RunType, Severity  # noqa: E402
from filevow.db.models import MonitoredPath, User  # noqa: E402
from filevow.secrets import create_secret_store  # noqa: E402
from filevow.services import trust, users  # noqa: E402
from filevow.services.baseline import BaselineBuilder, add_monitored_path  # noqa: E402
from filevow.services.context import AppContext, initialize  # noqa: E402
from filevow.services.monitor import MonitoringService  # noqa: E402

SITE_FILES = {
    "index.html": '<!doctype html>\n<html lang="en">\n<head>\n  <meta charset="utf-8">\n  <title>Welcome</title>\n</head>\n<body>\n  <h1>Hello</h1>\n  <p>Our latest offers.</p>\n</body>\n</html>\n',
    "about.html": "<!doctype html>\n<h1>About us</h1>\n<p>Family business since 1998.</p>\n",
    "contact.html": "<!doctype html>\n<h1>Contact</h1>\n<p>hello@example.com</p>\n",
    "css/site.css": "body { font-family: system-ui; margin: 2rem; }\nh1 { color: #0F2A44; }\n",
    "js/app.js": "import { loadMenu } from './menu.js';\n\nexport function init() {\n  loadMenu();\n  trackPage();\n}\n",
    "js/menu.js": "export function loadMenu() {\n  document.body.dataset.menu = 'ready';\n}\n",
    "config.php": "<?php\n$db_host = 'localhost';\n$db_user = 'app';\n$db_name = 'shop';\ndefine('DEBUG', false);\n",
    "web.config": '<configuration>\n  <system.webServer>\n    <httpErrors errorMode="Custom" />\n  </system.webServer>\n</configuration>\n',
    "server.log": "excluded from monitoring\n",
}


def main() -> None:
    if "--reset" in sys.argv and DEV_HOME.exists():
        shutil.rmtree(DEV_HOME)
    for relative, content in SITE_FILES.items():
        target = DEMO_SITE / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            target.write_text(content, encoding="utf-8")

    settings = Settings()
    ctx = AppContext(settings, create_secret_store(settings))
    initialize(ctx)

    with ctx.session() as session:
        accounts: dict[str, User] = {}
        for username, (password, role) in DEV_USERS.items():
            account = session.query(User).filter_by(username=username).first()
            accounts[username] = account or users.create_user(session, username, password, Role(role))
        owner = accounts["admin"]

        if trust.active_signing_key(session, owner.id) is None:
            trust.create_user_signing_key(session, settings, ctx.secrets, owner, DEV_KEY_PASSPHRASE)

        monitored = session.query(MonitoredPath).filter_by(owner_id=owner.id).first()
        if monitored is None:
            monitored = add_monitored_path(
                session,
                settings,
                DEMO_SITE,
                exclude=["*.log"],
                severity=Severity.HIGH,
                actor_user_id=owner.id,
                owner_id=owner.id,
            )
        private_key, signing_key = trust.unlock_user_signing_key(
            session, settings, ctx.secrets, owner.id, DEV_KEY_PASSPHRASE
        )
        summary = BaselineBuilder(session, settings, ctx.vault(), private_key, signing_key).protect(monitored)

    MonitoringService(ctx).verify(RunType.STARTUP)
    print(f"Demo environment ready in {DEV_HOME}")
    print(f"  {summary.created} files signed under {DEMO_SITE} (workspace of 'admin')")
    print("  Accounts and passphrases: see DEV_USERS in scripts/dev_env.py")


if __name__ == "__main__":
    main()
