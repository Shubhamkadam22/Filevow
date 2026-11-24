"""Alembic environment. Uses the connection handed over by ``filevow.db.migrate``
or, for the alembic command line, the configured database URL."""

from __future__ import annotations

from alembic import context
from sqlalchemy import Connection, engine_from_config, pool

import filevow.db.models  # noqa: F401 - registers every table on the metadata
from filevow.config import get_settings
from filevow.db.base import Base

config = context.config
target_metadata = Base.metadata


def _configure(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=connection.dialect.name == "sqlite",  # SQLite needs table rebuilds for ALTER
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_offline() -> None:
    context.configure(
        url=get_settings().resolved_database_url, target_metadata=target_metadata, literal_binds=True
    )
    with context.begin_transaction():
        context.run_migrations()


def run_online() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:
        _configure(connection)
        return
    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = get_settings().resolved_database_url
    engine = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with engine.connect() as fresh:
        _configure(fresh)


if context.is_offline_mode():
    run_offline()
else:
    run_online()
