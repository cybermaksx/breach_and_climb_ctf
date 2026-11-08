import os
import sqlite3

import click
from flask import current_app, g


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"], timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    with current_app.open_resource("schema.sql") as f:
        db.executescript(f.read().decode("utf8"))
    db.execute("PRAGMA journal_mode = WAL")
    os.chmod(current_app.config["DATABASE"], 0o600)


@click.command("init-db")
@click.option("--no-seed", is_flag=True, help="Create empty tables without demo data.")
def init_db_command(no_seed):
    """Drop all tables, recreate the schema and load E Corp seed data."""
    init_db()
    click.echo("Database schema created.")
    if not no_seed:
        from .seed import seed

        accounts = seed(get_db(), current_app.config["DOCUMENTS_DIR"])
        click.echo("Seed data loaded. Accounts:")
        for username, password, role in accounts:
            click.echo(f"  {username:<12} {role:<10} {password}")


def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
