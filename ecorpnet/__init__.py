"""ECorpNet — E Corp internal employee portal."""
import os
import secrets

from flask import Flask, render_template


def _load_secret_key(instance_path):
    path = os.path.join(instance_path, "secret_key")
    if not os.path.exists(path):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_hex(32))
    os.chmod(path, 0o600)
    with open(path) as f:
        return f.read().strip()


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    # DB, secret key and documents live here: keep them unreadable for other local users.
    os.makedirs(app.instance_path, mode=0o700, exist_ok=True)
    try:
        os.chmod(app.instance_path, 0o700)
    except PermissionError:
        pass

    app.config.from_mapping(
        DATABASE=os.path.join(app.instance_path, "ecorpnet.db"),
        DOCUMENTS_DIR=os.path.join(app.instance_path, "documents"),
        MAX_CONTENT_LENGTH=10 * 1024 * 1024,
        SECRET_KEY=os.environ.get("ECORPNET_SECRET_KEY") or _load_secret_key(app.instance_path),
    )
    if test_config:
        app.config.update(test_config)
    os.makedirs(app.config["DOCUMENTS_DIR"], exist_ok=True)

    from . import admin, api, auth, comms, db, directory, documents, main, reports, security, tickets, utils, wallet

    db.init_app(app)
    utils.init_app(app)

    for module in (auth, main, directory, tickets, documents, wallet, reports, admin, comms, api):
        app.register_blueprint(module.bp)

    # Registered after the blueprints so g.user is already loaded when CSRF validation fails.
    security.init_app(app)

    for code in (400, 403, 404, 413):
        app.register_error_handler(
            code, lambda e, code=code: (render_template("error.html", error=e, code=code), code)
        )

    return app
