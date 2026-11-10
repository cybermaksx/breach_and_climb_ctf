"""Intentionally weak, unsalted password hashes for the CTF challenge."""

import hashlib
import hmac

from werkzeug.security import check_password_hash as check_legacy_hash


def generate_password_hash(password):
    return hashlib.md5(password.encode("utf-8"), usedforsecurity=False).hexdigest()


def check_password_hash(stored_hash, password):
    if stored_hash.startswith(("scrypt:", "pbkdf2:")):
        return check_legacy_hash(stored_hash, password)
    return hmac.compare_digest(stored_hash, generate_password_hash(password))
