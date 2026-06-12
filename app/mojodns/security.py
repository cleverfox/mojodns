"""Password hashing.

New hashes are bcrypt. Hashes migrated from mojodns-perl use the legacy
Rails restful_authentication scheme sha1("--<salt>--<password>--") and are
stored as "legacysha1$<salt>$<hexdigest>"; they verify transparently and are
upgraded to bcrypt on the next successful login.
"""

import hashlib
import hmac
import secrets

import bcrypt


def hash_password(password: str) -> str:
    return "bcrypt$" + bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, stored: str) -> bool:
    scheme, _, rest = stored.partition("$")
    if scheme == "bcrypt":
        try:
            return bcrypt.checkpw(password.encode(), rest.encode())
        except ValueError:
            return False
    if scheme == "legacysha1":
        salt, _, digest = rest.partition("$")
        candidate = hashlib.sha1(f"--{salt}--{password}--".encode()).hexdigest()
        return hmac.compare_digest(candidate, digest)
    return False


def needs_rehash(stored: str) -> bool:
    return not stored.startswith("bcrypt$")


def make_token() -> str:
    return secrets.token_hex(24)
