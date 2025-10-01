import base64
import hashlib
import hmac
import os

def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    if salt is None:
        salt = os.urandom(16).hex()
    h = hashlib.sha256()
    h.update(bytes.fromhex(salt))
    h.update(password.encode('utf-8'))
    return salt, h.hexdigest()

def verify_password(stored: str, provided_password: str) -> bool:

    try:
        salt, stored_hash = stored.split('$', 1)
    except ValueError:
        return False
    _, computed_hash = hash_password(provided_password, salt=salt)
    return hmac.compare_digest(stored_hash, computed_hash)