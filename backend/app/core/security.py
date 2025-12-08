"""Password hashing and session token utilities."""
import secrets
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

# Configure argon2 with secure defaults
ph = PasswordHasher(
    time_cost=2,        # Number of iterations
    memory_cost=65536,  # 64 MB
    parallelism=1,      # Single thread
    hash_len=32,        # Output hash length
    salt_len=16         # Salt length
)


def hash_password(password: str) -> str:
    """Hash a password using argon2id."""
    return ph.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against its hash. Returns False on mismatch or invalid hash."""
    try:
        ph.verify(hashed, password)
        return True
    except (VerifyMismatchError, InvalidHashError):
        return False


def generate_session_token() -> str:
    """Generate a cryptographically secure session token."""
    return secrets.token_urlsafe(48)
