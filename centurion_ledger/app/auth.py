from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt, JWTError
from typing import Optional
import os
import secrets

# ============================================
# PASSWORD HASHING CONFIGURATION
# ============================================

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12  # Cost factor: higher = more secure but slower
)

# ============================================
# JWT CONFIGURATION
# ============================================

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable is required")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

# ============================================
# PASSWORD OPERATIONS
# ============================================

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain password against a hash.
    Returns False on any error to prevent timing attacks.
    """
    if not plain_password or not hashed_password:
        return False
    
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        # Constant-time failure - don't leak why it failed
        return False


def get_password_hash(password: str) -> str:
    """
    Hash a password with bcrypt.
    Raises ValueError if password doesn't meet requirements.
    """
    if not password:
        raise ValueError("Password cannot be empty")
    
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters")
    
    # Check complexity (defense in depth - schema validates too)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    
    if not (has_upper and has_lower and has_digit):
        raise ValueError("Password must contain uppercase, lowercase, and digit")
    
    return pwd_context.hash(password)


# ============================================
# PIN OPERATIONS
# ============================================

def verify_pin(plain_pin: str, hashed_pin: str) -> bool:
    """
    Verify a 6-digit PIN against a hash.
    Uses same bcrypt infrastructure as passwords.
    """
    if not plain_pin or not hashed_pin:
        return False
    
    # Validate format before verification
    if len(plain_pin) != 6 or not plain_pin.isdigit():
        return False
    
    try:
        return pwd_context.verify(plain_pin, hashed_pin)
    except Exception:
        return False


def get_pin_hash(pin: str) -> str:
    """
    Hash a 6-digit PIN with bcrypt.
    """
    if not pin:
        raise ValueError("PIN cannot be empty")
    
    if len(pin) != 6:
        raise ValueError("PIN must be exactly 6 digits")
    
    if not pin.isdigit():
        raise ValueError("PIN must contain only digits")
    
    # Prevent common weak PINs
    weak_pins = {'000000', '111111', '123456', '654321', '121212', '999999'}
    if pin in weak_pins:
        raise ValueError("This PIN is too common. Choose a more secure PIN.")
    
    return pwd_context.hash(pin)


# ============================================
# JWT TOKEN OPERATIONS
# ============================================

def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    """
    Create a JWT access token with secure claims.
    
    Required claims in data:
        - sub: user ID (string)
    
    Auto-injects:
        - exp: expiration time
        - iat: issued at
        - jti: unique token ID for revocation support
        - type: "access"
    """
    if not isinstance(data, dict):
        raise ValueError("Token data must be a dictionary")
    
    if "sub" not in data or not data["sub"]:
        raise ValueError("Token payload must contain 'sub' (user id)")
    
    to_encode = data.copy()
    
    # Calculate expiration
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    # Generate unique token ID for potential revocation
    jti = secrets.token_urlsafe(32)
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "jti": jti,
        "type": "access",
        "sub": str(data["sub"])  # Ensure string
    })
    
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    """
    Decode and validate a JWT token.
    Returns payload dict on success.
    Raises ValueError on any failure.
    """
    if not token or not isinstance(token, str):
        raise ValueError("Token is required")
    
    try:
        payload = jwt.decode(
            token, 
            SECRET_KEY, 
            algorithms=[ALGORITHM],
            options={
                "require": ["exp", "iat", "sub"],
                "verify_exp": True,
                "verify_iat": True
            }
        )
        
        # Validate token type
        if payload.get("type") != "access":
            raise ValueError("Invalid token type")
        
        # Ensure sub exists and is string
        if not payload.get("sub"):
            raise ValueError("Token missing subject")
        
        payload["sub"] = str(payload["sub"])
        
        return payload
        
    except JWTError as e:
        raise ValueError(f"Invalid or expired token: {str(e)}")
    except Exception as e:
        raise ValueError(f"Token validation failed: {str(e)}")


def get_token_expiry(token: str) -> Optional[datetime]:
    """
    Extract expiration time from token without full validation.
    Returns None if unparseable.
    """
    try:
        payload = jwt.decode(
            token, 
            SECRET_KEY, 
            algorithms=[ALGORITHM],
            options={"verify_signature": False, "verify_exp": False}
        )
        exp = payload.get("exp")
        if exp:
            return datetime.utcfromtimestamp(exp)
    except Exception:
        pass
    return None


# ============================================
# SECURITY UTILITIES
# ============================================

def generate_secure_token(length: int = 32) -> str:
    """
    Generate a cryptographically secure random token.
    Used for idempotency keys, reset tokens, etc.
    """
    return secrets.token_urlsafe(length)


def constant_time_compare(val1: str, val2: str) -> bool:
    """
    Compare two strings in constant time to prevent timing attacks.
    """
    if not val1 or not val2:
        return False
    
    return secrets.compare_digest(val1.encode(), val2.encode())