from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from utils.config import SECRET_KEY, ACCESS_TOKEN_EXPIRE_MINUTES

ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str):
    """
    Hashes a plaintext password for secure storage.
    """
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str):
    """
    Verifies a plaintext password against a hashed password.
    """
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    """
    Generates a JWT token with an expiration time.
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_access_token(token: str):
    """
    Decodes a JWT token to extract payload data.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None
