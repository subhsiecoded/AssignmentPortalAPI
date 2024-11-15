from pydantic import BaseModel
from typing import Optional

class UserRegister(BaseModel):
    """
    Model for user/admin registration requests.
    """
    username: str
    password: str

class Assignment(BaseModel):
    """
    Model for assignment submission requests.
    """
    userId: str
    task: str
    admin: str
    timestamp: Optional[str] = None
