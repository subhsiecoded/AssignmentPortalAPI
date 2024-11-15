from fastapi import APIRouter, HTTPException, Depends
from utils.auth import hash_password, verify_password, create_access_token, decode_access_token
from utils.database import db
from models import UserRegister, Assignment
from bson import ObjectId
from datetime import datetime
from fastapi.security import OAuth2PasswordBearer

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@router.post("/register")
def register_user(user: UserRegister):
    """
    Endpoint to register a new user.
    Validates if the username already exists and hashes the password before saving.
    """
    if db.users.find_one({"username": user.username}):
        raise HTTPException(status_code=400, detail="Username already exists")
    
    hashed_password = hash_password(user.password)
    db.users.insert_one({"username": user.username, "password": hashed_password, "role": "user"})
    return {"message": "User registered successfully", "role": "user"}

@router.post("/login")
def login_user(user: UserRegister):
    """
    Endpoint for user login.
    Verifies credentials and generates a JWT token for valid users with 'user' role.
    """
    db_user = db.users.find_one({"username": user.username})
    if not db_user or not verify_password(user.password, db_user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if db_user.get("role") != "user":
        raise HTTPException(status_code=403, detail="Access denied for this role")
    
    token = create_access_token({"username": user.username, "role": "user"})
    return {"access_token": token, "token_type": "bearer"}

@router.post("/upload")
def upload_assignment(assignment: Assignment, token: str = Depends(oauth2_scheme)):
    payload = decode_access_token(token)
    if not payload or payload.get("role") != "user":
        raise HTTPException(status_code=403, detail="Invalid or unauthorized token")

    assignment.timestamp = datetime.utcnow().isoformat()
    result = db.assignments.insert_one(assignment.dict())
    
    # Return the assignment with the generated ObjectId as string
    assignment_with_id = {**assignment.dict(), "_id": str(result.inserted_id)}
    return {"message": "Assignment uploaded successfully", "assignment": assignment_with_id}


@router.get("/admins")
def get_all_admins():
    """
    Fetches all registered admins for assignment tagging.
    Returns a list of admin usernames.
    """
    admins = db.users.find({"role": "admin"}, {"_id": 0, "username": 1})
    return {"admins": list(admins)}
