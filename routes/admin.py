from fastapi import APIRouter, HTTPException, Depends
from utils.auth import hash_password, verify_password, create_access_token, decode_access_token
from utils.database import db
from models import UserRegister
from bson import ObjectId
from fastapi.security import OAuth2PasswordBearer

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@router.post("/register")
def register_admin(admin: UserRegister):
    """
    Endpoint to register a new admin.
    Ensures the username is unique and hashes the password before saving.
    """
    if db.users.find_one({"username": admin.username}):
        raise HTTPException(status_code=400, detail="Username already exists")
    
    hashed_password = hash_password(admin.password)
    db.users.insert_one({"username": admin.username, "password": hashed_password, "role": "admin"})
    return {"message": "Admin registered successfully", "role": "admin"}

@router.post("/login")
def login_admin(admin: UserRegister):
    """
    Endpoint for admin login.
    Validates credentials and generates a JWT token for valid users with 'admin' role.
    """
    db_admin = db.users.find_one({"username": admin.username})
    if not db_admin or not verify_password(admin.password, db_admin["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if db_admin.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Access denied for this role")
    
    token = create_access_token({"username": admin.username, "role": "admin"})
    return {"access_token": token, "token_type": "bearer"}

@router.get("/assignments")
def get_assignments(token: str = Depends(oauth2_scheme)):
    payload = decode_access_token(token)
    if not payload or payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Invalid or unauthorized token")
    
    admin_username = payload.get("username")
    assignments = db.assignments.find({"admin": admin_username})

    # Convert _id (ObjectId) to string in each assignment
    assignments_list = [
        {**assignment, "_id": str(assignment["_id"])} for assignment in assignments
    ]
    
    return {"assignments": assignments_list}

@router.post("/assignments/{assignment_id}/accept")
def accept_assignment(assignment_id: str, token: str = Depends(oauth2_scheme)):
    """
    Endpoint for admins to accept an assignment.
    Updates the assignment status to 'accepted'.
    """
    payload = decode_access_token(token)
    if not payload or payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Invalid or unauthorized token")
    
    result = db.assignments.update_one({"_id": ObjectId(assignment_id)}, {"$set": {"status": "accepted"}})
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Assignment not found")
    return {"message": "Assignment accepted"}

@router.post("/assignments/{assignment_id}/reject")
def reject_assignment(assignment_id: str, token: str = Depends(oauth2_scheme)):
    """
    Endpoint for admins to reject an assignment.
    Updates the assignment status to 'rejected'.
    """
    payload = decode_access_token(token)
    if not payload or payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Invalid or unauthorized token")
    
    result = db.assignments.update_one({"_id": ObjectId(assignment_id)}, {"$set": {"status": "rejected"}})
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Assignment not found")
    return {"message": "Assignment rejected"}
