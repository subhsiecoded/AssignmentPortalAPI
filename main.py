from fastapi import FastAPI
from routes import user, admin

app = FastAPI()

# Include routes
app.include_router(user.router, prefix="/user", tags=["User"])
app.include_router(admin.router, prefix="/admin", tags=["Admin"])

@app.get("/")
def read_root():
    return {"message": "Welcome to the Assignment Submission Portal"}
