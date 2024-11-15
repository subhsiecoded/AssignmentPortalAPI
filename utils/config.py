from dotenv import load_dotenv
import os

# Load environment variables from .env
load_dotenv()

# Access environment variables
SECRET_KEY = os.getenv("SECRET_KEY")
DATABASE_URI = os.getenv("DATABASE_URI")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
