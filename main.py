from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from fastapi.openapi.utils import get_openapi

# --- Database ---
DATABASE_URL = "postgresql://postgres:postgres@db-1/college_management"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class Student(Base):
    __tablename__ = "students"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    email = Column(String, unique=True)

Base.metadata.create_all(bind=engine)

# --- Authentication ---
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
admin_username = "admin"
admin_password = pwd_context.hash("password123")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/")

def authenticate_user(username: str, password: str) -> bool:
    return username == admin_username and pwd_context.verify(password, admin_password)

def create_access_token(data: dict, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)) -> str:
    data.update({"exp": datetime.utcnow() + expires_delta})
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)) -> str:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("sub") != admin_username:
            raise HTTPException(status_code=401, detail="Invalid user")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    return admin_username

# --- App Init ---
app = FastAPI()

@app.post("/")
def login(form: OAuth2PasswordRequestForm = Depends()):
    if not authenticate_user(form.username, form.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token(data={"sub": form.username})
    return {"access_token": token, "token_type": "bearer"}

# --- DB Dependency ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Student Endpoints ---
@app.post("/students")
def create_student(name: str, email: str, db: Session = Depends(get_db), _: str = Depends(get_current_user)):
    student = Student(name=name, email=email)
    db.add(student)
    db.commit()
    return {"message": "Student added"}

@app.get("/students")
def read_students(db: Session = Depends(get_db), _: str = Depends(get_current_user)):
    return db.query(Student).all()

@app.delete("/students/{student_id}")
def delete_student(student_id: int, db: Session = Depends(get_db), _: str = Depends(get_current_user)):
    student = db.query(Student).filter(Student.id == student_id).first()
    if not student:
        raise HTTPException(status_code=404, detail="Student not found")
    db.delete(student)
    db.commit()
    return {"message": "Student deleted"}

# --- Swagger Authorize Button Setup ---
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(
        title="College Management API",
        version="1.0",
        description="Login at `/` to get JWT token. Use the token to access protected student endpoints.",
        routes=app.routes,
    )
    schema["components"]["securitySchemes"] = {
        "BearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
    }
    for path in schema["paths"].values():
        for method in path.values():
            method["security"] = [{"BearerAuth": []}]
    app.openapi_schema = schema
    return schema

app.openapi = custom_openapi
