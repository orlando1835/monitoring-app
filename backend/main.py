import asyncio
import datetime
import time
from typing import List, Dict, Any, Optional
import enum
import json

import httpx
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, desc, func, Enum, Boolean, Text
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel, field_validator

# --- CONFIGURACIÓN DE SEGURIDAD Y JWT ---
SECRET_KEY = "un-secreto-muy-dificil-de-adivinar" 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

MONITORING_INTERVAL_SECONDS = 60

# --- CONFIGURACIÓN DE BASE DE DATOS (MySQL) ---
DB_USER = "root"
DB_PASSWORD = "Certi123"
DB_HOST = "127.0.0.1"
DB_PORT = "3306"
DB_NAME = "monitoring_db"
DATABASE_URL = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- MODELOS DE DATOS Y BASE DE DATOS ---
class Role(str, enum.Enum):
    admin = "admin"
    consulta = "consulta"

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, index=True)
    hashed_password = Column(String(255))
    role = Column(Enum(Role))

class Service(Base):
    __tablename__ = "services"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, index=True, nullable=False)
    url = Column(String(1024), nullable=False)
    method = Column(String(10), nullable=False, default="GET")
    headers = Column(Text, nullable=True)
    payload = Column(Text, nullable=True)
    auth_type = Column(String(50), nullable=True)
    auth_username = Column(String(255), nullable=True)
    auth_password = Column(String(255), nullable=True)
    ssl_verify = Column(Boolean, default=True)

class Log(Base):
    __tablename__ = "logs"
    id = Column(Integer, primary_key=True, index=True)
    service_name = Column(String(255), index=True)
    url = Column(String(512))
    timestamp = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    response_time_ms = Column(Float)
    status_code = Column(Integer, nullable=True)
    status = Column(String(50))
    error_message = Column(String(500), nullable=True)

class UserCreate(BaseModel):
    username: str
    password: str
    role: Role

class UserOut(BaseModel):
    username: str
    role: Role
    class Config:
        from_attributes = True

class ServiceBase(BaseModel):
    name: str
    url: str
    method: str = "GET"
    headers: Optional[str] = None
    payload: Optional[str] = None
    auth_type: Optional[str] = None
    auth_username: Optional[str] = None
    auth_password: Optional[str] = None
    ssl_verify: bool = True

    @field_validator('headers', 'payload', mode='before')
    def validate_json_string(cls, v):
        if v is None or v == "" or v == "{}":
            return None
        try:
            json.loads(v)
        except json.JSONDecodeError:
            raise ValueError('must be a valid JSON string')
        return v

class ServiceCreate(ServiceBase): pass
class ServiceUpdate(ServiceBase): pass
class ServiceOut(ServiceBase):
    id: int
    class Config:
        from_attributes = True

Base.metadata.create_all(bind=engine)

# --- APLICACIÓN FASTAPI ---
app = FastAPI(title="API de Monitoreo con Gestión de Servicios", version="2.2.3")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# --- FUNCIONES DE UTILIDAD ---
def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def verify_password(plain_password, hashed_password): return pwd_context.verify(plain_password, hashed_password)
def get_password_hash(password): return pwd_context.hash(password)
def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + (expires_delta or datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# --- DEPENDENCIAS DE SEGURIDAD ---
async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None: raise credentials_exception
    except JWTError: raise credentials_exception
    user = db.query(User).filter(User.username == username).first()
    if user is None: raise credentials_exception
    return user

async def get_current_admin_user(current_user: User = Depends(get_current_user)):
    if current_user.role != Role.admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")
    return current_user

# --- ENDPOINTS DE AUTENTICACIÓN Y USUARIOS ---
@app.post("/token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password", headers={"WWW-Authenticate": "Bearer"})
    access_token = create_access_token(data={"sub": user.username, "role": user.role.value}, expires_delta=datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/api/users", response_model=UserOut)
def create_user(user: UserCreate, db: Session = Depends(get_db), admin_user: User = Depends(get_current_admin_user)):
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    db_user = User(username=user.username, hashed_password=get_password_hash(user.password), role=user.role)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.get("/api/users/me", response_model=UserOut)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

# --- ENDPOINTS DE GESTIÓN DE SERVICIOS (CRUD) ---
@app.post("/api/services", response_model=ServiceOut)
def create_service(service: ServiceCreate, db: Session = Depends(get_db), admin_user: User = Depends(get_current_admin_user)):
    db_service = Service(**service.model_dump())
    db.add(db_service)
    db.commit()
    db.refresh(db_service)
    return db_service

@app.get("/api/services", response_model=List[ServiceOut])
def read_services(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Service).order_by(Service.name).all()

@app.put("/api/services/{service_id}", response_model=ServiceOut)
def update_service(service_id: int, service: ServiceUpdate, db: Session = Depends(get_db), admin_user: User = Depends(get_current_admin_user)):
    db_service = db.query(Service).filter(Service.id == service_id).first()
    if db_service is None: raise HTTPException(status_code=404, detail="Service not found")
    update_data = service.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(db_service, key, value)
    db.commit()
    db.refresh(db_service)
    return db_service

@app.delete("/api/services/{service_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_service(service_id: int, db: Session = Depends(get_db), admin_user: User = Depends(get_current_admin_user)):
    db_service = db.query(Service).filter(Service.id == service_id).first()
    if db_service is None: raise HTTPException(status_code=404, detail="Service not found")
    db.delete(db_service)
    db.commit()
    return

# --- TAREAS DE FONDO: MONITOREO ---
async def monitor_service(service: Service):
    db = SessionLocal()
    try:
        start_time = time.time()
        log_data = { "service_name": service.name, "url": service.url, "response_time_ms": 0, "status_code": None, "status": "Error", "error_message": None }
        
        headers = json.loads(service.headers) if service.headers else {}
        payload = json.loads(service.payload) if service.payload else {}
        auth = (service.auth_username, service.auth_password) if service.auth_type == 'basic' else None
        
        request_args = { "method": service.method, "url": service.url, "headers": headers, "auth": auth }
        if service.method in ["POST", "PUT", "PATCH"]:
            request_args["json"] = payload
            
        async with httpx.AsyncClient(timeout=20.0, verify=service.ssl_verify) as client:
            response = await client.request(**request_args)

        log_data["response_time_ms"] = (time.time() - start_time) * 1000
        log_data["status_code"] = response.status_code
        if 200 <= response.status_code < 400:
            log_data["status"] = "Éxito"
        else:
            error_text = response.text.strip()
            log_data["error_message"] = error_text[:499] if error_text else f"Error con código {response.status_code} pero sin mensaje de respuesta."
    except Exception as e:
        log_data["response_time_ms"] = (time.time() - start_time) * 1000
        log_data["error_message"] = str(e)
    finally:
        db.add(Log(**log_data))
        db.commit()
        db.close()

async def background_monitoring():
    print(f"Iniciando monitoreo en segundo plano...")
    while True:
        db_for_query = SessionLocal()
        try:
            services_to_monitor = db_for_query.query(Service).all()
            if services_to_monitor:
                # CORRECCIÓN: La llamada a gather se hace sobre las tareas, no sobre el resultado de monitor_service
                tasks = [monitor_service(service) for service in services_to_monitor]
                await asyncio.gather(*tasks)
        except Exception as e:
            print(f"Error en el ciclo de monitoreo: {e}")
        finally:
            db_for_query.close()
        await asyncio.sleep(MONITORING_INTERVAL_SECONDS)

# --- ENDPOINTS PROTEGIDOS RESTANTES (CÓDIGO COMPLETO) ---
@app.get("/api/reports/custom")
def get_custom_report(
    service_name: Optional[str] = None, start_date: Optional[str] = None, end_date: Optional[str] = None,
    limit: int = 500, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    stats_query = db.query(Log)
    if service_name: stats_query = stats_query.filter(Log.service_name == service_name)
    if start_date:
        try:
            start_datetime = datetime.datetime.strptime(start_date, "%Y-%m-%d").replace(tzinfo=datetime.timezone.utc)
            stats_query = stats_query.filter(Log.timestamp >= start_datetime)
        except (ValueError, TypeError): pass
    if end_date:
        try:
            end_datetime = (datetime.datetime.strptime(end_date, "%Y-%m-%d") + datetime.timedelta(days=1)).replace(tzinfo=datetime.timezone.utc)
            stats_query = stats_query.filter(Log.timestamp < end_datetime)
        except (ValueError, TypeError): pass
    total_requests = stats_query.count()
    if total_requests == 0:
        return {"summary": {"total_requests": 0, "successful_requests": 0, "failed_requests": 0, "availability": 100, "avg_response_time": 0, "min_response_time": 0, "max_response_time": 0}, "logs": []}
    successful_requests = stats_query.filter(Log.status == "Éxito").count()
    availability = (successful_requests / total_requests * 100)
    success_stats_query = stats_query.filter(Log.status == "Éxito")
    avg_response_time, min_response_time, max_response_time = (0.0, 0.0, 0.0)
    if success_stats_query.count() > 0:
         avg_response_time, min_response_time, max_response_time = success_stats_query.with_entities(func.avg(Log.response_time_ms), func.min(Log.response_time_ms), func.max(Log.response_time_ms)).one()
    summary = {
        "total_requests": total_requests, "successful_requests": successful_requests, "failed_requests": total_requests - successful_requests,
        "availability": round(availability, 2),
        "avg_response_time": round(avg_response_time or 0, 2),
        "min_response_time": round(min_response_time or 0, 2),
        "max_response_time": round(max_response_time or 0, 2),
    }
    logs_sample = stats_query.order_by(desc(Log.timestamp)).limit(limit).all()
    return {"summary": summary, "logs": logs_sample}


@app.get("/api/status")
def get_current_status(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    subquery = db.query(Log.service_name, func.max(Log.id).label("max_id")).group_by(Log.service_name).subquery()
    latest_logs = db.query(Log).join(subquery, (Log.id == subquery.c.max_id)).all()
    status_map = {log.service_name: log for log in latest_logs}
    services_from_db = db.query(Service).all()
    all_statuses = []
    for service in services_from_db:
        if service.name in status_map:
            all_statuses.append(status_map[service.name])
        else:
            all_statuses.append({ "service_name": service.name, "status": "Pendiente", "timestamp": None, "url": service.url, "error_message": None })
    return all_statuses

@app.get("/api/stats")
def get_stats(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    twenty_four_hours_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=24)
    query = db.query(Log).filter(Log.timestamp >= twenty_four_hours_ago)
    total_checks = query.count()
    successful_checks = query.filter(Log.status == "Éxito").count()
    availability = (successful_checks / total_checks * 100) if total_checks > 0 else 100
    avg_response_time = query.with_entities(func.avg(Log.response_time_ms)).scalar() or 0
    failures_by_service = query.filter(Log.status == "Error").group_by(Log.service_name).with_entities(Log.service_name, func.count(Log.id)).all()
    response_time_by_service = query.filter(Log.status == "Éxito").group_by(Log.service_name).with_entities(Log.service_name, func.avg(Log.response_time_ms)).all()
    return {
        "overall_availability": round(availability, 2), "average_response_time": round(avg_response_time, 2), "total_failures": total_checks - successful_checks,
        "failures_by_service": [{"service": name, "count": count} for name, count in failures_by_service],
        "response_time_by_service": [{"service": name, "avg_time": round(avg, 2)} for name, avg in response_time_by_service]
    }

# --- INICIALIZACIÓN ---
@app.on_event("startup")
def startup_event():
    db = SessionLocal()
    if db.query(User).count() == 0:
        default_admin = User(username="admin", hashed_password=get_password_hash("admin"), role=Role.admin)
        db.add(default_admin)
        db.commit()
        print("*"*50)
        print("PRIMERA EJECUCIÓN: Se ha creado el usuario administrador por defecto.")
        print("Usuario: admin")
        print("Contraseña: admin")
        print("*"*50)
    db.close()
    asyncio.create_task(background_monitoring())
