from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException
from fastapi.security import OAuth2PasswordBearer

JWT_ALGORITHM = "HS256"
JWT_EXPIRY_MINS = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/users/auth/oauth2_password_login")

def get_password_hash(password)->str:
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password)->bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(secret_key:str, data: dict):
    to_encode = data.copy()
    current_time = datetime.now(tz=timezone.utc)
    to_encode.update({"iat": current_time})
    expire = current_time + timedelta(minutes=JWT_EXPIRY_MINS)
    to_encode.update({"exp": expire})
    to_encode.update({"iss": "EMBTR_AUTH"})
    encoded_jwt = jwt.encode(to_encode, secret_key, algorithm=JWT_ALGORITHM)
    return { "token" : encoded_jwt, "exp" : expire.isoformat() }

def resolve_subject_from_token(token: str, secret_key:str):
    try:
        payload = jwt.decode(token, secret_key, algorithms=[JWT_ALGORITHM])
        subject: str = payload.get("sub")
    
        if subject is None:
            raise HTTPException(status_code=401, detail="Could not validate credentials")
    
        return subject

    except Exception as error:
        print(error)
        raise HTTPException(status_code=401, detail="Could not validate credentials")