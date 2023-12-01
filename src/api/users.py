import logging
from fastapi import APIRouter, Depends
from typing import Union, Optional
from pydantic import BaseModel
from enum import Enum, IntEnum
from utils.emails import Msg91Mailer
from utils.sms import Msg91SMSClient
from config import Settings, get_settings
from utils.db import get_db
from models.users import UserReg, UserTable
from sqlmodel import Session
import uuid
import datetime

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

router = APIRouter()

class GenderEnum(str, Enum):
    male = 'male'
    female = 'female'
    other = 'other'


class UserRegistration(BaseModel):
    name: str
    gender: GenderEnum
    age: int
    isd_code: str
    phone: str
    phone_otp: str
    email: str
    email_otp: str
    password: str
    invite_code: str
    aadhar: Optional[str] = None
    pan: Optional[str] = None


@router.post("/register/mobile_otp", tags=["Registration"])
def request_mobile_otp_for_registration(
    isd_code: str, 
    mobile_number: str,
    settings: Settings = Depends(get_settings)
    ):
    
    mailer = Msg91SMSClient(
        authkey=settings.MSG91_AUTHKEY
    )

    mailer.send_otp_sms(
        mobile_number=isd_code + "" + mobile_number,
        otp="123456",
        dur_mins_str="2"
    )
    
    return {"otp_send_status": False}

@router.post("/register/email_otp", tags=["Registration"])
def request_email_otp_for_registration(email: str):
    return {"otp_send_status": False}

@router.post("/register/new_user", tags=["Registration"])
def new_user(
        user_reg: UserReg,
    ):
    db = get_db()
    new_user_record = UserTable(
        user_uuid = uuid.uuid4(),
        name = user_reg.name,
        gender = user_reg.gender,
        age = user_reg.age,
        isd_code = user_reg.isd_code,
        phone= user_reg.phone,
        email = user_reg.email,
        aadhaar = user_reg.aadhaar,
        pan = user_reg.pan,
        created_at = datetime.datetime.now(tz=datetime.timezone.utc),
        updated_at = datetime.datetime.now(tz=datetime.timezone.utc)
    )
    with Session(db) as session:
        session.add(new_user_record)
        session.commit()
        session.refresh(new_user_record)

    
    return {"user_added": False}


@router.post("/auth/mobile/otp", tags=["Auth"])
def request_otp(isd_code: str, mobile_number: str):
    return {"otp_send_status": False}


@router.post("/auth/mobile/token", tags=["Auth"])
def request_token_using_mobile(isd_code: str, mobile_number: str, otp: str):
    return {
        "token": "sample_jwt"
    }


@router.post("/auth/email/token", tags=["Auth"])
def request_token_using_email(email: str, password: str):
    return {"token": "sample_jwt"}


@router.post("/auth/email/password_reset", tags=["Auth"])
def request_password_reset_code_using_email(
    email: str,
    settings: Settings = Depends(get_settings)
):
    mailer = Msg91Mailer(
        authkey=settings.MSG91_AUTHKEY,
        domain=settings.MSG91_DOMAIN,
        from_email=settings.MSG91_FROM_EMAIL
    )

    mailer.send_email_using_template(
        to_email=email,
        to_name="User",
        template_id="global_otp",
        variables={
            "company_name": settings.name,
            "otp": 123456
        }
    )

    return {"message": "processed"}


@router.put("/auth/email/update_password", tags=["Auth"])
def update_password_using_reset_code(email: str, code: str, new_password: str):
    return {"message": "updated"}


@router.get("/me", tags=["Users"])
def get_user_profile():
    return {"user": {}}


@router.patch("/profile", tags=["Users"])
def update_user():
    return {"user": {}}
