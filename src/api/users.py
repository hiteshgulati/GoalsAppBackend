import logging
from fastapi import APIRouter, Depends, Request, Query
from fastapi.exceptions import HTTPException
from typing import Union, Optional, Annotated
from pydantic import BaseModel
from enum import Enum, IntEnum
from utils.emails import Msg91Mailer
from utils.sms import Msg91SMSClient, is_isd_code_approved
from utils.security import get_password_hash
from config import Settings, get_settings
from utils.db import get_db
from models.users import UserReg, UserTable
from models.users import PhoneOTP, InviteCodes, UserPasswordHash
from sqlmodel import Session, select
from utils.throttle import limiter
from datetime import datetime, timedelta
import random
import json
import uuid
import datetime

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

router = APIRouter()


class GenderEnum(str, Enum):
    male = 'male'
    female = 'female'
    other = 'other'


@router.post("/register/mobile-otp", tags=["Registration"])
@limiter.limit("50/hour")
def request_mobile_otp_for_registration(
    request: Request,
    isd_code: Annotated[str, Query(example="91")],
    mobile_number: Annotated[str, Query(pattern="^\d{4,15}$")],
    settings: Settings = Depends(get_settings)
):

    # Check if isd code is whitelisted (i.e tested + known to be functional)
    if not is_isd_code_approved(settings.APPROVED_ISD_CODES, isd_code):
        raise HTTPException(status_code=403, detail="ISD code not approved")

    # Generate a random OTP
    random_otp: str = ""
    for _ in range(6):
        random_otp = random_otp + str(random.randint(0, 9))
    expiry_time = datetime.datetime.now(
        tz=datetime.timezone.utc) + timedelta(minutes=2)

    # Store the OTP message and update expiry
    db = get_db()
    isd_phone_str = isd_code+""+mobile_number
    otp_record = PhoneOTP(
        isd_phone_str=isd_phone_str,
        otp=random_otp,
        otp_expires_at=expiry_time
    )
    with Session(db) as session:
        statement = select(PhoneOTP).where(
            PhoneOTP.isd_phone_str == isd_phone_str)
        result = session.exec(statement).first()

        # if otp record does not exist, create it
        if result is None:
            result = otp_record
        else:
            result.otp = random_otp
            result.otp_expires_at = expiry_time

        # persist the data to the database
        session.add(result)
        session.commit()
        session.refresh(result)

    # Send the OTP via SMS
    mailer = Msg91SMSClient(
        authkey=settings.MSG91_AUTHKEY
    )

    send_resp = mailer.send_otp_sms(
        mobile_number=isd_code + "" + mobile_number,
        otp=random_otp,
        dur_mins_str="2"
    )
    print(f"SMS request sent for {isd_phone_str}. Response Text: {send_resp}")

    # Parse response (if possible)
    try:
        parsed_resp = json.loads(send_resp)
        if "type" in parsed_resp:
            if parsed_resp["type"] == "success":
                return {"otp_send_status": True}
            else:
                raise HTTPException(
                    status_code=500, detail="Unexpected response")
        else:
            raise HTTPException(status_code=500, detail="Missing information")
    except:
        raise HTTPException(status_code=500, detail="Parsing error")


# @router.post("/register/email_otp", tags=["Registration"])
# def request_email_otp_for_registration(email: str):
#     return {"otp_send_status": False}

@router.post("/register/new-user", tags=["Registration"])
def new_user(
    user_reg: UserReg,
    settings: Settings = Depends(get_settings)
):

    # Check if isd code is whitelisted (i.e tested + known to be functional)
    if not is_isd_code_approved(settings.APPROVED_ISD_CODES, user_reg.isd_code):
        raise HTTPException(status_code=403, detail="ISD code not approved")

    # Check if user is already registered
    user_exists = False
    phone_search_result = None
    db = get_db()
    with Session(db) as session:

        phone_search_statement = select(UserTable).where(
            UserTable.phone == user_reg.phone).where(UserTable.isd_code == user_reg.isd_code)
        phone_search_result = session.exec(phone_search_statement).first()

        if phone_search_result is not None:
            user_exists = True

        email_search_statement = select(UserTable).where(
            UserTable.email == user_reg.email)
        email_search_result = session.exec(email_search_statement).first()

        if email_search_result is not None:
            user_exists = True

    if user_exists == True:
        raise HTTPException(status_code=403, detail="User already exists")

    # Check Invite Code validity
    is_invite_code_valid = False
    with Session(db) as session:
        invite_code_search = select(InviteCodes).where(
            InviteCodes.code == user_reg.invite_code)
        invite_code_search_result = session.exec(invite_code_search).first()

    if invite_code_search_result is not None:
        if invite_code_search_result.usage_count <= invite_code_search_result.max_usages:
            is_invite_code_valid = True

    if is_invite_code_valid == False:
        raise HTTPException(status_code=403, detail="Invite code is not valid")

    # Check OTP
    is_otp_matching = False
    is_otp_expired = True
    isd_phone_str:str = user_reg.isd_code+""+user_reg.phone
    current_time = datetime.datetime.now(tz=datetime.timezone.utc)
    otp_search_result = None
    with Session(db) as session:
        otp_search_result = session.get(PhoneOTP, isd_phone_str)

    if otp_search_result is not None:
        if otp_search_result.otp == user_reg.phone_otp:
            is_otp_matching = True
            if current_time < otp_search_result.otp_expires_at:
                is_otp_expired = False

    # Check OTP validity
    print(f"OTP Match: {is_otp_matching} OTP Expired: {is_otp_expired}")
    if is_otp_matching == False or is_otp_expired == True:
        raise HTTPException(status_code=400, detail="Phone OTP is not valid")

    # Hash password
    hashed_pass = get_password_hash(user_reg.password)

    # Store the new user details
    user_uuid = uuid.uuid4()
    invite_code_search_result.usage_count = invite_code_search_result.usage_count + 1
    new_user_record = UserTable(
        user_uuid=user_uuid,
        invitation_code=user_reg.invite_code,
        name=user_reg.name,
        gender=user_reg.gender,
        age=user_reg.age,
        isd_code=user_reg.isd_code,
        phone=user_reg.phone,
        email=user_reg.email,
        aadhaar=user_reg.aadhaar,
        pan=user_reg.pan,
        created_at=current_time,
        updated_at=current_time
    )
    uph = UserPasswordHash(
        user_uuid=user_uuid,
        password_hash=hashed_pass,
        last_updated_at=current_time
    )

    with Session(db) as session:
        session.add(new_user_record)
        session.add(uph)
        session.add(invite_code_search_result)
        session.commit()
        session.refresh(new_user_record)

    # TODO: Send Welcome Email

    return {"user_added": True}


# @router.post("/auth/mobile/otp", tags=["Auth"])
# def request_otp(isd_code: str, mobile_number: str):
#     return {"otp_send_status": False}


# @router.post("/auth/mobile/token", tags=["Auth"])
# def request_token_using_mobile(isd_code: str, mobile_number: str, otp: str):
#     return {
#         "token": "sample_jwt"
#     }


@router.post("/auth/login/mobile-password", tags=["Auth"])
def request_token_using_mobile_password(isd_code: str, phone: str, password: str):
    # TODO: Throttle to slow down brute force attacks
    # TODO: Find user from phone number in database
    # TODO: Find user's hashed password
    # TODO: Hash input password and check
    # TODO: Generate token with an expiry timestamp
    # TODO: Send token

    return {"token": "sample_jwt"}


# @router.post("/auth/email/password_reset", tags=["Auth"])
# def request_password_reset_code_using_email(
#     email: str,
#     settings: Settings = Depends(get_settings)
# ):
#     mailer = Msg91Mailer(
#         authkey=settings.MSG91_AUTHKEY,
#         domain=settings.MSG91_DOMAIN,
#         from_email=settings.MSG91_FROM_EMAIL
#     )

#     mailer.send_email_using_template(
#         to_email=email,
#         to_name="User",
#         template_id="global_otp",
#         variables={
#             "company_name": settings.name,
#             "otp": 123456
#         }
#     )

#     return {"message": "processed"}


# @router.put("/auth/email/update_password", tags=["Auth"])
# def update_password_using_reset_code(email: str, code: str, new_password: str):
#     return {"message": "updated"}


@router.get("/me", tags=["Users"])
def get_user_profile():
    # TODO: Authenticate token
    # TODO: Find user from token
    # TODO: Return user profile data
    return {"user": {}}


# @router.patch("/profile", tags=["Users"])
# def update_user():
#     return {"user": {}}
