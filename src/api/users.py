import logging
from fastapi import APIRouter, Depends, Request, Query, status, Header, UploadFile
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.exceptions import HTTPException
from jose import JWTError
from typing import Union, Optional, Annotated
from pydantic import BaseModel
from enum import Enum, IntEnum
from utils.emails import Msg91Mailer
from utils.sms import Msg91SMSClient, is_isd_code_approved
from utils.security import (
    get_password_hash,
    verify_password,
    create_access_token,
    oauth2_scheme,
    resolve_subject_from_token,
)
from config import Settings, get_settings
from utils.db import get_db
from models.users import UserReg, UserTable, UserUpdate, UserPhoto
from models.users import PhoneOTP, InviteCodes, UserPasswordHash
from sqlmodel import Session, select, text
from utils.throttle import limiter
from datetime import datetime, timedelta
import random
import json
import uuid
import datetime
import base64
from utils.api import StandardResponse

MAX_FILE_SIZE = 1 * 1024 * 1024  # 1MB

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

router = APIRouter()


async def get_user(db, user_uuid):
    user_search_result = None
    with Session(db) as session:
        phone_search_statement = select(UserTable).where(
            UserTable.user_uuid == user_uuid
        )
        user_search_result = session.exec(phone_search_statement).first()

        if user_search_result is not None:
            return user_search_result

    return None


async def get_user_pic(db, user_uuid) -> UserPhoto | None:
    search_res = None
    with Session(db) as session:
        pic_search_statement = select(UserPhoto).where(UserPhoto.user_uuid == user_uuid)
        search_res = session.exec(pic_search_statement).first()

        if search_res is not None:
            return search_res

    return None


async def get_current_user(
    token=Depends(oauth2_scheme),
    db=Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        user_uuid = resolve_subject_from_token(
            token=token, secret_key=settings.JWT_SECRET_KEY
        )
        if user_uuid is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = await get_user(db=db, user_uuid=user_uuid)
    if user is None:
        raise credentials_exception
    return user


@router.post("/register/mobile-otp", tags=["Registration"])
@limiter.limit("50/hour")
def request_mobile_otp_for_registration(
    request: Request,
    isd_code: Annotated[str, Query(example="91")],
    mobile_number: Annotated[str, Query(pattern="^\d{4,15}$")],
    settings: Settings = Depends(get_settings),
):
    # Check if isd code is whitelisted (i.e tested + known to be functional)
    if not is_isd_code_approved(settings.APPROVED_ISD_CODES, isd_code):
        raise HTTPException(status_code=403, detail="ISD code not approved")

    # Generate a random OTP
    random_otp: str = ""
    for _ in range(6):
        random_otp = random_otp + str(random.randint(0, 9))
    expiry_time = datetime.datetime.now(tz=datetime.timezone.utc) + timedelta(minutes=5)

    # Store the OTP message and update expiry
    db = get_db()
    isd_phone_str = isd_code + "" + mobile_number
    otp_record = PhoneOTP(
        isd_phone_str=isd_phone_str, otp=random_otp, otp_expires_at=expiry_time
    )
    with Session(db) as session:
        statement = select(PhoneOTP).where(PhoneOTP.isd_phone_str == isd_phone_str)
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
    mailer = Msg91SMSClient(authkey=settings.MSG91_AUTHKEY)

    send_resp = mailer.send_otp_sms(
        mobile_number=isd_code + "" + mobile_number, otp=random_otp, dur_mins_str="5"
    )
    print(f"SMS request sent for {isd_phone_str}. Response Text: {send_resp}")

    # Parse response (if possible)
    try:
        parsed_resp = json.loads(send_resp)
        if "type" in parsed_resp:
            if parsed_resp["type"] == "success":
                return {"otp_send_status": True}
            else:
                raise HTTPException(status_code=500, detail="Unexpected response")
        else:
            raise HTTPException(status_code=500, detail="Missing information")
    except:
        raise HTTPException(status_code=500, detail="Parsing error")


# @router.post("/register/email_otp", tags=["Registration"])
# def request_email_otp_for_registration(email: str):
#     return {"otp_send_status": False}


@router.post("/register/new-user", tags=["Registration"])
def new_user(user_reg: UserReg, settings: Settings = Depends(get_settings)):
    # Check if isd code is whitelisted (i.e tested + known to be functional)
    if not is_isd_code_approved(settings.APPROVED_ISD_CODES, user_reg.isd_code):
        raise HTTPException(status_code=403, detail="ISD code not approved")

    # Check if user is already registered
    user_exists = False
    phone_search_result = None
    db = get_db()
    with Session(db) as session:
        phone_search_statement = (
            select(UserTable)
            .where(UserTable.phone == user_reg.phone)
            .where(UserTable.isd_code == user_reg.isd_code)
        )
        phone_search_result = session.exec(phone_search_statement).first()

        if phone_search_result is not None:
            user_exists = True

        email_search_statement = select(UserTable).where(
            UserTable.email == user_reg.email
        )
        email_search_result = session.exec(email_search_statement).first()

        if email_search_result is not None:
            user_exists = True

    if user_exists == True:
        raise HTTPException(status_code=403, detail="User already exists")

    # Check Invite Code validity
    is_invite_code_valid = False
    with Session(db) as session:
        invite_code_search = select(InviteCodes).where(
            InviteCodes.code == user_reg.invite_code
        )
        invite_code_search_result = session.exec(invite_code_search).first()

    if invite_code_search_result is not None:
        if (
            invite_code_search_result.usage_count
            <= invite_code_search_result.max_usages
        ):
            is_invite_code_valid = True

    if is_invite_code_valid == False:
        raise HTTPException(status_code=403, detail="Invite code is not valid")

    # Check OTP
    is_otp_matching = False
    is_otp_expired = True
    isd_phone_str: str = user_reg.isd_code + "" + user_reg.phone
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
    # Calculate dob if needed
    this_year = datetime.datetime.now(tz=datetime.timezone.utc)
    dob = datetime.datetime(year=this_year.year, month=1, day=1)  # default
    if user_reg.dob is None:
        dob = dob - datetime.timedelta(days=user_reg.age * 365.2425)
        dob = dob.replace(hour=0)
        dob = dob.replace(minute=0)
        dob = dob.replace(second=0)
        dob = dob.replace(microsecond=0)
    else:
        dob = user_reg.dob

    # Store the new user details
    user_uuid = uuid.uuid4()
    invite_code_search_result.usage_count = invite_code_search_result.usage_count + 1
    new_user_record = UserTable(
        user_uuid=user_uuid,
        invitation_code=user_reg.invite_code,
        name=user_reg.name,
        gender=user_reg.gender,
        age=user_reg.age,
        dob=dob,
        isd_code=user_reg.isd_code,
        phone=user_reg.phone,
        email=user_reg.email,
        aadhaar=user_reg.aadhaar,
        pan=user_reg.pan,
        created_at=current_time,
        updated_at=current_time,
    )
    uph = UserPasswordHash(
        user_uuid=user_uuid, password_hash=hashed_pass, last_updated_at=current_time
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


@router.post("/auth/login/check-user", tags=["Auth"])
@limiter.limit("1/second")
def check_user_exists(
    request: Request,
    isd_code: str,
    phone: str,
    settings: Settings = Depends(get_settings),
):
    # Check if isd code is whitelisted (i.e tested + known to be functional)
    if not is_isd_code_approved(settings.APPROVED_ISD_CODES, isd_code):
        raise HTTPException(status_code=403, detail="ISD code not approved")

    # Check if user is registered
    user_exists = False
    user_search_result = None
    db = get_db()
    with Session(db) as session:
        phone_search_statement = (
            select(UserTable)
            .where(UserTable.phone == phone)
            .where(UserTable.isd_code == isd_code)
        )
        user_search_result = session.exec(phone_search_statement).first()

        if user_search_result is not None:
            user_exists = True

    return {user_exists: user_exists}


@router.post("/auth/oauth2_password_login", tags=["Auth"])
@limiter.limit("1/second")
def oauth2_login(
    request: Request,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    settings: Settings = Depends(get_settings),
):
    # Check if user is registered
    user_exists = False
    user_search_result = None
    db = get_db()
    with Session(db) as session:
        query = text(
            """
            SELECT * from UserTable
            WHERE CONCAT(isd_code, phone) = :username
            """
        )
        user_search_result = session.execute(
            statement=query, params={"username": form_data.username}
        ).first()

        if user_search_result is not None:
            user_exists = True

    if user_exists == False:
        raise HTTPException(status_code=403, detail="Forbidden")

    # Find user's hashed password
    user_uuid = user_search_result.user_uuid
    with Session(db) as session:
        password_hash_search = select(UserPasswordHash).where(
            UserPasswordHash.user_uuid == user_uuid
        )
        pass_hash_search_res = session.exec(password_hash_search).first()

    if pass_hash_search_res is None:
        raise HTTPException(status_code=500, detail="Unable to verify")

    # Hash input password and check
    password = form_data.password
    is_pass_ok = verify_password(
        plain_password=password, hashed_password=pass_hash_search_res.password_hash
    )
    if is_pass_ok == False:
        raise HTTPException(status_code=403, detail="Forbidden")

    # Generate token with an expiry timestamp
    token_data = create_access_token(
        settings.JWT_SECRET_KEY,
        {
            "sub": str(user_uuid),
        },
    )

    # Send token
    return {
        "token_type": "bearer",
        "access_token": token_data["token"],
        "exp": token_data["exp"],
    }


@router.post("/auth/login/mobile-password", tags=["Auth"])
@limiter.limit("1/second")
def request_token_using_mobile_password(
    request: Request,
    isd_code: str,
    phone: str,
    password: str,
    settings: Settings = Depends(get_settings),
):
    # Check if isd code is whitelisted (i.e tested + known to be functional)
    if not is_isd_code_approved(settings.APPROVED_ISD_CODES, isd_code):
        raise HTTPException(status_code=403, detail="ISD code not approved")

    # Check if user is registered
    user_exists = False
    user_search_result = None
    db = get_db()
    with Session(db) as session:
        phone_search_statement = (
            select(UserTable)
            .where(UserTable.phone == phone)
            .where(UserTable.isd_code == isd_code)
        )
        user_search_result = session.exec(phone_search_statement).first()

        if user_search_result is not None:
            user_exists = True

    if user_exists == False:
        raise HTTPException(status_code=403, detail="Forbidden")

    # Find user's hashed password
    user_uuid = user_search_result.user_uuid
    with Session(db) as session:
        password_hash_search = select(UserPasswordHash).where(
            UserPasswordHash.user_uuid == user_uuid
        )
        pass_hash_search_res = session.exec(password_hash_search).first()

    if pass_hash_search_res is None:
        raise HTTPException(status_code=500, detail="Unable to verify")

    # Hash input password and check
    is_pass_ok = verify_password(
        plain_password=password, hashed_password=pass_hash_search_res.password_hash
    )
    if is_pass_ok == False:
        raise HTTPException(status_code=403, detail="Forbidden")

    # Generate token with an expiry timestamp
    token_data = create_access_token(
        settings.JWT_SECRET_KEY,
        {
            "sub": str(user_uuid),
        },
    )

    # Send token
    return token_data


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
def get_user_profile(user=Depends(get_current_user)):
    return user


@router.patch("/me", tags=["Users"])
def update_user(
    updates: UserUpdate, user: UserTable = Depends(get_current_user), db=Depends(get_db)
):
    # Apply updates
    if updates.name is not None:
        user.name = updates.name

    if updates.gender is not None:
        user.gender = updates.gender

    if updates.dob is not None:
        user.dob = updates.dob

    if updates.pan is not None:
        user.pan = updates.pan

    if updates.aadhaar is not None:
        user.aadhaar = updates.aadhaar

    with Session(db) as session:
        session.add(user)
        session.commit()
        session.refresh(user)
    return user


@router.put("/me/pic", tags=["Users"])
async def update_display_picture(
    pic: UploadFile, user: UserTable = Depends(get_current_user), db=Depends(get_db)
) -> StandardResponse:
    # Read file content
    file_content = await pic.read()

    # Check file size
    if len(file_content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"Image too large. Max size is {MAX_FILE_SIZE} bytes",
        )

    # Base64 encode the file
    base64_encoded_data = base64.b64encode(file_content).decode("utf-8")

    # Determine media type
    whitelisted_media_types = ["image/jpeg", "image/png"]

    if pic.content_type not in whitelisted_media_types:
        raise HTTPException(status_code=400, detail="Unsupported image format")

    # Check if pic already exists
    existing_pic = await get_user_pic(db=db, user_uuid=user.user_uuid)
    img_record = None
    if existing_pic is None:
        img_record = UserPhoto(
            user_uuid=user.user_uuid,
            media_type=pic.content_type,
            data=base64_encoded_data,
            last_updated_at=datetime.datetime.now(tz=datetime.timezone.utc),
        )
    else:
        img_record = existing_pic
        existing_pic.data = base64_encoded_data
        existing_pic.last_updated_at = (
            datetime.datetime.now(tz=datetime.timezone.utc),
        )
        existing_pic.media_type = pic.content_type

    with Session(db) as session:
        session.add(img_record)
        session.commit()
        session.refresh(img_record)

    return StandardResponse(success=True, message="File uploaded")


@router.get("/me/pic", tags=["Users"])
async def get_user_profile_pic(user=Depends(get_current_user), db=Depends(get_db)):
    # Check if pic already exists
    existing_pic = await get_user_pic(db=db, user_uuid=user.user_uuid)

    if existing_pic is None:
        raise HTTPException(status_code=404, detail="No image found for the user")
    else:
        return {
            "data": existing_pic.data,
            "media_type": existing_pic.media_type,
            "last_updated_at": existing_pic.last_updated_at,
        }
    return user
