from sqlmodel import Field, SQLModel, Column, DateTime
import uuid as uuid_pkg
from enum import Enum, IntEnum
import datetime
from typing import Optional
from pydantic import EmailStr, BaseModel


class GenderEnum(str, Enum):
    male = 'male'
    female = 'female'
    other = 'other'


class OTPChannels(str, Enum):
    email = 'email'
    phone = 'phone'


class User(SQLModel):
    name: str = Field(
        max_length=255,
        description="The name of the user",
    )
    gender: GenderEnum = Field(
        description="The gender of the user",
    )
    dob: Optional[datetime.datetime] = Field(
        description="The date of birth of the user",
        sa_column=Column(
            DateTime(timezone=True),
            nullable=True
        )
    )
    isd_code: str = Field(
        regex="^\d{1,3}$",
        description="The isd code of user's phone number",
    )
    phone: str = Field(
        regex="^\d{4,15}$",
        description="The user's phone number",
    )
    email: EmailStr = Field(
        description="The user's email",
    )
    pan: Optional[str] = Field(
        max_length=16,
        description="The user's PAN number",
    )
    aadhaar: Optional[str] = Field(
        max_length=16,
        description="The user's Aadhaar number",
    )


class UserReg(User):
    age: int = Field(
        description="The age of the user",
        ge=18,
        le=100
    )
    phone_otp: str = Field(
        regex="^\d{6}$",
        description="The phone OTP of the user",
    )
    password: str = Field(
        max_length=64,
        description="The password of the user",
    )
    invite_code: str = Field(
        max_length=32,
        description="The invite code of the user",
    )


class UserTable(User, table=True):
    user_uuid: uuid_pkg.UUID = Field(
        default_factory=uuid_pkg.uuid4,
        primary_key=True,
        nullable=False,
        description="The UUID of the user",
    )
    invitation_code: str = Field(
        description="User's registration invitation code",
    )
    created_at: datetime.datetime = Field(
        description="User's creation timestamp",
        sa_column=Column(
            DateTime(timezone=True),
            nullable=False
        )
    )
    updated_at: datetime.datetime = Field(
        description="User's updation timestamp",
        sa_column=Column(
            DateTime(timezone=True),
            nullable=False
        )
    )


class PhoneOTP(SQLModel, table=True):
    isd_phone_str: str = Field(
        primary_key=True,
        nullable=False,
        description="A mobile number",
    )
    otp: str = Field(
        min_length=6,
        max_length=6,
        nullable=False,
        description="The OTP sent to the phone",
    )
    otp_expires_at: datetime.datetime = Field(
        description="The expiry timestamp of the OTP",
        sa_column=Column(
            DateTime(timezone=True),
            nullable=False
        )
    )

# class EmailOTP(SQLModel, table=True):
#     email_addr: str = Field(
#         primary_key=True,
#         nullable=False,
#         description="An email address",
#     )
#     otp: str = Field(
#         max_length=16,
#         nullable = True,
#         description="The OTP sent to the email",
#     )
#     otp_expires_at: datetime.datetime = Field(
#         description="The expiry timestamp of the OTP",
#         nullable = True
#     )

# class RegistrationOTP(SQLModel, table=True):
#     request_uuid: str = Field(
#         primary_key=True,
#         nullable=False,
#         description="An otp request",
#     )
#     otp_type: OTPChannels  = Field(
#         description="The channel to which the OTP was sent",
#     )
#     otp: str = Field(
#         max_length=16,
#         description="The OTP of the user",
#     )
#     otp_expires_at: datetime.datetime = Field(
#         description="The expiry timestamp of the OTP",
#     )


class InviteCodes(SQLModel, table=True):
    code: str = Field(
        max_length=32,
        nullable=False,
        primary_key=True,
        description="The Invite Code",
    )
    usage_count: int = Field(
        nullable=False,
        default=0,
        description="The number of time the invite code has been used"
    )
    max_usages: int = Field(
        description="The maximum number of times the invite code is allowed to be used",
        nullable=False,
        default=50
    )


class UserPasswordHash(SQLModel, table=True):
    user_uuid: uuid_pkg.UUID = Field(
        default_factory=uuid_pkg.uuid4,
        primary_key=True,
        nullable=False,
        description="The UUID of the user",
    )
    password_hash: str = Field(
        description="The hash of the user's password",
        nullable=False
    )
    last_updated_at: datetime.datetime = Field(
        description="The update timestamp of the password",
        sa_column=Column(
            DateTime(timezone=True),
            nullable=False
        )
    )

class UserUpdate(BaseModel):
    name: Optional[str] = Field(
        max_length=255,
        description="The name of the user",
    )
    gender: Optional[GenderEnum] = Field(
        description="The gender of the user",
    )
    dob: Optional[datetime.datetime] = Field(
        description="The date of birth of the user",
        sa_column=Column(
            DateTime(timezone=True),
            nullable=True
        )
    )
    pan: Optional[str] = Field(
        max_length=16,
        description="The user's PAN number",
    )
    aadhaar: Optional[str] = Field(
        max_length=16,
        description="The user's Aadhaar number",
    )