from sqlmodel import Field, SQLModel
import uuid as uuid_pkg
from enum import Enum, IntEnum
import datetime
from typing import Optional

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
        max_length=255,
        description="The gender of the user",
    )
    age: int = Field(
        description="The age of the user",
    )
    isd_code: str = Field(
        max_length=16,
        description="The isd code of user's phone number",
    )
    phone: str = Field(
        max_length=32,
        description="The user's phone number",
    )
    email: str = Field(
        max_length=256,
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
    phone_otp: str = Field(
        max_length=16,
        description="The phone OTP of the user",
    )
    email_otp: str = Field(
        max_length=16,
        description="The email OTP of the user",
    )
    password: str = Field(
        max_length=64,
        description="The password of the user",
    )
    invite_code:str = Field(
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
    created_at: datetime.datetime = Field(
        description="User's creation timestamp",
    )
    updated_at: datetime.datetime = Field(
        description="User's updation timestamp",
    )

class PhoneOTP(SQLModel, table=True):
    isd_phone_str: str = Field(
        primary_key=True,
        nullable=False,
        description="A mobile number",
    )
    otp: str = Field(
        max_length=16,
        nullable = True,
        description="The OTP sent to the phone",
    )
    otp_expires_at: datetime.datetime = Field(
        description="The expiry timestamp of the OTP",
        nullable = True
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
    invite_uuid: uuid_pkg.UUID = Field(
        default_factory=uuid_pkg.uuid4,
        primary_key=True,
        nullable=False,
        description="The UUID of the invite code",
    )
    code: str = Field(
        max_length=32,
        description="The Invite Code",
    )
    max_usages: int = Field(
        description="The maximum number of times the invite code is allowed to be used",
    )


class UserPasswordHash(SQLModel, table=True):
    user_uuid: uuid_pkg.UUID = Field(
        default_factory=uuid_pkg.uuid4,
        primary_key=True,
        nullable=False,
        description="The UUID of the user",
    )
    password_hash: str  = Field(
        description="The hash of the user's password",
    )
    last_updated_at: datetime.datetime = Field(
        description="The update timestamp of the password",
        nullable = True
    )