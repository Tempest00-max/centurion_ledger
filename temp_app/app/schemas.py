from pydantic import BaseModel, EmailStr, Field, field_validator
from typing import List, Optional
from datetime import datetime
from decimal import Decimal
from uuid import UUID


# ============================================
# BASE SCHEMAS
# ============================================

class AccountBase(BaseModel):
    """Base account data for creation."""
    owner_name: str = Field(..., min_length=1, max_length=255)
    username: str = Field(..., min_length=3, max_length=255)
    email: EmailStr

    @field_validator('username')
    @classmethod
    def username_alphanumeric(cls, v):
        if not v.replace('_', '').replace('-', '').isalnum():
            raise ValueError('Username must be alphanumeric with underscores or hyphens only')
        return v.lower()

    @field_validator('owner_name')
    @classmethod
    def owner_name_strip(cls, v):
        return v.strip()


class SignupRequest(AccountBase):
    """Signup request that includes password and PIN in the body."""
    password: str = Field(..., min_length=8)
    pin: str = Field(..., min_length=6, max_length=6)

    @field_validator('pin')
    @classmethod
    def validate_pin(cls, v):
        if not v.isdigit():
            raise ValueError('PIN must contain only digits')
        return v

    @field_validator('password')
    @classmethod
    def validate_password_strength(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v


class Account(AccountBase):
    """Full account schema for API responses."""
    id: str
    balance: Decimal = Decimal('0')
    currency: str = 'NGN'
    version: int = 1
    created_at: Optional[datetime] = None
    failed_pin_attempts: int = 0
    locked_until: Optional[datetime] = None

    @field_validator('id', mode='before')
    @classmethod
    def validate_id(cls, v):
        """Ensure UUID is always returned as string."""
        if v is None:
            raise ValueError('ID cannot be None')
        return str(v)

    @field_validator('balance', mode='before')
    @classmethod
    def validate_balance(cls, v):
        """Ensure balance is always Decimal."""
        if v is None:
            return Decimal('0')
        try:
            return Decimal(str(v))
        except (ValueError, TypeError):
            raise ValueError('Invalid balance value')

    @field_validator('currency')
    @classmethod
    def validate_currency(cls, v):
        """Normalize currency to uppercase."""
        if not v:
            return 'NGN'
        v = v.upper()
        allowed = {'NGN', 'USD', 'EUR', 'GBP'}
        if v not in allowed:
            raise ValueError(f'Currency must be one of: {", ".join(allowed)}')
        return v

    class Config:
        from_attributes = True
        json_encoders = {
            Decimal: lambda v: float(v),
            datetime: lambda v: v.isoformat() if v else None
        }


class Transaction(BaseModel):
    """Transaction schema for API responses."""
    id: str
    sender_id: str
    receiver_id: str
    amount: Decimal = Decimal('0')
    currency: str = 'NGN'
    status: str = 'COMPLETED'
    signature: str = ''
    idempotency_key: Optional[str] = None
    created_at: Optional[datetime] = None

    @field_validator('id', 'sender_id', 'receiver_id', mode='before')
    @classmethod
    def validate_uuid_fields(cls, v):
        """Ensure all UUID fields are strings."""
        if v is None:
            raise ValueError('ID fields cannot be None')
        return str(v)

    @field_validator('amount', mode='before')
    @classmethod
    def validate_amount(cls, v):
        """Ensure amount is always Decimal."""
        if v is None:
            return Decimal('0')
        try:
            d = Decimal(str(v))
            if d < 0:
                raise ValueError('Amount cannot be negative')
            return d
        except (ValueError, TypeError):
            raise ValueError('Invalid amount value')

    @field_validator('currency')
    @classmethod
    def validate_currency(cls, v):
        """Normalize currency to uppercase."""
        if not v:
            return 'NGN'
        v = v.upper()
        allowed = {'NGN', 'USD', 'EUR', 'GBP'}
        if v not in allowed:
            raise ValueError(f'Currency must be one of: {", ".join(allowed)}')
        return v

    class Config:
        from_attributes = True
        json_encoders = {
            Decimal: lambda v: float(v),
            datetime: lambda v: v.isoformat() if v else None
        }


class UpdateProfile(BaseModel):
    """Profile update schema with strict validation."""
    owner_name: Optional[str] = Field(None, min_length=1, max_length=255)
    email: Optional[EmailStr] = None
    pin: Optional[str] = Field(None, min_length=6, max_length=6)
    password: Optional[str] = Field(None, min_length=8)

    @field_validator('owner_name')
    @classmethod
    def owner_name_strip(cls, v):
        if v is not None:
            return v.strip()
        return v

    @field_validator('pin')
    @classmethod
    def validate_pin(cls, v):
        if v is not None:
            if not v.isdigit():
                raise ValueError('PIN must contain only digits')
        return v

    @field_validator('password')
    @classmethod
    def validate_password_strength(cls, v):
        if v is not None:
            if len(v) < 8:
                raise ValueError('Password must be at least 8 characters')
            if not any(c.isupper() for c in v):
                raise ValueError('Password must contain at least one uppercase letter')
            if not any(c.islower() for c in v):
                raise ValueError('Password must contain at least one lowercase letter')
            if not any(c.isdigit() for c in v):
                raise ValueError('Password must contain at least one digit')
        return v


class LoginResponse(BaseModel):
    """OAuth2 token response."""
    access_token: str
    token_type: str = 'bearer'
    expires_in: int = 3600


class TransferResponse(BaseModel):
    """Transfer success response."""
    status: str
    transaction_id: str
    amount_sent: float
    currency: str
    sender_balance: float
    receiver_name: str
    receiver_email: str


class ForecastResponse(BaseModel):
    """AI forecast response."""
    message: str
    insights: List[str]
    prediction: Optional[dict]
    recommendations: List[str]
    daily_activity: dict
