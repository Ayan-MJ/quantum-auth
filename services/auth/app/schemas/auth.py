"""
Auth-related Pydantic schemas
"""
from typing import Optional

from pydantic import BaseModel, UUID4


class SignupResponse(BaseModel):
    """
    Response model for signup endpoint
    """
    user_id: UUID4
    is_new: bool


class TokenData(BaseModel):
    """
    Data extracted from JWT token
    """
    user_id: str
    email: Optional[str] = None
