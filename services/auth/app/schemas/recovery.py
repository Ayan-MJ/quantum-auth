"""
Recovery-related Pydantic schemas
"""
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field, UUID4, validator


class RecoveryShareCreate(BaseModel):
    """
    Schema for creating recovery shares
    """
    threshold: int = Field(default=3, ge=2, description="Minimum number of shares needed to recover the secret")
    shares: int = Field(default=5, ge=3, le=10, description="Total number of shares to generate")
    
    @validator("shares")
    def shares_must_be_greater_than_threshold(cls, v, values):
        if "threshold" in values and v < values["threshold"]:
            raise ValueError("Number of shares must be greater than or equal to threshold")
        return v


class RecoverySharesResponse(BaseModel):
    """
    Schema for recovery shares response
    """
    shares: List[str]
    threshold: int
    total: int


class RecoveryShareDB(BaseModel):
    """
    Schema for recovery share in database
    """
    id: UUID4
    user_id: UUID4
    share: str
    created_at: datetime
    
    class Config:
        from_attributes = True


class RecoveryShareVerify(BaseModel):
    """
    Schema for verifying recovery shares
    """
    shares: List[str] = Field(..., min_items=2, description="List of shares to verify")


class RecoveryShareVerifyResponse(BaseModel):
    """
    Schema for recovery share verification response
    """
    valid: bool
    message: Optional[str] = None
