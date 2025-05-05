"""
Authentication routes for the Auth service
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.supabase import get_current_user, TokenPayload
from app.db.session import get_db
from app.schemas.auth import SignupResponse

router = APIRouter()


@router.post("/signup", response_model=SignupResponse)
async def signup(
    token_payload: TokenPayload = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Validate the Supabase JWT and return the user ID
    
    This endpoint is called after the user has signed up with Supabase.
    It validates the JWT token and returns the user ID.
    
    The frontend can use this to determine if the user is new or existing
    based on the is_new flag in the response.
    """
    user_id = token_payload.sub
    
    # Check if the user already has keys in our database
    # This determines if the user is new or existing
    from app.db.models import UserKeys
    existing_keys = db.query(UserKeys).filter(UserKeys.user_id == user_id).first()
    
    return SignupResponse(
        user_id=user_id,
        is_new=existing_keys is None
    )
