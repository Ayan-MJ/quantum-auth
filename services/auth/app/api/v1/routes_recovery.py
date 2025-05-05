"""
Recovery routes for the Auth service
"""
from typing import Any, List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.security import generate_secret_shares, verify_shares
from app.core.supabase import get_current_user, TokenPayload
from app.db.models import RecoveryShares, UserKeys
from app.db.session import get_db
from app.schemas.recovery import (
    RecoveryShareCreate,
    RecoverySharesResponse,
    RecoveryShareVerify,
    RecoveryShareVerifyResponse,
)

router = APIRouter()


@router.post("/recovery/shares", response_model=RecoverySharesResponse)
async def create_recovery_shares(
    share_request: RecoveryShareCreate,
    token_payload: TokenPayload = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Any:
    """
    Create recovery shares for a user's private key
    
    This endpoint generates Shamir secret shares for the user's private key
    and stores them in the database.
    """
    user_id = token_payload.sub
    
    # Get the user's keys
    user_keys = db.query(UserKeys).filter(UserKeys.user_id == user_id).first()
    
    if not user_keys:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Keys not found for this user. Create keys first.",
        )
    
    # Delete any existing shares for this user
    db.query(RecoveryShares).filter(RecoveryShares.user_id == user_id).delete()
    
    # Generate new shares
    try:
        shares = generate_secret_shares(
            user_keys.encrypted_private_key,
            share_request.threshold,
            share_request.shares,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate shares: {str(e)}",
        )
    
    # Store shares in the database
    for share in shares:
        db_share = RecoveryShares(
            user_id=user_id,
            share=share,
        )
        db.add(db_share)
    
    db.commit()
    
    return RecoverySharesResponse(
        shares=shares,
        threshold=share_request.threshold,
        total=share_request.shares,
    )


@router.post("/recovery/verify", response_model=RecoveryShareVerifyResponse)
async def verify_recovery_shares(
    verify_request: RecoveryShareVerify,
    token_payload: TokenPayload = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Any:
    """
    Verify that a set of recovery shares are valid
    
    This endpoint checks if the provided shares can be combined to recover a secret.
    """
    # Verify the shares
    is_valid = verify_shares(verify_request.shares)
    
    if is_valid:
        return RecoveryShareVerifyResponse(
            valid=True,
            message="Shares are valid and can be combined to recover the secret",
        )
    else:
        return RecoveryShareVerifyResponse(
            valid=False,
            message="Shares are invalid or insufficient to recover the secret",
        )
