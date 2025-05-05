"""
Key management routes for the Auth service
"""
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.supabase import get_current_user, TokenPayload
from app.db.models import UserKeys
from app.db.session import get_db
from app.schemas.keys import KeyEnvelope, KeyEnvelopeCreate, KeyEnvelopeResponse

router = APIRouter()


@router.post("/keys", response_model=KeyEnvelopeResponse)
async def create_keys(
    key_envelope: KeyEnvelopeCreate,
    token_payload: TokenPayload = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Any:
    """
    Create or update a user's key envelope
    
    This endpoint is called after the user has generated a key pair.
    It stores the key envelope in the database.
    """
    user_id = token_payload.sub
    
    # Check if the user already has keys
    existing_keys = db.query(UserKeys).filter(UserKeys.user_id == user_id).first()
    
    if existing_keys:
        # Update existing keys
        existing_keys.algorithm = key_envelope.algorithm
        existing_keys.public_key = key_envelope.public_key
        existing_keys.encrypted_private_key = key_envelope.encrypted_private_key
        db.commit()
        db.refresh(existing_keys)
        
        return KeyEnvelopeResponse(
            user_id=existing_keys.user_id,
            algorithm=existing_keys.algorithm,
            public_key=existing_keys.public_key,
            encrypted_private_key=existing_keys.encrypted_private_key,
            created_at=existing_keys.created_at,
        )
    else:
        # Create new keys
        new_keys = UserKeys(
            user_id=user_id,
            algorithm=key_envelope.algorithm,
            public_key=key_envelope.public_key,
            encrypted_private_key=key_envelope.encrypted_private_key,
        )
        db.add(new_keys)
        db.commit()
        db.refresh(new_keys)
        
        return KeyEnvelopeResponse(
            user_id=new_keys.user_id,
            algorithm=new_keys.algorithm,
            public_key=new_keys.public_key,
            encrypted_private_key=new_keys.encrypted_private_key,
            created_at=new_keys.created_at,
        )


@router.get("/keys/self", response_model=KeyEnvelopeResponse)
async def get_self_keys(
    token_payload: TokenPayload = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Any:
    """
    Get the current user's key envelope
    """
    user_id = token_payload.sub
    
    # Get the user's keys
    user_keys = db.query(UserKeys).filter(UserKeys.user_id == user_id).first()
    
    if not user_keys:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Keys not found for this user",
        )
    
    return KeyEnvelopeResponse(
        user_id=user_keys.user_id,
        algorithm=user_keys.algorithm,
        public_key=user_keys.public_key,
        encrypted_private_key=user_keys.encrypted_private_key,
        created_at=user_keys.created_at,
    )
