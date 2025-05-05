"""
tRPC router for Auth service
"""
from fastapi import Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional

from app.core.security import generate_secret_shares, recover_secret_from_shares, verify_shares
from app.core.supabase import TokenPayload, verify_token
from app.db.models import UserKeys, RecoveryShares
from app.db.session import get_db
from app.schemas.auth import SignupResponse
from app.schemas.keys import KeyEnvelope, KeyEnvelopeCreate
from app.schemas.recovery import RecoveryShareCreate, RecoveryShareResponse, RecoveryShareVerify, RecoveryKeyRequest, RecoveryKeyResponse


class TRPCRouter:
    """tRPC router for Auth service"""
    
    def __init__(self, db: AsyncSession = Depends(get_db)):
        self.db = db
    
    async def get_current_user(self, token: str) -> TokenPayload:
        """Get the current user from the token"""
        return await verify_token(token)
    
    async def signup(self, token: str) -> SignupResponse:
        """Sign up a user"""
        # Verify the token
        user = await self.get_current_user(token)
        
        # Check if the user already has keys
        result = await self.db.execute(
            "SELECT * FROM user_keys WHERE user_id = :user_id",
            {"user_id": user.sub}
        )
        existing_user = result.scalar_one_or_none()
        
        return SignupResponse(
            user_id=user.sub,
            is_new=existing_user is None
        )
    
    async def create_key(self, key_data: KeyEnvelopeCreate, token: str) -> KeyEnvelope:
        """Create a new key for a user"""
        # Verify the token
        user = await self.get_current_user(token)
        
        # Check if the user already has keys
        result = await self.db.execute(
            "SELECT * FROM user_keys WHERE user_id = :user_id",
            {"user_id": user.sub}
        )
        existing_key = result.scalar_one_or_none()
        
        if existing_key:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Key already exists for this user"
            )
        
        # Create the key
        await self.db.execute(
            """
            INSERT INTO user_keys (user_id, algorithm, public_key, encrypted_private_key)
            VALUES (:user_id, :algorithm, :public_key, :encrypted_private_key)
            """,
            {
                "user_id": user.sub,
                "algorithm": key_data.algorithm,
                "public_key": key_data.public_key,
                "encrypted_private_key": key_data.encrypted_private_key
            }
        )
        await self.db.commit()
        
        return KeyEnvelope(
            algorithm=key_data.algorithm,
            public_key=key_data.public_key,
            encrypted_private_key=key_data.encrypted_private_key
        )
    
    async def get_key(self, token: str) -> KeyEnvelope:
        """Get a user's key"""
        # Verify the token
        user = await self.get_current_user(token)
        
        # Get the key
        result = await self.db.execute(
            "SELECT * FROM user_keys WHERE user_id = :user_id",
            {"user_id": user.sub}
        )
        key = result.scalar_one_or_none()
        
        if not key:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Key not found for this user"
            )
        
        return KeyEnvelope(
            algorithm=key.algorithm,
            public_key=key.public_key,
            encrypted_private_key=key.encrypted_private_key
        )
    
    async def update_key(self, key_data: KeyEnvelopeCreate, token: str) -> KeyEnvelope:
        """Update a user's key"""
        # Verify the token
        user = await self.get_current_user(token)
        
        # Check if the user has a key
        result = await self.db.execute(
            "SELECT * FROM user_keys WHERE user_id = :user_id",
            {"user_id": user.sub}
        )
        existing_key = result.scalar_one_or_none()
        
        if not existing_key:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Key not found for this user"
            )
        
        # Update the key
        await self.db.execute(
            """
            UPDATE user_keys
            SET algorithm = :algorithm, public_key = :public_key, encrypted_private_key = :encrypted_private_key
            WHERE user_id = :user_id
            """,
            {
                "user_id": user.sub,
                "algorithm": key_data.algorithm,
                "public_key": key_data.public_key,
                "encrypted_private_key": key_data.encrypted_private_key
            }
        )
        await self.db.commit()
        
        return KeyEnvelope(
            algorithm=key_data.algorithm,
            public_key=key_data.public_key,
            encrypted_private_key=key_data.encrypted_private_key
        )
    
    async def create_recovery_shares(self, recovery_data: RecoveryShareCreate, token: str) -> RecoveryShareResponse:
        """Create recovery shares for a user"""
        # Verify the token
        user = await self.get_current_user(token)
        
        # Get the user's key
        result = await self.db.execute(
            "SELECT * FROM user_keys WHERE user_id = :user_id",
            {"user_id": user.sub}
        )
        key = result.scalar_one_or_none()
        
        if not key:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Key not found for this user"
            )
        
        # Generate the shares
        shares = generate_secret_shares(
            key.encrypted_private_key,
            recovery_data.threshold,
            recovery_data.num_shares
        )
        
        # Store the shares in the database
        for share in shares:
            await self.db.execute(
                """
                INSERT INTO recovery_shares (user_id, share)
                VALUES (:user_id, :share)
                """,
                {
                    "user_id": user.sub,
                    "share": share
                }
            )
        await self.db.commit()
        
        return RecoveryShareResponse(
            shares=shares,
            threshold=recovery_data.threshold
        )
    
    async def verify_recovery_shares(self, verify_data: RecoveryShareVerify) -> dict:
        """Verify recovery shares"""
        # Verify the shares
        valid = verify_shares(verify_data.shares)
        
        return {"valid": valid}
    
    async def recover_key(self, recover_data: RecoveryKeyRequest) -> RecoveryKeyResponse:
        """Recover a key using shares"""
        try:
            # Recover the encrypted private key
            encrypted_private_key = recover_secret_from_shares(recover_data.shares)
            
            # Get the user's key
            result = await self.db.execute(
                "SELECT * FROM user_keys WHERE user_id = :user_id",
                {"user_id": recover_data.user_id}
            )
            key = result.scalar_one_or_none()
            
            if not key:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            
            # Verify the recovered key matches the stored key
            if key.encrypted_private_key != encrypted_private_key:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Recovered key does not match stored key"
                )
            
            return RecoveryKeyResponse(
                algorithm=key.algorithm,
                public_key=key.public_key,
                encrypted_private_key=encrypted_private_key
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid shares: {str(e)}"
            )
