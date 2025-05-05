"""
SQLAlchemy models for the Auth service
"""
import uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy import Column, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class UserKeys(Base):
    """
    Model for storing user encryption keys
    """
    __tablename__ = "user_keys"

    user_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    algorithm = Column(String, default="x25519-kyber768-hybrid")
    public_key = Column(Text, nullable=False)
    encrypted_private_key = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationship to recovery shares
    recovery_shares = relationship("RecoveryShares", back_populates="user_keys", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<UserKeys(user_id={self.user_id}, algorithm={self.algorithm})>"


class RecoveryShares(Base):
    """
    Model for storing Shamir secret shares for key recovery
    """
    __tablename__ = "recovery_shares"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("user_keys.user_id"))
    share = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationship to user keys
    user_keys = relationship("UserKeys", back_populates="recovery_shares")

    def __repr__(self):
        return f"<RecoveryShares(id={self.id}, user_id={self.user_id})>"
