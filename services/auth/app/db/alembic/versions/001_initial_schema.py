"""Initial schema

Revision ID: 001
Revises: 
Create Date: 2025-05-05

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create user_keys table
    op.create_table(
        'user_keys',
        sa.Column('user_id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('algorithm', sa.String(), default='x25519-kyber768-hybrid'),
        sa.Column('public_key', sa.Text(), nullable=False),
        sa.Column('encrypted_private_key', sa.Text(), nullable=False),
        sa.Column('created_at', sa.TIMESTAMP(timezone=True), server_default=sa.text('now()'))
    )
    
    # Create recovery_shares table
    op.create_table(
        'recovery_shares',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('user_keys.user_id')),
        sa.Column('share', sa.Text(), nullable=False),
        sa.Column('created_at', sa.TIMESTAMP(timezone=True), server_default=sa.text('now()'))
    )
    
    # Add indexes
    op.create_index('ix_recovery_shares_user_id', 'recovery_shares', ['user_id'])


def downgrade() -> None:
    # Drop tables in reverse order
    op.drop_table('recovery_shares')
    op.drop_table('user_keys')
