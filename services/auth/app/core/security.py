"""
Security utilities for the Auth service
"""
from fastapi import HTTPException, status
from app.core.simple_sharing import split_secret, recover_secret, verify_shares as verify_shares_impl

# Maximum number of shares allowed
MAX_SHARES = 10

def generate_secret_shares(secret: str, threshold: int, num_shares: int) -> list[str]:
    """
    Generate Shamir secret shares for a secret
    
    Args:
        secret: The secret to share
        threshold: The minimum number of shares required to recover the secret
        num_shares: The total number of shares to generate
        
    Returns:
        A list of secret shares
    """
    # Validate parameters
    if threshold < 2:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Threshold must be at least 2"
        )
    
    if num_shares < threshold:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Number of shares must be at least equal to threshold"
        )
    
    if num_shares > MAX_SHARES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Number of shares cannot exceed {MAX_SHARES}"
        )
    
    try:
        # Generate shares
        shares = split_secret(secret, threshold, num_shares)
        return shares
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate secret shares: {str(e)}"
        )

def recover_secret_from_shares(shares: list[str]) -> str:
    """
    Recover a secret from Shamir secret shares
    
    Args:
        shares: The secret shares (either full shares or just the share parts)
        
    Returns:
        The recovered secret
    """
    # Validate parameters
    if len(shares) < 2:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least 2 shares are required to recover the secret"
        )
    
    try:
        # Recover secret
        secret = recover_secret(shares)
        return secret
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to recover secret: {str(e)}"
        )

def verify_shares(shares: list[str]) -> bool:
    """
    Verify that a set of shares are valid and can be used to recover a secret
    
    Args:
        shares: The secret shares (either full shares or just the share parts)
        
    Returns:
        True if the shares are valid and sufficient, False otherwise
    """
    return verify_shares_impl(shares)
