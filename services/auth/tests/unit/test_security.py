"""
Unit tests for security utilities
"""
import pytest
from fastapi import HTTPException

from app.core.security import generate_secret_shares, recover_secret_from_shares, verify_shares


class TestSecurity:
    """Test security utilities"""
    
    def test_generate_secret_shares(self):
        """Test generating secret shares"""
        # Test with valid parameters
        secret = "my-super-secret-key"
        threshold = 3
        num_shares = 5
        
        shares = generate_secret_shares(secret, threshold, num_shares)
        
        assert len(shares) == num_shares
        assert all(isinstance(share, str) for share in shares)
        
        # Verify we can recover the secret with exactly threshold shares
        recovered_secret = recover_secret_from_shares([share.split(":")[1] for share in shares[:threshold]])
        assert recovered_secret == secret
        
        # Verify we can recover with more than threshold shares
        recovered_secret = recover_secret_from_shares([share.split(":")[1] for share in shares])
        assert recovered_secret == secret
    
    def test_generate_secret_shares_invalid_params(self):
        """Test generating secret shares with invalid parameters"""
        secret = "my-super-secret-key"
        
        # Test with threshold < 2
        with pytest.raises(HTTPException) as excinfo:
            generate_secret_shares(secret, 1, 5)
        assert "Threshold must be at least 2" in str(excinfo.value.detail)
        
        # Test with num_shares < threshold
        with pytest.raises(HTTPException) as excinfo:
            generate_secret_shares(secret, 3, 2)
        assert "Number of shares must be at least equal to threshold" in str(excinfo.value.detail)
        
        # Test with num_shares > MAX_SHARES
        with pytest.raises(HTTPException) as excinfo:
            generate_secret_shares(secret, 3, 20)
        assert "Number of shares cannot exceed" in str(excinfo.value.detail)
    
    def test_recover_secret_from_shares(self):
        """Test recovering a secret from shares"""
        # Generate shares
        secret = "my-super-secret-key"
        threshold = 3
        num_shares = 5
        shares = generate_secret_shares(secret, threshold, num_shares)
        
        # Test with valid shares
        recovered_secret = recover_secret_from_shares([share.split(":")[1] for share in shares[:threshold]])
        assert recovered_secret == secret
        
        # Test with insufficient shares
        with pytest.raises(HTTPException) as excinfo:
            recover_secret_from_shares([share.split(":")[1] for share in shares[:threshold-1]])
        assert "At least 2 shares are required" in str(excinfo.value.detail)
        
        # Test with invalid shares
        with pytest.raises(HTTPException) as excinfo:
            recover_secret_from_shares(["invalid-share-1", "invalid-share-2", "invalid-share-3"])
        assert "Failed to recover secret" in str(excinfo.value.detail)
    
    def test_verify_shares(self):
        """Test verifying shares"""
        # Generate shares
        secret = "my-super-secret-key"
        threshold = 3
        num_shares = 5
        shares = generate_secret_shares(secret, threshold, num_shares)
        
        # Test with valid shares
        assert verify_shares([share.split(":")[1] for share in shares[:threshold]]) is True
        
        # Test with insufficient shares
        assert verify_shares([share.split(":")[1] for share in shares[:threshold-1]]) is False
        
        # Test with invalid shares
        assert verify_shares(["invalid-share-1", "invalid-share-2", "invalid-share-3"]) is False
