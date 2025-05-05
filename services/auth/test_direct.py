"""
Direct test of the security module functions
"""
from app.core.simple_sharing import split_secret, recover_secret, verify_shares

def test_direct():
    """Test the simple_sharing module directly"""
    # Test parameters
    secret = "my-super-secret-key"
    threshold = 3
    num_shares = 5
    
    # Generate shares
    shares = split_secret(secret, threshold, num_shares)
    print(f"Generated shares: {shares}")
    
    # Verify number of shares
    assert len(shares) == num_shares
    
    # Test with threshold shares
    threshold_shares = shares[:threshold]
    print(f"Using threshold shares: {threshold_shares}")
    
    # Verify that we can recover the secret with threshold shares
    assert verify_shares(threshold_shares) is True
    
    # Test with insufficient shares
    insufficient_shares = shares[:threshold-1]
    print(f"Using insufficient shares: {insufficient_shares}")
    assert verify_shares(insufficient_shares) is False
    
    # Test with invalid shares
    invalid_shares = ["invalid1", "invalid2", "invalid3"]
    print(f"Using invalid shares: {invalid_shares}")
    assert verify_shares(invalid_shares) is False
    
    print("All tests passed!")

if __name__ == "__main__":
    test_direct()
