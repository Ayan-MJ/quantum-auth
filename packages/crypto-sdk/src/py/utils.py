"""
Utility functions for the Quantum Auth Crypto SDK
"""

import os
import base64
from typing import List, Tuple


def b64url_encode(data: bytes) -> str:
    """
    Encodes bytes to a base64url string
    
    Args:
        data: The bytes to encode
        
    Returns:
        A base64url encoded string
    """
    # Convert to base64
    base64_encoded = base64.b64encode(data).decode('ascii')
    # Convert to base64url (replace + with -, / with _, and remove trailing =)
    return base64_encoded.replace('+', '-').replace('/', '_').rstrip('=')


def b64url_decode(data: str) -> bytes:
    """
    Decodes a base64url string to bytes
    
    Args:
        data: The base64url string to decode
        
    Returns:
        The decoded bytes
    """
    # Convert from base64url to base64 (add padding if needed)
    base64_str = data.replace('-', '+').replace('_', '/')
    padding = len(base64_str) % 4
    if padding:
        base64_str += '=' * (4 - padding)
    
    # Decode base64 to bytes
    return base64.b64decode(base64_str)


def bytes_concat(*arrays: bytes) -> bytes:
    """
    Concatenates multiple byte arrays into a single byte array
    
    Args:
        *arrays: The byte arrays to concatenate
        
    Returns:
        A new byte array containing all the input arrays
    """
    return b''.join(arrays)


def bytes_split(data: bytes, *lengths: int) -> List[bytes]:
    """
    Splits a byte array into multiple parts at specified lengths
    
    Args:
        data: The bytes to split
        *lengths: The lengths of each part
        
    Returns:
        A list of byte arrays
        
    Raises:
        ValueError: If the sum of lengths doesn't match the data length
    """
    total_length = sum(lengths)
    if total_length != len(data):
        raise ValueError(f"Sum of lengths ({total_length}) doesn't match data length ({len(data)})")
    
    result = []
    offset = 0
    
    for length in lengths:
        result.append(data[offset:offset + length])
        offset += length
    
    return result


def get_random_bytes(length: int) -> bytes:
    """
    Generates cryptographically secure random bytes
    
    Args:
        length: The number of bytes to generate
        
    Returns:
        A byte array of random bytes
    """
    return os.urandom(length)
