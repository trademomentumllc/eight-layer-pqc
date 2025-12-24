"""
Unit tests for ML-DSA-87 (NIST FIPS 204)
All layers using signatures
"""

import pytest

# Try to import pqcrypto, skip tests if not available
try:
    from pqcrypto.sign.dilithium5 import generate_keypair, sign, verify
    PQCRYPTO_AVAILABLE = True
except ImportError:
    PQCRYPTO_AVAILABLE = False
    generate_keypair = None
    sign = None
    verify = None

pytestmark = pytest.mark.skipif(
    not PQCRYPTO_AVAILABLE,
    reason="pqcrypto not installed - skipping PQC tests"
)


def test_ml_dsa_keypair_generation():
    """Test ML-DSA-87 keypair generation"""
    public_key, secret_key = generate_keypair()
    assert len(public_key) > 0
    assert len(secret_key) > 0


def test_ml_dsa_sign_verify():
    """Test ML-DSA-87 sign/verify round-trip"""
    public_key, secret_key = generate_keypair()
    message = b"Eight-Layer Quantum-Hardened Architecture v2.0"

    # Sign
    signature = sign(message, secret_key)
    assert len(signature) > 0

    # Verify
    try:
        verify(signature, message, public_key)
    except Exception as e:
        pytest.fail(f"Signature verification failed: {e}")


def test_ml_dsa_tamper_detection():
    """Test ML-DSA-87 detects message tampering"""
    public_key, secret_key = generate_keypair()
    message = b"Original message"
    tampered = b"Tampered message"

    signature = sign(message, secret_key)

    # Should fail on tampered message
    with pytest.raises(Exception):
        verify(signature, tampered, public_key)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
