"""
BPC cryptographic primitives — Python implementation of BPC spec v1.0.

Implements:
- ECDSA P-256 keypair generation
- Canonical payload construction (alphabetically sorted JSON)
- HMAC-SHA-256 secret derivation
- SHA-256 body hashing
- ECDSA-SHA-256 request signing
"""

import base64
import hashlib
import hmac
import json
import uuid
import time
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    SECP256R1,
    generate_private_key,
)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from cryptography.hazmat.backends import default_backend

from .runtime_capture import emit_key_generation_capture


def _b64url(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def generate_keypair(runtime_metadata: dict | None = None, capture_details: dict | None = None) -> dict:
    """
    Generate an ECDSA P-256 keypair.

    Returns a dict with:
        private_key: EllipticCurvePrivateKey (keep secret, never transmit)
        public_key_jwk: dict  (JWK format, send to server during pairing)
        fingerprint: str      (first 20 chars of base64url(SHA-256(JWK)))
    """
    private_key = generate_private_key(SECP256R1(), default_backend())
    public_key = private_key.public_key()

    # Export public key as uncompressed point bytes (04 || x || y)
    pub_bytes = public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    x_bytes = pub_bytes[1:33]
    y_bytes = pub_bytes[33:65]

    pub_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(x_bytes),
        "y": _b64url(y_bytes),
    }

    # Fingerprint: base64url(SHA-256(sorted JSON of JWK))[:20]
    jwk_json = json.dumps(pub_jwk, sort_keys=True, separators=(",", ":"))
    fingerprint = _b64url(hashlib.sha256(jwk_json.encode()).digest())[:20]

    emit_key_generation_capture(
        {
            "protocol": "bpc",
            "packageName": "bpc-client",
            "event": "bpc.python.keypair.generated",
            "keyFingerprint": fingerprint,
            "algorithm": "ECDSA P-256",
            "extractable": True,
            "runtime": runtime_metadata or {},
            "details": {
                "publicKeyType": pub_jwk["kty"],
                "curve": pub_jwk["crv"],
                **(capture_details or {}),
            },
        }
    )

    return {
        "private_key": private_key,
        "public_key_jwk": pub_jwk,
        "fingerprint": fingerprint,
    }


def compute_body_hash(body: Optional[bytes]) -> str:
    """
    Compute BPC body hash: "sha256:" + base64url(SHA-256(body))[:32]
    For empty/None body, hash the empty string.
    """
    data = body if body else b""
    digest = hashlib.sha256(data).digest()
    return "sha256:" + _b64url(digest)[:32]


def derive_secret_hmac(secret: str, nonce: str, timestamp: int) -> str:
    """
    Derive per-request HMAC: base64url(HMAC-SHA-256(secret, nonce + str(timestamp)))
    Returns full 256-bit output (43 base64url chars).
    """
    message = (nonce + str(timestamp)).encode()
    key = secret.encode()
    digest = hmac.new(key, message, hashlib.sha256).digest()
    return _b64url(digest)


def sign_request(
    private_key: EllipticCurvePrivateKey,
    pair_id: str,
    secret: str,
    method: str,
    path: str,
    body: Optional[bytes] = None,
) -> dict:
    """
    Build and sign a BPC canonical payload for an HTTP request.

    Returns a dict of BPC headers to attach to the request:
        X-BPC-Pair-ID
        X-BPC-Signature
        X-BPC-Signed-Data
        X-BPC-Version
    """
    nonce = str(uuid.uuid4())
    timestamp = int(time.time() * 1000)  # Unix milliseconds
    body_hash = compute_body_hash(body)
    secret_hmac = derive_secret_hmac(secret, nonce, timestamp)

    # Canonical payload — keys sorted alphabetically per spec
    payload = {
        "body_hash": body_hash,
        "method": method.upper(),
        "nonce": nonce,
        "pair_id": pair_id,
        "path": path,
        "secret_hmac": secret_hmac,
        "timestamp": timestamp,
        "version": "1.0",
    }

    # Canonical JSON — sorted keys, no spaces
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    canonical_bytes = canonical.encode()

    # ECDSA-SHA-256 signature over canonical JSON
    signature_bytes = private_key.sign(canonical_bytes, ECDSA(SHA256()))
    signature = _b64url(signature_bytes)

    # Signed data = base64url(canonical JSON)
    signed_data = _b64url(canonical_bytes)

    return {
        "X-BPC-Pair-ID": pair_id,
        "X-BPC-Signature": signature,
        "X-BPC-Signed-Data": signed_data,
        "X-BPC-Version": "1.0",
    }
