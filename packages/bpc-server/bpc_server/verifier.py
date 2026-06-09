"""
BPCVerifier — implements the 12-step BPC verification pipeline (spec v1.0).

Steps:
1.  Rate limit check (delegated to caller)
2.  Headers present
3.  Pair exists and is active
4.  Pair not locked out
5.  Decode and parse canonical payload
6.  Protocol version check
7.  Timestamp within window
8.  Nonce not seen before
9.  Method and path match
10. Body hash match
11. Verify ECDSA signature
12. Scope enforcement
"""

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePublicKey, SECP256R1
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend

from .registry import PairRecord, InMemoryPairRegistry
from .nonce_store import InMemoryNonceStore


def _b64url_decode(s: str) -> bytes:
    """Decode base64url with padding."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _import_public_key_jwk(jwk: dict) -> EllipticCurvePublicKey:
    """Import an ECDSA P-256 public key from JWK format."""
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePublicNumbers,
        SECP256R1,
    )
    x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
    y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
    numbers = EllipticCurvePublicNumbers(x=x, y=y, curve=SECP256R1())
    return numbers.public_key(default_backend())


@dataclass
class BPCVerificationResult:
    ok: bool
    pair_id: Optional[str] = None
    pair: Optional[PairRecord] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None

    @classmethod
    def success(cls, pair_id: str, pair: PairRecord) -> "BPCVerificationResult":
        return cls(ok=True, pair_id=pair_id, pair=pair)

    @classmethod
    def failure(cls, code: str, message: str) -> "BPCVerificationResult":
        return cls(ok=False, error_code=code, error_message=message)


# Scope → allowed HTTP methods
SCOPE_METHODS = {
    "read": {"GET", "HEAD", "OPTIONS"},
    "read-write": {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"},
    "admin": {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"},
}


class BPCVerifier:
    """
    Stateless BPC verifier. Inject a registry and nonce store.

    Usage:
        verifier = BPCVerifier(registry=InMemoryPairRegistry(), nonce_store=InMemoryNonceStore())
        result = verifier.verify(
            headers=request.headers,
            method=request.method,
            path=request.path,
            body=await request.body(),
        )
        if not result.ok:
            return 401, result.error_code
    """

    def __init__(
        self,
        registry=None,
        nonce_store=None,
        sig_window_ms: int = 60_000,
        lockout_count: int = 10,
    ):
        self.registry = registry or InMemoryPairRegistry()
        self.nonce_store = nonce_store or InMemoryNonceStore()
        self.sig_window_ms = sig_window_ms
        self.lockout_count = lockout_count

    def verify(
        self,
        headers: dict,
        method: str,
        path: str,
        body: Optional[bytes] = None,
    ) -> BPCVerificationResult:
        """Run the full 12-step BPC verification pipeline."""

        # Step 2: Headers present
        required = ["X-BPC-Pair-ID", "X-BPC-Signature", "X-BPC-Signed-Data", "X-BPC-Version"]
        # Case-insensitive header lookup
        headers_lower = {k.lower(): v for k, v in headers.items()}
        for h in required:
            if h.lower() not in headers_lower:
                return BPCVerificationResult.failure("missing_headers", f"Missing header: {h}")

        pair_id = headers_lower["x-bpc-pair-id"]
        signature_b64 = headers_lower["x-bpc-signature"]
        signed_data_b64 = headers_lower["x-bpc-signed-data"]
        version = headers_lower["x-bpc-version"]

        # Step 3: Pair exists and is active
        pair = self.registry.get(pair_id)
        if pair is None:
            return BPCVerificationResult.failure("unknown_pair", f"Unknown pair: {pair_id}")
        if pair.status == "revoked":
            return BPCVerificationResult.failure("pair_revoked", "Pair has been revoked")
        if pair.expires_at and pair.expires_at < time.time():
            return BPCVerificationResult.failure("pair_expired", "Pair has expired")

        # Step 4: Pair not locked out
        if pair.failed_sigs >= self.lockout_count:
            return BPCVerificationResult.failure(
                "pair_locked_out", f"Pair locked after {pair.failed_sigs} failures"
            )

        # Step 5: Decode and parse canonical payload
        try:
            canonical_bytes = _b64url_decode(signed_data_b64)
            payload = json.loads(canonical_bytes)
        except Exception as e:
            return BPCVerificationResult.failure("invalid_signed_data", f"Cannot decode signed data: {e}")

        # Step 6: Protocol version check
        if payload.get("version") != "1.0":
            return BPCVerificationResult.failure(
                "unsupported_version", f"Unsupported version: {payload.get('version')}"
            )

        # Step 7: Timestamp within window
        now_ms = int(time.time() * 1000)
        ts = payload.get("timestamp", 0)
        if abs(now_ms - ts) > self.sig_window_ms:
            self.registry.increment_failed_sigs(pair_id)
            return BPCVerificationResult.failure(
                "timestamp_expired",
                f"Timestamp {ts} is outside ±{self.sig_window_ms}ms window",
            )

        # Step 8: Nonce not seen before
        nonce = payload.get("nonce", "")
        if not self.nonce_store.consume(nonce, ttl_ms=self.sig_window_ms * 2 + 10_000):
            return BPCVerificationResult.failure("replay_detected", f"Nonce already consumed: {nonce}")

        # Step 9: Method and path match
        if payload.get("method") != method.upper():
            self.registry.increment_failed_sigs(pair_id)
            return BPCVerificationResult.failure(
                "method_path_mismatch",
                f"Method mismatch: payload={payload.get('method')} request={method.upper()}",
            )
        if payload.get("path") != path:
            self.registry.increment_failed_sigs(pair_id)
            return BPCVerificationResult.failure(
                "method_path_mismatch",
                f"Path mismatch: payload={payload.get('path')} request={path}",
            )

        # Step 10: Body hash match
        body_data = body or b""
        expected_hash = "sha256:" + base64.urlsafe_b64encode(
            hashlib.sha256(body_data).digest()
        ).rstrip(b"=").decode()[:32]
        if payload.get("body_hash") != expected_hash:
            self.registry.increment_failed_sigs(pair_id)
            return BPCVerificationResult.failure(
                "body_hash_mismatch",
                f"Body hash mismatch: expected={expected_hash} got={payload.get('body_hash')}",
            )

        # Step 11: Verify ECDSA signature
        try:
            public_key = _import_public_key_jwk(pair.public_key_jwk)
            sig_bytes = _b64url_decode(signature_b64)
            public_key.verify(sig_bytes, canonical_bytes, ECDSA(SHA256()))
        except InvalidSignature:
            self.registry.increment_failed_sigs(pair_id)
            return BPCVerificationResult.failure("signature_invalid", "ECDSA signature verification failed")
        except Exception as e:
            self.registry.increment_failed_sigs(pair_id)
            return BPCVerificationResult.failure("signature_invalid", f"Signature error: {e}")

        # Step 12: Scope enforcement
        allowed_methods = SCOPE_METHODS.get(pair.scope, set())
        if method.upper() not in allowed_methods:
            return BPCVerificationResult.failure(
                "scope_denied",
                f"Scope '{pair.scope}' does not allow {method.upper()}",
            )

        # All checks passed
        self.registry.reset_failed_sigs(pair_id)
        return BPCVerificationResult.success(pair_id=pair_id, pair=pair)
