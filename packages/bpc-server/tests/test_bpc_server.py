"""
Tests for bpc-server Python package.

Covers:
- BPCVerifier: all 12 verification steps
- Replay attack prevention
- Pair lockout after failures
- Scope enforcement
- Adversarial inputs (tampered payload, wrong key, expired timestamp)
- InMemoryPairRegistry CRUD
- InMemoryNonceStore replay prevention
"""

import base64
import hashlib
import json
import time
import uuid
from unittest.mock import patch

import pytest

from bpc_server.verifier import BPCVerifier, BPCVerificationResult
from bpc_server.registry import InMemoryPairRegistry, PairRecord
from bpc_server.nonce_store import InMemoryNonceStore


# ── Test fixtures ─────────────────────────────────────────────────────────────

def make_pair_and_client():
    """Create a test pair and matching bpc_client for signing."""
    from bpc_client.crypto import generate_keypair
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

    kp = generate_keypair()
    private_key = kp["private_key"]
    pub_jwk = kp["public_key_jwk"]

    pair = PairRecord(
        pair_id="pair_test_001",
        name="test-client",
        scope="read-write",
        mode="development",
        public_key_jwk=pub_jwk,
        secret_hash="argon2id_placeholder",  # not used in Python verifier (HMAC-based)
        status="active",
    )

    return pair, private_key, "MySecret1!"


def make_verifier(pair: PairRecord = None):
    registry = InMemoryPairRegistry()
    nonce_store = InMemoryNonceStore()
    if pair:
        registry.register(pair)
    verifier = BPCVerifier(registry=registry, nonce_store=nonce_store, sig_window_ms=60_000)
    return verifier, registry, nonce_store


def sign_headers(private_key, pair_id: str, secret: str, method: str, path: str, body: bytes = None):
    from bpc_client.crypto import sign_request
    return sign_request(private_key, pair_id, secret, method, path, body)


# ── Registry tests ────────────────────────────────────────────────────────────

class TestInMemoryPairRegistry:
    def test_register_and_get(self):
        registry = InMemoryPairRegistry()
        pair = PairRecord("pair_1", "test", "read", "development", {}, "hash")
        registry.register(pair)
        assert registry.get("pair_1") is pair

    def test_get_unknown_returns_none(self):
        registry = InMemoryPairRegistry()
        assert registry.get("pair_unknown") is None

    def test_revoke_sets_status(self):
        registry = InMemoryPairRegistry()
        pair = PairRecord("pair_1", "test", "read", "development", {}, "hash")
        registry.register(pair)
        registry.revoke("pair_1")
        assert registry.get("pair_1").status == "revoked"

    def test_increment_failed_sigs(self):
        registry = InMemoryPairRegistry()
        pair = PairRecord("pair_1", "test", "read", "development", {}, "hash")
        registry.register(pair)
        registry.increment_failed_sigs("pair_1")
        registry.increment_failed_sigs("pair_1")
        assert registry.get("pair_1").failed_sigs == 2

    def test_reset_failed_sigs(self):
        registry = InMemoryPairRegistry()
        pair = PairRecord("pair_1", "test", "read", "development", {}, "hash")
        registry.register(pair)
        registry.increment_failed_sigs("pair_1")
        registry.reset_failed_sigs("pair_1")
        assert registry.get("pair_1").failed_sigs == 0


# ── Nonce store tests ─────────────────────────────────────────────────────────

class TestInMemoryNonceStore:
    def test_fresh_nonce_returns_true(self):
        store = InMemoryNonceStore()
        assert store.consume("nonce-1") is True

    def test_replay_nonce_returns_false(self):
        store = InMemoryNonceStore()
        store.consume("nonce-1")
        assert store.consume("nonce-1") is False

    def test_different_nonces_both_accepted(self):
        store = InMemoryNonceStore()
        assert store.consume("nonce-1") is True
        assert store.consume("nonce-2") is True

    def test_expired_nonce_can_be_reused(self):
        store = InMemoryNonceStore()
        store.consume("nonce-1", ttl_ms=1)  # 1ms TTL
        time.sleep(0.01)  # wait for expiry
        # After eviction, nonce should be gone
        assert store.consume("nonce-1") is True


# ── Verifier tests ────────────────────────────────────────────────────────────

class TestBPCVerifier:
    def setup_method(self):
        self.pair, self.private_key, self.secret = make_pair_and_client()
        self.verifier, self.registry, self.nonce_store = make_verifier(self.pair)

    def test_valid_get_request_passes(self):
        headers = sign_headers(self.private_key, self.pair.pair_id, self.secret, "GET", "/api/data")
        result = self.verifier.verify(headers, "GET", "/api/data")
        assert result.ok is True
        assert result.pair_id == self.pair.pair_id

    def test_valid_post_request_with_body_passes(self):
        body = b'{"name":"test"}'
        headers = sign_headers(self.private_key, self.pair.pair_id, self.secret, "POST", "/api/items", body)
        result = self.verifier.verify(headers, "POST", "/api/items", body=body)
        assert result.ok is True

    def test_missing_headers_fails(self):
        result = self.verifier.verify({}, "GET", "/api/data")
        assert result.ok is False
        assert result.error_code == "missing_headers"

    def test_unknown_pair_fails(self):
        headers = sign_headers(self.private_key, "pair_unknown", self.secret, "GET", "/api/data")
        result = self.verifier.verify(headers, "GET", "/api/data")
        assert result.ok is False
        assert result.error_code == "unknown_pair"

    def test_revoked_pair_fails(self):
        self.registry.revoke(self.pair.pair_id)
        headers = sign_headers(self.private_key, self.pair.pair_id, self.secret, "GET", "/api/data")
        result = self.verifier.verify(headers, "GET", "/api/data")
        assert result.ok is False
        assert result.error_code == "pair_revoked"

    def test_expired_pair_fails(self):
        self.pair.expires_at = time.time() - 1  # expired 1 second ago
        headers = sign_headers(self.private_key, self.pair.pair_id, self.secret, "GET", "/api/data")
        result = self.verifier.verify(headers, "GET", "/api/data")
        assert result.ok is False
        assert result.error_code == "pair_expired"

    def test_locked_pair_fails(self):
        self.pair.failed_sigs = 10  # at lockout threshold
        headers = sign_headers(self.private_key, self.pair.pair_id, self.secret, "GET", "/api/data")
        result = self.verifier.verify(headers, "GET", "/api/data")
        assert result.ok is False
        assert result.error_code == "pair_locked_out"

    def test_replay_attack_fails(self):
        headers = sign_headers(self.private_key, self.pair.pair_id, self.secret, "GET", "/api/data")
        # First request succeeds
        result1 = self.verifier.verify(headers, "GET", "/api/data")
        assert result1.ok is True
        # Replay fails
        result2 = self.verifier.verify(headers, "GET", "/api/data")
        assert result2.ok is False
        assert result2.error_code == "replay_detected"

    def test_expired_timestamp_fails(self):
        headers = sign_headers(self.private_key, self.pair.pair_id, self.secret, "GET", "/api/data")
        # Decode and tamper the timestamp
        signed_data = headers["X-BPC-Signed-Data"]
        padding = 4 - len(signed_data) % 4
        if padding != 4:
            signed_data += "=" * padding
        payload = json.loads(base64.urlsafe_b64decode(signed_data))
        payload["timestamp"] = int(time.time() * 1000) - 120_000  # 2 minutes ago

        # Re-encode the tampered payload (signature will be invalid, but timestamp check comes first)
        tampered = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        tampered_b64 = base64.urlsafe_b64encode(tampered.encode()).rstrip(b"=").decode()
        headers["X-BPC-Signed-Data"] = tampered_b64

        result = self.verifier.verify(headers, "GET", "/api/data")
        assert result.ok is False
        assert result.error_code == "timestamp_expired"

    def test_method_mismatch_fails(self):
        headers = sign_headers(self.private_key, self.pair.pair_id, self.secret, "GET", "/api/data")
        result = self.verifier.verify(headers, "POST", "/api/data")
        assert result.ok is False
        assert result.error_code == "method_path_mismatch"

    def test_path_mismatch_fails(self):
        headers = sign_headers(self.private_key, self.pair.pair_id, self.secret, "GET", "/api/data")
        result = self.verifier.verify(headers, "GET", "/api/other")
        assert result.ok is False
        assert result.error_code == "method_path_mismatch"

    def test_body_hash_mismatch_fails(self):
        body = b'{"name":"test"}'
        headers = sign_headers(self.private_key, self.pair.pair_id, self.secret, "POST", "/api/items", body)
        # Send different body
        result = self.verifier.verify(headers, "POST", "/api/items", body=b'{"name":"tampered"}')
        assert result.ok is False
        assert result.error_code == "body_hash_mismatch"

    def test_invalid_signature_fails(self):
        headers = sign_headers(self.private_key, self.pair.pair_id, self.secret, "GET", "/api/data")
        # Tamper the signature
        headers["X-BPC-Signature"] = headers["X-BPC-Signature"][:-4] + "AAAA"
        result = self.verifier.verify(headers, "GET", "/api/data")
        assert result.ok is False
        assert result.error_code == "signature_invalid"

    def test_scope_read_blocks_post(self):
        self.pair.scope = "read"
        headers = sign_headers(self.private_key, self.pair.pair_id, self.secret, "POST", "/api/items")
        result = self.verifier.verify(headers, "POST", "/api/items")
        assert result.ok is False
        assert result.error_code == "scope_denied"

    def test_scope_read_allows_get(self):
        self.pair.scope = "read"
        headers = sign_headers(self.private_key, self.pair.pair_id, self.secret, "GET", "/api/data")
        result = self.verifier.verify(headers, "GET", "/api/data")
        assert result.ok is True

    def test_scope_admin_allows_delete(self):
        self.pair.scope = "admin"
        headers = sign_headers(self.private_key, self.pair.pair_id, self.secret, "DELETE", "/api/items/1")
        result = self.verifier.verify(headers, "DELETE", "/api/items/1")
        assert result.ok is True

    def test_scope_read_write_blocks_delete(self):
        self.pair.scope = "read-write"
        headers = sign_headers(self.private_key, self.pair.pair_id, self.secret, "DELETE", "/api/items/1")
        result = self.verifier.verify(headers, "DELETE", "/api/items/1")
        assert result.ok is False
        assert result.error_code == "scope_denied"

    def test_failed_sig_increments_counter(self):
        headers = sign_headers(self.private_key, self.pair.pair_id, self.secret, "GET", "/api/data")
        headers["X-BPC-Signature"] = "invalid"
        self.verifier.verify(headers, "GET", "/api/data")
        assert self.registry.get(self.pair.pair_id).failed_sigs == 1

    def test_successful_verify_resets_failed_sig_counter(self):
        self.pair.failed_sigs = 3
        headers = sign_headers(self.private_key, self.pair.pair_id, self.secret, "GET", "/api/data")
        result = self.verifier.verify(headers, "GET", "/api/data")
        assert result.ok is True
        assert self.registry.get(self.pair.pair_id).failed_sigs == 0

    def test_case_insensitive_headers(self):
        headers = sign_headers(self.private_key, self.pair.pair_id, self.secret, "GET", "/api/data")
        # Lowercase all header keys
        lower_headers = {k.lower(): v for k, v in headers.items()}
        result = self.verifier.verify(lower_headers, "GET", "/api/data")
        assert result.ok is True
