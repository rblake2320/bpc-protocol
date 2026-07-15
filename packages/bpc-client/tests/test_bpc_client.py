"""
Tests for bpc-client Python package.

Covers:
- Keypair generation
- Body hash computation
- HMAC secret derivation
- Request signing (canonical payload + ECDSA)
- Signature verification (using @bpc/core-compatible logic)
- BPCClient HTTP request signing
- CLI commands (mocked)
- MCP tool dispatch
"""

import base64
import hashlib
import hmac
import json
import uuid
import time
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from bpc_client.crypto import (
    generate_keypair,
    compute_body_hash,
    derive_secret_key,
    derive_secret_hmac,
    validate_secret,
    sign_request,
    _b64url,
)
from bpc_client.client import BPCClient, BPCPair, BPCError, BPCAuthError, BPCPairLockedError
from bpc_client.mcp.server import handle_tool_call, TOOLS
from bpc_client.runtime_capture import (
    collect_runtime_metadata,
    sanitize_capture_value,
    set_key_generation_capture_sink,
)


# ── Crypto tests ──────────────────────────────────────────────────────────────

class TestKeypairGeneration:
    def test_generates_keypair(self):
        kp = generate_keypair()
        assert "private_key" in kp
        assert "public_key_jwk" in kp
        assert "fingerprint" in kp

    def test_public_key_jwk_has_required_fields(self):
        kp = generate_keypair()
        jwk = kp["public_key_jwk"]
        assert jwk["kty"] == "EC"
        assert jwk["crv"] == "P-256"
        assert "x" in jwk
        assert "y" in jwk

    def test_fingerprint_is_20_chars(self):
        kp = generate_keypair()
        assert len(kp["fingerprint"]) == 20

    def test_each_keypair_is_unique(self):
        kp1 = generate_keypair()
        kp2 = generate_keypair()
        assert kp1["fingerprint"] != kp2["fingerprint"]
        assert kp1["public_key_jwk"]["x"] != kp2["public_key_jwk"]["x"]

    def test_key_generation_capture_is_opt_in_and_redacted(self):
        events = []
        set_key_generation_capture_sink(events.append)
        try:
            kp = generate_keypair(
                runtime_metadata={"tool": "codex", "model": "gpt-5.5", "sessionId": "session-test"},
                capture_details={"privateKey": "must-not-leak", "apiToken": "must-not-leak"},
            )
        finally:
            set_key_generation_capture_sink(None)

        assert len(events) == 1
        assert events[0]["event"] == "bpc.python.keypair.generated"
        assert events[0]["keyFingerprint"] == kp["fingerprint"]
        assert events[0]["runtime"]["model"] == "gpt-5.5"
        serialized = json.dumps(events[0])
        assert "must-not-leak" not in serialized
        assert "[REDACTED]" in serialized


class TestRuntimeCapture:
    def test_collects_runtime_metadata_from_env(self, monkeypatch):
        monkeypatch.setenv("AI_RUNTIME_MODEL", "gpt-5.5")
        monkeypatch.setenv("AI_RUNTIME_SESSION_ID", "runtime-session-123")
        runtime = collect_runtime_metadata()
        assert runtime["model"] == "gpt-5.5"
        assert runtime["sessionId"] == "runtime-session-123"

    def test_sanitize_redacts_nested_secret_fields(self):
        sanitized = sanitize_capture_value(
            {"ok": "visible", "nested": {"sharedSecret": "hidden", "rawKey": "hidden"}}
        )
        serialized = json.dumps(sanitized)
        assert "visible" in serialized
        assert "hidden" not in serialized


class TestBodyHash:
    def test_empty_body_hash(self):
        h = compute_body_hash(None)
        assert h.startswith("sha256:")
        # SHA-256 of empty string
        expected = "sha256:" + _b64url(hashlib.sha256(b"").digest())
        assert h == expected

    def test_body_hash_with_content(self):
        body = b'{"key":"value"}'
        h = compute_body_hash(body)
        assert h.startswith("sha256:")
        expected = "sha256:" + _b64url(hashlib.sha256(body).digest())
        assert h == expected

    def test_different_bodies_produce_different_hashes(self):
        h1 = compute_body_hash(b"body1")
        h2 = compute_body_hash(b"body2")
        assert h1 != h2


class TestHMACDerivation:
    def test_hmac_produces_43_chars(self):
        result = derive_secret_hmac("MySecret1!", str(uuid.uuid4()), int(time.time() * 1000))
        assert len(result) == 43

    def test_hmac_is_deterministic(self):
        nonce = str(uuid.uuid4())
        ts = int(time.time() * 1000)
        r1 = derive_secret_hmac("MySecret1!", nonce, ts)
        r2 = derive_secret_hmac("MySecret1!", nonce, ts)
        assert r1 == r2

    def test_different_nonces_produce_different_hmacs(self):
        ts = int(time.time() * 1000)
        r1 = derive_secret_hmac("MySecret1!", str(uuid.uuid4()), ts)
        r2 = derive_secret_hmac("MySecret1!", str(uuid.uuid4()), ts)
        assert r1 != r2

    def test_hmac_matches_manual_calculation(self):
        secret = "MySecret1!"
        nonce = "test-nonce-123"
        ts = 1700000000000
        message = (nonce + str(ts)).encode()
        derived = base64.urlsafe_b64decode(derive_secret_key(secret) + "=")
        expected = _b64url(hmac.new(derived, message, hashlib.sha256).digest())
        result = derive_secret_hmac(secret, nonce, ts)
        assert result == expected

    def test_registration_secret_policy_rejects_weak_values(self):
        with pytest.raises(ValueError):
            validate_secret("weak")

    def test_registration_secret_policy_accepts_reference_value(self):
        validate_secret("ValidRegistration1!@")


class TestRequestSigning:
    def setup_method(self):
        self.kp = generate_keypair()
        self.private_key = self.kp["private_key"]

    def test_sign_request_returns_four_headers(self):
        headers = sign_request(self.private_key, "pair_abc", "MySecret1!", "GET", "/api/data")
        assert "X-BPC-Pair-ID" in headers
        assert "X-BPC-Signature" in headers
        assert "X-BPC-Signed-Data" in headers
        assert "X-BPC-Version" in headers

    def test_version_header_is_1_0(self):
        headers = sign_request(self.private_key, "pair_abc", "MySecret1!", "GET", "/api/data")
        assert headers["X-BPC-Version"] == "1.0"

    def test_pair_id_in_header(self):
        headers = sign_request(self.private_key, "pair_xyz", "MySecret1!", "GET", "/api/data")
        assert headers["X-BPC-Pair-ID"] == "pair_xyz"

    def test_signed_data_decodes_to_valid_canonical_payload(self):
        headers = sign_request(self.private_key, "pair_abc", "MySecret1!", "POST", "/api/items", body=b'{"x":1}')
        signed_data = headers["X-BPC-Signed-Data"]
        # Add padding
        padding = 4 - len(signed_data) % 4
        if padding != 4:
            signed_data += "=" * padding
        canonical = json.loads(base64.urlsafe_b64decode(signed_data))

        assert canonical["version"] == "1.0"
        assert canonical["method"] == "POST"
        assert canonical["path"] == "/api/items"
        assert canonical["pair_id"] == "pair_abc"
        assert "nonce" in canonical
        assert "timestamp" in canonical
        assert "body_hash" in canonical
        assert "secret_hmac" in canonical

    def test_canonical_payload_keys_are_sorted(self):
        headers = sign_request(self.private_key, "pair_abc", "MySecret1!", "GET", "/api/data")
        signed_data = headers["X-BPC-Signed-Data"]
        padding = 4 - len(signed_data) % 4
        if padding != 4:
            signed_data += "=" * padding
        canonical_str = base64.urlsafe_b64decode(signed_data).decode()
        # Keys should appear in alphabetical order
        keys = list(json.loads(canonical_str).keys())
        assert keys == sorted(keys)

    def test_ecdsa_signature_verifiable_with_public_key(self):
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
        from cryptography.hazmat.primitives.hashes import SHA256

        headers = sign_request(self.private_key, "pair_abc", "MySecret1!", "GET", "/api/data")
        signed_data_b64 = headers["X-BPC-Signed-Data"]
        sig_b64 = headers["X-BPC-Signature"]

        # Decode signed data
        padding = 4 - len(signed_data_b64) % 4
        if padding != 4:
            signed_data_b64 += "=" * padding
        canonical_bytes = base64.urlsafe_b64decode(signed_data_b64)

        # Decode signature
        padding = 4 - len(sig_b64) % 4
        if padding != 4:
            sig_b64 += "=" * padding
        sig_bytes = base64.urlsafe_b64decode(sig_b64)

        # Verify with public key — should not raise
        public_key = self.kp["private_key"].public_key()
        assert len(sig_bytes) == 64
        public_key.verify(
            encode_dss_signature(
                int.from_bytes(sig_bytes[:32], "big"),
                int.from_bytes(sig_bytes[32:], "big"),
            ),
            canonical_bytes,
            ECDSA(SHA256()),
        )

    def test_each_request_has_unique_nonce(self):
        h1 = sign_request(self.private_key, "pair_abc", "MySecret1!", "GET", "/api/data")
        h2 = sign_request(self.private_key, "pair_abc", "MySecret1!", "GET", "/api/data")
        assert h1["X-BPC-Signed-Data"] != h2["X-BPC-Signed-Data"]


# ── BPCClient tests ───────────────────────────────────────────────────────────

class TestBPCClientConstruction:
    def _make_pair(self) -> BPCPair:
        from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
        kp = generate_keypair()
        pem = kp["private_key"].private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
        return BPCPair(
            pair_id="pair_test_001",
            secret="MySecret1!",
            private_key_pem=pem,
            name="test-pair",
            scope="read-write",
            base_url="https://api.example.com",
        )

    def test_client_stores_pair_id(self):
        pair = self._make_pair()
        client = BPCClient(pair)
        assert client.pair_id == "pair_test_001"

    def test_client_stores_pair_name(self):
        pair = self._make_pair()
        client = BPCClient(pair)
        assert client.pair_name == "test-pair"

    def test_base_url_strips_trailing_slash(self):
        pair = self._make_pair()
        client = BPCClient(pair, base_url="https://api.example.com/")
        assert client._base_url == "https://api.example.com"

    def test_bpc_headers_added_to_get_request(self):
        pair = self._make_pair()
        client = BPCClient(pair)

        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch.object(client._http, "request", return_value=mock_response) as mock_req:
            client.get("/api/data")
            call_kwargs = mock_req.call_args
            headers = call_kwargs[1]["headers"]
            assert "X-BPC-Pair-ID" in headers
            assert "X-BPC-Signature" in headers
            assert "X-BPC-Signed-Data" in headers
            assert "X-BPC-Version" in headers

    def test_401_raises_bpc_auth_error(self):
        pair = self._make_pair()
        client = BPCClient(pair)

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.json.return_value = {"error": {"code": "signature_invalid", "message": "bad sig"}}
        mock_response.text = "bad sig"

        with patch.object(client._http, "request", return_value=mock_response):
            with pytest.raises(BPCAuthError):
                client.get("/api/data")

    def test_pair_locked_raises_bpc_pair_locked_error(self):
        pair = self._make_pair()
        client = BPCClient(pair)

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.json.return_value = {"error": {"code": "pair_locked_out", "message": "locked"}}
        mock_response.text = "locked"

        with patch.object(client._http, "request", return_value=mock_response):
            with pytest.raises(BPCPairLockedError):
                client.get("/api/data")

    def test_post_with_json_body_sets_content_type(self):
        pair = self._make_pair()
        client = BPCClient(pair)

        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch.object(client._http, "request", return_value=mock_response) as mock_req:
            client.post("/api/items", json={"name": "test"})
            call_kwargs = mock_req.call_args
            headers = call_kwargs[1]["headers"]
            assert headers.get("Content-Type") == "application/json"

    def test_registration_sends_derived_key_not_plaintext_secret(self):
        response = MagicMock()
        response.status_code = 201
        response.json.return_value = {"pairId": "pair_registered"}
        secret = "ValidRegistration1!@"
        with patch("bpc_client.client.httpx.post", return_value=response) as post:
            client = BPCClient.register(
                "https://api.example.com", "registered", secret, save=False,
            )
        payload = post.call_args.kwargs["json"]
        assert client.pair_id == "pair_registered"
        assert "secret" not in payload
        assert payload["secretHash"] == derive_secret_key(secret)

    def test_rotation_uses_old_key_to_bind_new_key_and_pair_id(self):
        pair = self._make_pair()
        client = BPCClient(pair)
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {"newPairId": "pair_rotated_002"}

        with patch.object(client._http, "post", return_value=response) as post, \
             patch.object(client, "_save_pair"):
            rotated = client.rotate()

        request = post.call_args.kwargs["json"]
        canonical = base64.urlsafe_b64decode(
            request["signedData"] + "=" * ((4 - len(request["signedData"]) % 4) % 4)
        )
        signature_bytes = base64.urlsafe_b64decode(
            request["signature"] + "=" * ((4 - len(request["signature"]) % 4) % 4)
        )
        pair._private_key.public_key().verify(
            encode_dss_signature(
                int.from_bytes(signature_bytes[:32], "big"),
                int.from_bytes(signature_bytes[32:], "big"),
            ),
            canonical,
            ECDSA(SHA256()),
        )
        payload = json.loads(canonical)
        assert payload["old_pair_id"] == pair.pair_id
        assert payload["purpose"] == "rotation"
        assert json.loads(payload["new_pub_jwk_json"]) == request["newPubJwk"]
        assert rotated.pair_id == "pair_rotated_002"
        assert rotated._pair.secret == pair.secret

    def test_corrupt_saved_pair_file_fails_closed(self, tmp_path, monkeypatch):
        pair_file = tmp_path / "pairs.json"
        pair_file.write_text("{not-json")
        monkeypatch.setattr(BPCClient, "PAIRS_FILE", pair_file)
        with pytest.raises(BPCError) as exc:
            BPCClient._load_pairs_file()
        assert exc.value.code == "pair_store_corrupt"

    def test_revocation_requires_admin_credential(self, monkeypatch):
        monkeypatch.delenv("BPC_ADMIN_TOKEN", raising=False)
        client = BPCClient(self._make_pair())
        with pytest.raises(BPCError) as exc:
            client.revoke()
        assert exc.value.code == "admin_auth_required"

    def test_revocation_sends_admin_credential_and_removes_local_pair(self):
        client = BPCClient(self._make_pair())
        response = MagicMock()
        response.status_code = 200
        with patch.object(client._http, "post", return_value=response) as post, \
             patch.object(client, "_load_pairs_file", return_value={client.pair_name: {}}), \
             patch.object(client, "_write_pairs_file") as write:
            client.revoke(admin_token="admin-test-token")
        assert post.call_args.kwargs["headers"]["Authorization"] == "Bearer admin-test-token"
        assert post.call_args.kwargs["json"] == {"pairId": client.pair_id}
        write.assert_called_once_with({})


# ── MCP tool tests ────────────────────────────────────────────────────────────

class TestMCPTools:
    def test_tools_list_has_seven_tools(self):
        assert len(TOOLS) == 7

    def test_all_tools_have_required_fields(self):
        for tool in TOOLS:
            assert "name" in tool
            assert "description" in tool
            assert "inputSchema" in tool

    def test_bpc_list_pairs_returns_json(self):
        with patch("bpc_client.client.BPCClient._load_pairs_file", return_value={}):
            result = handle_tool_call("bpc_list_pairs", {})
            data = json.loads(result)
            assert isinstance(data, list)

    def test_bpc_pair_info_unknown_pair(self):
        with patch("bpc_client.client.BPCClient._load_pairs_file", return_value={}):
            result = handle_tool_call("bpc_pair_info", {"name": "nonexistent"})
            data = json.loads(result)
            assert "error" in data

    def test_unknown_tool_returns_error(self):
        result = handle_tool_call("nonexistent_tool", {})
        data = json.loads(result)
        assert "error" in data
