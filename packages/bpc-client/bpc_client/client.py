"""
BPCClient — high-level Python client for BPC-protected APIs.

Handles:
- Pair registration (register_pair / register_direct for dev mode)
- Persistent pair storage (~/.bpc/pairs.json)
- Automatic request signing on every HTTP call
- Pair rotation
"""

import json
import os
from pathlib import Path
from typing import Optional, Any

import httpx

from .crypto import _b64url, derive_secret_key, generate_keypair, sign_request, validate_secret


class BPCError(Exception):
    """Base error for BPC protocol failures."""
    def __init__(self, message: str, code: str = "bpc_error", status: int = 0):
        super().__init__(message)
        self.code = code
        self.status = status


class BPCAuthError(BPCError):
    """Raised when BPC verification fails (signature invalid, pair revoked, etc.)."""
    pass


class BPCPairLockedError(BPCError):
    """Raised when the pair has been locked out due to too many failures."""
    pass


class BPCPair:
    """Represents a registered BPC pair (software key + pair ID + secret)."""

    def __init__(
        self,
        pair_id: str,
        secret: str,
        private_key_pem: str,
        name: str = "",
        scope: str = "read-write",
        base_url: str = "",
    ):
        self.pair_id = pair_id
        self.secret = secret
        self.name = name
        self.scope = scope
        self.base_url = base_url

        # Load private key from PEM
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        from cryptography.hazmat.backends import default_backend
        self._private_key = load_pem_private_key(
            private_key_pem.encode(), password=None, backend=default_backend()
        )
        self._private_key_pem = private_key_pem

    def to_dict(self) -> dict:
        return {
            "pair_id": self.pair_id,
            "secret": self.secret,
            "private_key_pem": self._private_key_pem,
            "name": self.name,
            "scope": self.scope,
            "base_url": self.base_url,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "BPCPair":
        return cls(
            pair_id=data["pair_id"],
            secret=data["secret"],
            private_key_pem=data["private_key_pem"],
            name=data.get("name", ""),
            scope=data.get("scope", "read-write"),
            base_url=data.get("base_url", ""),
        )


class BPCClient:
    """
    HTTP client that automatically signs every request with BPC.

    Usage:
        # Register a new pair (development mode — auto-approved)
        client = BPCClient.register(
            base_url="https://api.example.com",
            name="my-agent",
            secret="MySecret1!",
            mode="development",
        )

        # Make signed requests
        response = client.get("/api/data")
        response = client.post("/api/items", json={"name": "test"})

        # Load saved pair
        client = BPCClient.load(base_url="https://api.example.com", name="my-agent")
    """

    PAIRS_FILE = Path.home() / ".bpc" / "pairs.json"

    def __init__(self, pair: BPCPair, base_url: Optional[str] = None):
        self._pair = pair
        self._base_url = (base_url or pair.base_url).rstrip("/")
        self._http = httpx.Client(timeout=30.0)

    @classmethod
    def register(
        cls,
        base_url: str,
        name: str,
        secret: str,
        scope: str = "read-write",
        mode: str = "development",
        register_path: str = "/bpc/register",
        approve_path: str = "/bpc/approve",
        save: bool = True,
    ) -> "BPCClient":
        """
        Register a new BPC pair with the server.

        In development mode, the server auto-approves and returns the pair ID immediately.
        In production mode, the owner must approve via the admin UI before the pair is active.
        """
        try:
            validate_secret(secret)
        except ValueError as exc:
            raise BPCError(str(exc), code="invalid_secret") from exc
        kp = generate_keypair()

        from cryptography.hazmat.primitives.serialization import (
            Encoding, PrivateFormat, NoEncryption
        )
        private_key_pem = kp["private_key"].private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        ).decode()

        payload = {
            "name": name,
            "scope": scope,
            "mode": mode,
            "secretHash": derive_secret_key(secret),
            "pubJwk": kp["public_key_jwk"],
        }

        resp = httpx.post(f"{base_url.rstrip('/')}{register_path}", json=payload, timeout=30)
        if resp.status_code not in (200, 201):
            raise BPCError(
                f"Registration failed: {resp.text}",
                code="registration_failed",
                status=resp.status_code,
            )

        data = resp.json()

        # Development mode: server may return pairId directly
        pair_id = data.get("pairId") or data.get("pair_id")
        if not pair_id:
            # Production mode: need approval token
            token = data.get("approvalToken") or data.get("token")
            if not token:
                raise BPCError("No pairId or approvalToken in registration response")
            # Wait for approval (caller must poll or use approve_path)
            raise BPCError(
                f"Pair pending approval. Token: {token}. "
                "Call BPCClient.approve(base_url, token, ...) after owner approves.",
                code="pending_approval",
            )

        pair = BPCPair(
            pair_id=pair_id,
            secret=secret,
            private_key_pem=private_key_pem,
            name=name,
            scope=scope,
            base_url=base_url,
        )

        client = cls(pair, base_url)
        if save:
            client._save_pair(pair)
        return client

    @classmethod
    def load(cls, name: str, base_url: Optional[str] = None) -> "BPCClient":
        """Load a previously saved pair by name."""
        pairs = cls._load_pairs_file()
        if name not in pairs:
            raise BPCError(f"No saved pair named '{name}'. Run BPCClient.register() first.")
        pair = BPCPair.from_dict(pairs[name])
        return cls(pair, base_url or pair.base_url)

    @classmethod
    def from_pair(cls, pair: BPCPair, base_url: Optional[str] = None) -> "BPCClient":
        """Create a client from an existing BPCPair object."""
        return cls(pair, base_url)

    def _build_headers(self, method: str, path: str, body: Optional[bytes]) -> dict:
        return sign_request(
            private_key=self._pair._private_key,
            pair_id=self._pair.pair_id,
            secret=self._pair.secret,
            method=method,
            path=path,
            body=body,
        )

    def _handle_response(self, resp: httpx.Response) -> httpx.Response:
        if resp.status_code == 401:
            try:
                err = resp.json()
                code = err.get("error", {}).get("code", "auth_error")
                msg = err.get("error", {}).get("message", resp.text)
            except Exception:
                code, msg = "auth_error", resp.text
            if code == "pair_locked_out":
                raise BPCPairLockedError(msg, code=code, status=401)
            raise BPCAuthError(msg, code=code, status=401)
        if resp.status_code == 403:
            raise BPCAuthError(
                f"Scope denied: {resp.text}", code="scope_denied", status=403
            )
        return resp

    def request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[Any] = None,
        data: Optional[bytes] = None,
        params: Optional[dict] = None,
        headers: Optional[dict] = None,
        **kwargs,
    ) -> httpx.Response:
        """Make a BPC-signed HTTP request."""
        import json as _json

        body: Optional[bytes] = None
        extra_headers: dict = {}

        if json is not None:
            body = _json.dumps(json, separators=(",", ":")).encode()
            extra_headers["Content-Type"] = "application/json"
        elif data is not None:
            body = data

        bpc_headers = self._build_headers(method.upper(), path, body)
        all_headers = {**bpc_headers, **extra_headers, **(headers or {})}

        url = f"{self._base_url}{path}"
        resp = self._http.request(
            method,
            url,
            content=body,
            params=params,
            headers=all_headers,
            **kwargs,
        )
        return self._handle_response(resp)

    def get(self, path: str, **kwargs) -> httpx.Response:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs) -> httpx.Response:
        return self.request("POST", path, **kwargs)

    def put(self, path: str, **kwargs) -> httpx.Response:
        return self.request("PUT", path, **kwargs)

    def patch(self, path: str, **kwargs) -> httpx.Response:
        return self.request("PATCH", path, **kwargs)

    def delete(self, path: str, **kwargs) -> httpx.Response:
        return self.request("DELETE", path, **kwargs)

    def rotate(
        self,
        rotate_path: str = "/bpc/rotate",
    ) -> "BPCClient":
        """
        Rotate the pair key. The old private key authorizes the new public key.
        The existing registration secret is preserved by protocol v1.0.
        """
        kp = generate_keypair()
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PrivateFormat, NoEncryption
        )
        new_private_pem = kp["private_key"].private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        ).decode()

        import time
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        from cryptography.hazmat.primitives.hashes import SHA256

        timestamp = int(time.time() * 1000)
        rotation_payload = {
            "new_pub_jwk_json": json.dumps(kp["public_key_jwk"], separators=(",", ":")),
            "old_pair_id": self._pair.pair_id,
            "purpose": "rotation",
            "timestamp": timestamp,
        }
        canonical = json.dumps(rotation_payload, sort_keys=True, separators=(",", ":")).encode()
        der_signature = self._pair._private_key.sign(canonical, ECDSA(SHA256()))
        r, s = decode_dss_signature(der_signature)
        signature = _b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
        signed_data = _b64url(canonical)
        resp = self._http.post(
            f"{self._base_url}{rotate_path}",
            json={
                "oldPairId": self._pair.pair_id,
                "newPubJwk": kp["public_key_jwk"],
                "signature": signature,
                "signedData": signed_data,
                "timestamp": timestamp,
            },
        )
        if resp.status_code not in (200, 201):
            raise BPCError(f"Rotation failed: {resp.text}", code="rotation_failed")

        response_body = resp.json()
        new_pair_id = response_body.get("newPairId") or response_body.get("new_pair_id")
        if not new_pair_id:
            raise BPCError("Rotation response omitted newPairId", code="rotation_failed")

        new_pair = BPCPair(
            pair_id=new_pair_id,
            secret=self._pair.secret,
            private_key_pem=new_private_pem,
            name=self._pair.name,
            scope=self._pair.scope,
            base_url=self._base_url,
        )
        self._save_pair(new_pair)
        return BPCClient(new_pair, self._base_url)

    def revoke(self, revoke_path: str = "/bpc/revoke", admin_token: Optional[str] = None) -> None:
        """Revoke this pair using the server lifecycle-admin credential."""
        token = admin_token or os.environ.get("BPC_ADMIN_TOKEN")
        if not token:
            raise BPCError("BPC_ADMIN_TOKEN is required for revocation", code="admin_auth_required")
        resp = self._http.post(
            f"{self._base_url}{revoke_path}",
            json={"pairId": self._pair.pair_id},
            headers={"Authorization": f"Bearer {token}"},
        )
        if resp.status_code not in (200, 204):
            raise BPCError(f"Revocation failed: {resp.text}", code="revocation_failed")
        # Remove from local storage
        pairs = self._load_pairs_file()
        pairs.pop(self._pair.name, None)
        self._write_pairs_file(pairs)

    @property
    def pair_id(self) -> str:
        return self._pair.pair_id

    @property
    def pair_name(self) -> str:
        return self._pair.name

    # ── Storage helpers ──────────────────────────────────────────────────────

    def _save_pair(self, pair: BPCPair) -> None:
        pairs = self._load_pairs_file()
        pairs[pair.name] = pair.to_dict()
        self._write_pairs_file(pairs)

    @classmethod
    def _load_pairs_file(cls) -> dict:
        if not cls.PAIRS_FILE.exists():
            return {}
        try:
            return json.loads(cls.PAIRS_FILE.read_text())
        except Exception as exc:
            raise BPCError(f"Saved pair file is unreadable: {exc}", code="pair_store_corrupt") from exc

    @classmethod
    def _write_pairs_file(cls, pairs: dict) -> None:
        cls.PAIRS_FILE.parent.mkdir(parents=True, exist_ok=True)
        temp_path = cls.PAIRS_FILE.with_suffix(cls.PAIRS_FILE.suffix + ".tmp")
        temp_path.write_text(json.dumps(pairs, indent=2))
        temp_path.chmod(0o600)
        os.replace(temp_path, cls.PAIRS_FILE)
        cls.PAIRS_FILE.chmod(0o600)  # owner-only read/write
