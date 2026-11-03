"""
Native interactsh client (no external binary required).

Implements the public interactsh protocol used by ProjectDiscovery:

1. generate an RSA-2048 key pair and a 20-char correlation id;
2. ``POST /register`` with the base64 PEM public key, secret and id;
3. build callback URLs as ``<correlation-id><nonce>.<server>``;
4. ``GET /poll?id=...&secret=...`` and decrypt AES-CTR payloads whose key is
   RSA-OAEP(SHA-256) encrypted.

The implementation mirrors ``pkg/client/client.go`` closely enough to work with
public and self-hosted servers.  ``cryptography`` and ``aiohttp`` are optional
at import time but required to actually use the transport.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import random
import secrets
import string
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from xoxss.oob.base import OOBHit, OOBSource, extract_marker

_ZBASE32 = "ybndrfg8ejkmcpqxot1uwisza345h769"
_XID_ALPHABET = "0123456789abcdefghijklmnopqrstuv"
_DEFAULT_SERVERS = ("oast.pro", "oast.live", "oast.site", "oast.online", "oast.fun")


def zbase32(data: bytes) -> str:
    """Encode bytes with z-base-32 (the alphabet interactsh uses)."""
    bits = 0
    value = 0
    out: List[str] = []
    for byte in data:
        value = (value << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append(_ZBASE32[(value >> bits) & 31])
    if bits:
        out.append(_ZBASE32[(value << (5 - bits)) & 31])
    return "".join(out)


def correlation_id() -> str:
    """Generate a 20-character interactsh correlation id (``[0-9a-v]``)."""
    return "".join(secrets.choice(_XID_ALPHABET) for _ in range(20))


def random_secret() -> str:
    return f"{secrets.token_hex(16)}-{secrets.token_hex(8)}"


def _require_crypto() -> Tuple[Any, Any, Any, Any, Any, Any]:
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except Exception as exc:  # pragma: no cover - optional dependency
        raise RuntimeError(
            "interactsh requires the 'cryptography' package (pip install cryptography)"
        ) from exc
    return hashes, serialization, padding, rsa, Cipher, (algorithms, modes)


def generate_keypair() -> Tuple[Any, str]:
    """Return ``(private_key, base64(PEM public key))``."""
    _, serialization, _, rsa, _, _ = _require_crypto()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # The Go client labels the PEM "RSA PUBLIC KEY" but stores PKIX bytes; use
    # the standard label here — parsers look at the DER, not the label.
    return private_key, base64.b64encode(public_pem).decode("ascii")


def encrypt_message(public_key: Any, plaintext: bytes) -> Tuple[str, str]:
    """Test helper: return ``(aes_key_b64, ciphertext_b64)`` for a message."""
    hashes, _, padding, _, Cipher, (algorithms, modes) = _require_crypto()
    key = os.urandom(32)
    iv = os.urandom(16)
    encryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    ciphertext = iv + encryptor.update(plaintext) + encryptor.finalize()
    wrapped = public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(wrapped).decode("ascii"), base64.b64encode(ciphertext).decode("ascii")


def decrypt_message(private_key: Any, aes_key_b64: str, ciphertext_b64: str) -> bytes:
    """Decrypt one interactsh ``data`` item."""
    hashes, _, padding, _, Cipher, (algorithms, modes) = _require_crypto()
    wrapped = base64.b64decode(aes_key_b64 or "")
    key = private_key.decrypt(
        wrapped,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    if len(key) not in (16, 24, 32):
        raise ValueError(f"unexpected AES key length: {len(key)}")
    ciphertext = base64.b64decode(ciphertext_b64 or "")
    if len(ciphertext) < 16:
        raise ValueError("ciphertext is shorter than the IV")
    iv, body = ciphertext[:16], ciphertext[16:]
    decryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
    return decryptor.update(body) + decryptor.finalize()


@dataclass
class InteractshConfig:
    server: str = "oast.pro"
    token: str = ""
    insecure: bool = False
    timeout: float = 15.0
    correlation_length: int = 20
    nonce_length: int = 20


class InteractshClient(OOBSource):
    """A native interactsh transport."""

    name = "interactsh"

    def __init__(
        self,
        console: Any,
        *,
        server: str = "oast.pro",
        token: str = "",
        insecure: bool = False,
        timeout: float = 15.0,
        proxy: Optional[str] = None,
    ):
        self.console = console
        self.config = InteractshConfig(server=server or "oast.pro", token=token or "", insecure=insecure, timeout=max(5.0, timeout))
        self.proxy = proxy
        self.private_key: Any = None
        self.public_key_b64 = ""
        self.correlation = correlation_id()
        self.secret = random_secret()
        self.server_url = ""
        self.host = ""
        self.session: Any = None
        self._labels: Dict[str, str] = {}
        self._registered = False
        self._last_error = ""

    # -- lifecycle ---------------------------------------------------------------
    @staticmethod
    def _normalise_servers(value: str) -> List[str]:
        servers: List[str] = []
        for item in (value or "").split(","):
            item = item.strip()
            if not item:
                continue
            if not item.startswith(("http://", "https://")):
                item = "https://" + item
            servers.append(item.rstrip("/"))
        return servers or ["https://oast.pro"]

    async def start(self) -> bool:
        try:
            import aiohttp
        except Exception as exc:  # pragma: no cover
            self._last_error = f"aiohttp is required: {exc}"
            return False
        try:
            self.private_key, self.public_key_b64 = generate_keypair()
        except Exception as exc:
            self._last_error = str(exc)
            self.console.warn(self._last_error)
            return False

        connector = aiohttp.TCPConnector(ssl=False if self.config.insecure else None)
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)

        payload = json.dumps(
            {
                "public-key": self.public_key_b64,
                "secret-key": self.secret,
                "correlation-id": self.correlation,
            }
        ).encode("utf-8")

        errors: List[str] = []
        servers = self._normalise_servers(self.config.server)
        random.shuffle(servers)
        for server in servers:
            try:
                async with self.session.post(
                    server + "/register",
                    data=payload,
                    headers=self._headers(),
                    proxy=self.proxy,
                ) as response:
                    body = await response.text()
                    if response.status != 200:
                        errors.append(f"{server}: HTTP {response.status} {body[:180]}")
                        continue
                    try:
                        message = json.loads(body).get("message", "")
                    except Exception:
                        message = ""
                    if message != "registration successful":
                        errors.append(f"{server}: unexpected response {body[:180]}")
                        continue
                    self.server_url = server
                    self.host = urlsplit(server).hostname or self.config.server
                    self._registered = True
                    self.console.debug(f"interactsh registered with {server} as {self.correlation}")
                    return True
            except Exception as exc:
                errors.append(f"{server}: {exc}")

        await self.close()
        self._last_error = "; ".join(errors)[:500] or "registration failed"
        self.console.warn(f"interactsh registration failed: {self._last_error}")
        return False

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.config.token:
            headers["Authorization"] = self.config.token
        return headers

    async def close(self) -> None:
        if self.session is not None and self._registered:
            try:
                payload = json.dumps(
                    {"correlation-id": self.correlation, "secret-key": self.secret}
                ).encode("utf-8")
                await asyncio.wait_for(
                    self.session.post(
                        self.server_url + "/deregister",
                        data=payload,
                        headers=self._headers(),
                        proxy=self.proxy,
                    ),
                    timeout=self.config.timeout,
                )
            except Exception:
                pass
        self._registered = False
        if self.session is not None and not self.session.closed:
            await self.session.close()
        self.session = None

    # -- callbacks ---------------------------------------------------------------
    def callback_for(self, marker: str) -> str:
        label = self._labels.get(marker)
        if not label:
            nonce_bytes = os.urandom(16)
            nonce = zbase32(nonce_bytes)
            nonce = nonce[: self.config.nonce_length].ljust(self.config.nonce_length, "y")
            label = f"{self.correlation}{nonce}"
            self._labels[marker] = label
        return f"https://{label}.{self.host}"

    @property
    def callback_base(self) -> str:
        return f"https://{self.correlation}.{self.host}" if self.host else ""

    # -- polling -----------------------------------------------------------------
    def _decode_interaction(self, item: Any, aes_key: str = "") -> Optional[Dict[str, Any]]:
        if isinstance(item, dict):
            return item
        if not isinstance(item, str):
            return None
        raw = item.strip()
        if not raw:
            return None
        if raw.startswith("{"):
            try:
                return json.loads(raw)
            except Exception:
                return None
        if aes_key and self.private_key is not None:
            try:
                plaintext = decrypt_message(self.private_key, aes_key, raw)
                return json.loads(plaintext.decode("utf-8", "replace"))
            except Exception as exc:
                self.console.debug(f"interactsh decrypt failed: {exc}")
                return None
        try:
            decoded = base64.b64decode(raw)
            return json.loads(decoded.decode("utf-8", "replace"))
        except Exception:
            return None

    def _hit_from_interaction(self, interaction: Dict[str, Any]) -> Optional[OOBHit]:
        raw = str(interaction.get("raw-request") or interaction.get("raw") or "")
        full_id = str(interaction.get("full-id") or interaction.get("full_id") or "")
        marker = extract_marker(raw, self._labels.keys()) or extract_marker(full_id, self._labels.keys())
        if not marker and raw:
            # Last resort: any ?m=..., even if the registration map is empty.
            from xoxss.oob.base import extract_marker as _extract

            marker = _extract(raw)
        if not marker:
            return None
        return OOBHit(
            marker=marker,
            protocol=str(interaction.get("protocol") or ""),
            remote_address=str(interaction.get("remote-address") or interaction.get("remote_address") or ""),
            raw=raw or json.dumps(interaction, ensure_ascii=False),
            timestamp=str(interaction.get("timestamp") or ""),
            full_id=full_id,
            source="interactsh",
        )

    async def poll(self) -> List[OOBHit]:
        if not self._registered or self.session is None:
            return []
        url = f"{self.server_url}/poll"
        params = {"id": self.correlation, "secret": self.secret}
        try:
            async with self.session.get(
                url, params=params, headers={"Authorization": self.config.token} if self.config.token else None, proxy=self.proxy
            ) as response:
                body = await response.text()
                if response.status != 200:
                    self.console.debug(f"interactsh poll HTTP {response.status}: {body[:160]}")
                    return []
                payload = json.loads(body)
        except Exception as exc:
            self.console.debug(f"interactsh poll error: {exc}")
            return []

        hits: List[OOBHit] = []
        aes_key = str(payload.get("aes_key") or "")
        for item in payload.get("data") or []:
            interaction = self._decode_interaction(item, aes_key)
            if interaction:
                hit = self._hit_from_interaction(interaction)
                if hit:
                    hits.append(hit)
        for key in ("extra", "tlddata"):
            for item in payload.get(key) or []:
                interaction = self._decode_interaction(item, "")
                if interaction:
                    hit = self._hit_from_interaction(interaction)
                    if hit:
                        hits.append(hit)
        return hits

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transport": "interactsh",
            "server": self.server_url or self.config.server,
            "correlation_id": self.correlation,
            "callback_base": self.callback_base,
            "registered": self._registered,
            "last_error": self._last_error,
        }


__all__ = [
    "InteractshClient",
    "InteractshConfig",
    "correlation_id",
    "zbase32",
    "generate_keypair",
    "encrypt_message",
    "decrypt_message",
]
