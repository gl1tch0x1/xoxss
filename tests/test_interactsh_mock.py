"""End-to-end interactsh transport test against a local mock server.

The client is exercised for real: it generates an RSA key pair, registers, builds
a callback label, polls, and decrypts an AES-CTR interaction whose key is
RSA-OAEP wrapped. No external service is contacted.
"""

import asyncio
import base64
import json

import pytest

pytest.importorskip("aiohttp")
pytest.importorskip("cryptography")

from aiohttp import web
from cryptography.hazmat.primitives import serialization


class _MockInteractsh:
    def __init__(self):
        self.public_key = None
        self.correlation = ""
        self.secret = ""
        self.registration = None
        self.deregistered = False
        self.interaction = None
        self.poll_count = 0

    async def register(self, request):
        body = await request.json()
        self.registration = body
        self.correlation = body["correlation-id"]
        self.secret = body["secret-key"]
        self.public_key = serialization.load_pem_public_key(
            base64.b64decode(body["public-key"])
        )
        return web.json_response({"message": "registration successful"})

    async def poll(self, request):
        self.poll_count += 1
        if request.query.get("id") != self.correlation:
            return web.json_response({"message": "unknown correlation"}, status=401)
        if request.query.get("secret") != self.secret:
            return web.json_response({"message": "bad secret"}, status=401)
        if not self.interaction or self.public_key is None:
            return web.json_response({"data": []})

        from xoxss.oob.interactsh import encrypt_message

        aes_key, ciphertext = encrypt_message(
            self.public_key, json.dumps(self.interaction).encode("utf-8")
        )
        return web.json_response({"data": [ciphertext], "aes_key": aes_key})

    async def deregister(self, request):
        self.deregistered = True
        return web.json_response({"message": "deregistration successful"})


def _console():
    class Console:
        def info(self, *args, **kwargs):
            pass

        def warn(self, *args, **kwargs):
            pass

        def debug(self, *args, **kwargs):
            pass

        def ok(self, *args, **kwargs):
            pass

    return Console()


def test_interactsh_register_poll_and_decrypt():
    from xoxss.oob.interactsh import InteractshClient

    async def scenario():
        mock = _MockInteractsh()
        app = web.Application()
        app.router.add_post("/register", mock.register)
        app.router.add_get("/poll", mock.poll)
        app.router.add_post("/deregister", mock.deregister)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        try:
            client = InteractshClient(
                _console(), server=f"http://127.0.0.1:{port}", insecure=True, timeout=10.0
            )
            assert await client.start(), client._last_error
            assert mock.registration["correlation-id"] == client.correlation
            assert mock.registration["secret-key"] == client.secret

            callback = client.callback_for("MARK1")
            assert callback.startswith("https://")
            assert client.correlation in callback
            assert client.callback_base.endswith(client.host)

            mock.interaction = {
                "protocol": "http",
                "unique-id": "abc",
                "full-id": client.correlation + "nonce",
                "raw": "GET /?m=MARK1 HTTP/1.1\r\nHost: target.test\r\n",
                "remote-address": "203.0.113.9",
                "timestamp": "2026-11-03T00:00:00Z",
            }
            hits = await client.poll()
            assert [hit.marker for hit in hits] == ["MARK1"]
            assert hits[0].protocol == "http"
            assert hits[0].remote_address == "203.0.113.9"
            assert hits[0].source == "interactsh"

            # A poll without pending interactions must be empty, not an error.
            mock.interaction = None
            assert await client.poll() == []
            assert mock.poll_count >= 2

            await client.close()
            assert mock.deregistered
        finally:
            await runner.cleanup()

    asyncio.run(scenario())
