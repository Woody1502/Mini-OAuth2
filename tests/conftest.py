import json
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

import src.auth_server.main as auth_main
import src.resource_server.main as rs_main
from src.core.clock import Clock
from src.core.jti_store import JtiStore
from src.core.password_hasher import PasswordHasher
from src.core.refresh_store import RefreshStore
from src.core.revocation_store import RevocationStore
from src.core.signer import SignerHS256
from src.core.token_codec import TokenCodec
from src.auth_server.grant_service import GrantService
from src.auth_server.repositories import ClientRepoFile, RoleRepoFile, UserRepoFile
from src.resource_server.middleware import AuthMiddleware

SECRET = "test-secret-key"
AUD = "payments-api"
ISSUER = "mini-auth"


@pytest.fixture()
def tmp_data(tmp_path):
    hasher = PasswordHasher()
    users = [
        {
            "user_id": "u-100",
            "username": "alice",
            "password_hash": hasher.hash("alice123"),
            "roles": ["manager", "viewer"],
            "status": "active",
        },
        {
            "user_id": "u-101",
            "username": "bob",
            "password_hash": hasher.hash("bob123"),
            "roles": ["viewer"],
            "status": "active",
        },
    ]
    clients = [
        {
            "client_id": "cli-001",
            "client_secret": "secret",
            "allowed_grants": ["password", "client_credentials", "refresh_token"],
            "allowed_scopes": ["payments:read", "payments:write", "users:read"],
            "aud": AUD,
        },
        {
            "client_id": "cli-read",
            "client_secret": "secret",
            "allowed_grants": ["client_credentials"],
            "allowed_scopes": ["payments:read"],
            "aud": AUD,
        },
    ]
    (tmp_path / "users.json").write_text(json.dumps(users))
    (tmp_path / "clients.json").write_text(json.dumps(clients))
    (tmp_path / "refresh_index.ndjson").write_text("")
    (tmp_path / "revocations.ndjson").write_text("")
    return tmp_path


@pytest.fixture()
def jti_store():
    return JtiStore()


def build_services(tmp_path, jti_store=None):
    if jti_store is None:
        jti_store = JtiStore()
    signer = SignerHS256(SECRET)
    codec = TokenCodec(signer)
    clock = Clock(skew_sec=30)
    refresh_store = RefreshStore(str(tmp_path / "refresh_index.ndjson"))
    revocation_store = RevocationStore(str(tmp_path / "revocations.ndjson"))
    cfg_auth = Mock(issuer=ISSUER, aud=AUD, access_ttl_sec=900, refresh_ttl_days=14, clock_skew_sec=30)
    cfg_rs = Mock(aud=AUD, clock_skew_sec=30)
    gs = GrantService(
        config=cfg_auth, token_codec=codec,
        user_repo=UserRepoFile(str(tmp_path / "users.json")),
        client_repo=ClientRepoFile(str(tmp_path / "clients.json")),
        role_repo=RoleRepoFile("data/roles.json"),
        refresh_store=refresh_store, revocation_store=revocation_store,
        password_hasher=PasswordHasher(), clock=clock,
        jti_store=jti_store,
    )
    mw = AuthMiddleware(token_codec=codec, config=cfg_rs,
                        revocation_store=revocation_store, clock=clock)
    return gs, mw


@pytest.fixture()
def username():
    return "alice"


@pytest.fixture()
def password():
    return "alice123"


@pytest.fixture()
def scope():
    return ["payments:read", "payments:write"]


@pytest.fixture()
def clients(tmp_data, jti_store):
    gs, mw = build_services(tmp_data, jti_store)
    auth_main.grant_service = gs
    rs_main.auth_middleware = mw
    return TestClient(auth_main.app), TestClient(rs_main.app)
