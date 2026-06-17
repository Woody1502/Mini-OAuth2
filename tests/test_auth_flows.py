import time
import uuid
from http import HTTPStatus

from tests.conftest import build_services, SECRET, AUD, ISSUER
from src.core.signer import SignerHS256
from src.core.token_codec import TokenCodec


def token_password(auth, username, password, scopes):
    return auth.post("/token", json={
        "grant_type": "password",
        "client_id": "cli-001", "client_secret": "secret",
        "username": username, "password": password, "scopes": scopes,
    })


def make_token(scopes=None, exp=30, iat=0):
    if scopes is None:
        scopes = ["payments:read", "payments:write"]
    now = int(time.time())
    payload = {
        "typ": "AT", "alg": "HS256",
        "iss": ISSUER, "sub": "u-100", "aud": AUD,
        "client_id": "cli-001", "scopes": scopes, "roles": ["manager", "viewer"],
        "jti": str(uuid.uuid4()),
        "iat": now + iat, "exp": now + exp,
    }
    return TokenCodec(SignerHS256(SECRET)).encode(payload)


def test_password_grant_success_then_resource_access(clients, username, password, scope):
    auth, rs = clients
    r = token_password(auth, username, password, scope)
    assert r.status_code == HTTPStatus.OK
    body = r.json()
    assert "access_token" in body and "refresh_token" in body
    assert body["token_type"] == "bearer"
    r2 = rs.get("/api/payments", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert r2.status_code == HTTPStatus.OK


def test_wrong_password_returns_401(clients, username, scope):
    auth, _ = clients
    r = token_password(auth, username, "wrongpass", scope)
    assert r.status_code == HTTPStatus.UNAUTHORIZED


def test_client_credentials_read_ok_write_forbidden(clients):
    auth, rs = clients
    r = auth.post("/token", json={
        "grant_type": "client_credentials",
        "client_id": "cli-read", "client_secret": "secret",
        "scopes": ["payments:read"],
    })
    assert r.status_code == HTTPStatus.OK
    token = r.json()["access_token"]
    assert rs.get("/api/payments", headers={"Authorization": f"Bearer {token}"}).status_code == HTTPStatus.OK
    assert rs.post("/api/payments", headers={"Authorization": f"Bearer {token}"}).status_code == HTTPStatus.FORBIDDEN


def test_refresh_rotation_old_token_rejected(clients, username, password, scope):
    auth, _ = clients
    old_refresh = token_password(auth, username, password, scope).json()["refresh_token"]

    r2 = auth.post("/token/refresh", json={
        "refresh_token": old_refresh, "client_id": "cli-001", "client_secret": "secret",
    })
    assert r2.status_code == HTTPStatus.OK
    assert r2.json()["refresh_token"] != old_refresh

    r3 = auth.post("/token/refresh", json={
        "refresh_token": old_refresh, "client_id": "cli-001", "client_secret": "secret",
    })
    assert r3.status_code == HTTPStatus.CONFLICT


def test_revocation(clients, username, password, scope):
    auth, rs = clients

    body = token_password(auth, username, password, scope).json()
    access = body["access_token"]
    headers = {"Authorization": f"Bearer {access}"}
    assert rs.get("/api/payments", headers=headers).status_code == HTTPStatus.OK
    auth.post("/revoke", json={"token": access})
    assert rs.get("/api/payments", headers=headers).status_code == HTTPStatus.UNAUTHORIZED

    refresh = token_password(auth, username, password, scope).json()["refresh_token"]
    auth.post("/revoke", json={"token": refresh})
    r = auth.post("/token/refresh", json={
        "refresh_token": refresh, "client_id": "cli-001", "client_secret": "secret",
    })
    assert r.status_code == HTTPStatus.UNAUTHORIZED


def test_clock_skew(clients):
    _, rs = clients

    assert rs.get("/api/payments", headers={"Authorization": f"Bearer {make_token(iat=20)}"}).status_code == HTTPStatus.OK
    assert rs.get("/api/payments", headers={"Authorization": f"Bearer {make_token(exp=-20)}"}).status_code == HTTPStatus.OK
    assert rs.get("/api/payments", headers={"Authorization": f"Bearer {make_token(exp=-40)}"}).status_code == HTTPStatus.UNAUTHORIZED
    assert rs.get("/api/payments", headers={"Authorization": f"Bearer {make_token(iat=40)}"}).status_code == HTTPStatus.UNAUTHORIZED


def test_viewer_role_cannot_write_payments(clients, scope):
    auth, rs = clients
    token = token_password(auth, "bob", "bob123", scope).json()["access_token"]
    assert rs.get("/api/payments", headers={"Authorization": f"Bearer {token}"}).status_code == HTTPStatus.OK
    assert rs.post("/api/payments", headers={"Authorization": f"Bearer {token}"}).status_code == HTTPStatus.FORBIDDEN


def test_introspect_active_vs_expired(clients, username, password, scope):
    auth, _ = clients
    access = token_password(auth, username, password, scope).json()["access_token"]
    assert auth.post("/introspect", json={"token": access}).json()["active"] is True

    expired_token = make_token(exp=-100)
    assert auth.post("/introspect", json={"token": expired_token}).json()["active"] is False


def test_corrupted_signature_returns_401(clients):
    _, rs = clients
    r = rs.get("/api/payments", headers={"Authorization": "Bearer 123.signature"})
    assert r.status_code == HTTPStatus.UNAUTHORIZED


def test_restart_preserves_state(tmp_data):
    gs, _ = build_services(tmp_data)

    r = gs.password_grant("alice", "alice123", "cli-001", "secret", ["payments:read"])
    access = r["access_token"]
    refresh = r["refresh_token"]
    jti = TokenCodec(SignerHS256(SECRET)).decode(access)["jti"]

    gs.revoke(access)
    gs.refresh_grant(refresh, "cli-001", "secret")

    gs2, _ = build_services(tmp_data)
    assert gs2.revocation_store.is_access_revoked(jti)
    assert gs2.refresh_store.get(refresh)["rotated"] is True
