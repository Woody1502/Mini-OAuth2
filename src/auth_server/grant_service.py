import logging
from src.auth_server.utils import build_payload, token_response

logger = logging.getLogger(__name__)
from src.constants import (
    GRANT_PASSWORD,
    GRANT_CLIENT_CREDENTIALS,
    GRANT_REFRESH_TOKEN,
    SECONDS_PER_DAY,
)
from src.core.scope_matcher import ScopeMatcher
from src.core.exceptions import (
    InvalidSignatureError,
    RefreshTokenNotFoundError,
    RefreshTokenAlreadyRotatedError,
    RefreshTokenExpiredError,
)
from src.auth_server.exceptions import (
    AccessDeniedError,
    InvalidClientError,
    InvalidGrantError,
    TokenReuseError,
    UnauthorizedClientError,
)


class GrantService:

    def __init__(self, config, token_codec, user_repo, client_repo,
                 role_repo, refresh_store, revocation_store, password_hasher,
                 clock, jti_store, metrics=None):
        self.config = config
        self.token_codec = token_codec
        self.jti_store = jti_store
        self.user_repo = user_repo
        self.client_repo = client_repo
        self.role_repo = role_repo
        self.refresh_store = refresh_store
        self.revocation_store = revocation_store
        self.password_hasher = password_hasher
        self.clock = clock
        self.metrics = metrics

    def _verify_client(self, client_id: str, client_secret: str, required_grant: str) -> dict:
        """Находим клиента, проверяем секрет и разрешённый grant type"""
        client = self.client_repo.find_by_id(client_id)
        if not client:
            raise InvalidClientError(f"Клиент {client_id} не найден")
        if client_secret != client["client_secret"]:
            raise InvalidClientError("Неверный client_secret")
        if required_grant not in client["allowed_grants"]:
            raise UnauthorizedClientError(f"Grant {required_grant} не разрешён для клиента {client_id}")
        return client

    def password_grant(self, username: str, password: str, client_id: str,
                        client_secret: str, requested_scopes: list[str]) -> dict:
        """Выдаём access + refresh токены по логину и паролю пользователя"""
        client = self._verify_client(client_id, client_secret, GRANT_PASSWORD)
        user = self.user_repo.find_by_username(username)
        if user is None:
            raise InvalidGrantError(f"Пользователь {username} не найден")
        if user["status"] != "active":
            raise AccessDeniedError(f"Пользователь {username} заблокирован")
        if not self.password_hasher.verify(password, user["password_hash"]):
            raise InvalidGrantError("Неверный пароль")
        role_scopes = ScopeMatcher.expand_roles(user["roles"], self.role_repo.load())
        final_scopes = ScopeMatcher.intersect(requested_scopes, role_scopes, set(client["allowed_scopes"]))
        now = self.clock.now()
        scope_str = " ".join(final_scopes)
        payload = build_payload(self.config, user["user_id"], sorted(final_scopes), client_id, user["roles"], now)
        access_token = self.token_codec.encode(payload)
        self.jti_store.record(payload["jti"])
        refresh_token = self.refresh_store.create(user["user_id"], client_id, now + self.config.refresh_ttl_days * SECONDS_PER_DAY)
        logger.info("password grant: user=%s client=%s scope=%s", username, client_id, scope_str)
        if self.metrics:
            self.metrics.record("token_issued", grant_type="password", sub=user["user_id"], client=client_id)
        return token_response(access_token, self.config.access_ttl_sec, scope_str, refresh_token)

    def client_credentials_grant(self, client_id: str, client_secret: str,
                                   requested_scopes: list[str]) -> dict:
        """Выдаём access-токен для клиента"""
        client = self._verify_client(client_id, client_secret, GRANT_CLIENT_CREDENTIALS)
        now = self.clock.now()
        scopes = ScopeMatcher.intersect(requested_scopes, set(client["allowed_scopes"]))
        scope_str = " ".join(scopes)
        payload = build_payload(self.config, client_id, sorted(scopes), client_id, [], now)
        access_token = self.token_codec.encode(payload)
        self.jti_store.record(payload["jti"])
        logger.info("client_credentials grant: client=%s scope=%s", client_id, scope_str)
        if self.metrics:
            self.metrics.record("token_issued", grant_type="client_credentials", sub=client_id)
        return token_response(access_token, self.config.access_ttl_sec, scope_str)

    def refresh_grant(self, refresh_token: str, client_id: str,
                       client_secret: str) -> dict:
        """Ротируем refresh-токен и выдаём новую пару access + refresh"""
        client = self._verify_client(client_id, client_secret, GRANT_REFRESH_TOKEN)
        old_record = self.refresh_store.get(refresh_token)
        if old_record is None:
            raise InvalidGrantError("Refresh-токен не найден")
        if self.revocation_store.is_refresh_revoked(refresh_token):
            raise InvalidGrantError("Refresh-токен отозван")
        now = self.clock.now()
        new_exp = now + self.config.refresh_ttl_days * SECONDS_PER_DAY
        try:
            new_refresh_id = self.refresh_store.rotate(
                refresh_token, old_record["user_id"], client_id, new_exp
            )
        except RefreshTokenAlreadyRotatedError as e:
            logger.warning("refresh token reuse detected (possible theft): token=%s client=%s", refresh_token, client_id)
            raise TokenReuseError(str(e))
        except (RefreshTokenNotFoundError, RefreshTokenExpiredError) as e:
            raise InvalidGrantError(str(e))
        new_user = self.user_repo.find_by_user_id(old_record["user_id"])
        role_scopes = ScopeMatcher.expand_roles(new_user["roles"], self.role_repo.load())
        final_scopes = ScopeMatcher.intersect(list(role_scopes), set(client["allowed_scopes"]))
        scope_str = " ".join(final_scopes)
        payload = build_payload(self.config, old_record["user_id"], sorted(final_scopes), client_id, new_user["roles"], now)
        access_token = self.token_codec.encode(payload)
        self.jti_store.record(payload["jti"])
        logger.info("refresh grant: user=%s client=%s scope=%s", old_record["user_id"], client_id, scope_str)
        if self.metrics:
            self.metrics.record("token_issued", grant_type="refresh_token", sub=old_record["user_id"], client=client_id)
        return token_response(access_token, self.config.access_ttl_sec, scope_str, new_refresh_id)

    def revoke(self, token: str, token_type_hint: str | None = None) -> None:
        """Отзываем access-токен по jti или opaque refresh-токен по его значению"""
        if token_type_hint == "refresh_token":
            self._revoke_refresh(token)
            return
        try:
            payload = self.token_codec.decode(token)
            self.revocation_store.revoke_access(payload["jti"], payload["exp"])
            self.jti_store.remove(payload["jti"])
            logger.info("access token revoked: jti=%s", payload["jti"])
            if self.metrics:
                self.metrics.record("token_revoked", type="access", jti=payload["jti"])
        except InvalidSignatureError:
            self._revoke_refresh(token)

    def _revoke_refresh(self, token: str) -> None:
        record = self.refresh_store.get(token)
        if record is not None:
            self.revocation_store.revoke_refresh(token, record["exp"])
            logger.info("refresh token revoked: user=%s client=%s", record["user_id"], record["client_id"])
            if self.metrics:
                self.metrics.record("token_revoked", type="refresh", user=record["user_id"])

    def introspect(self, token: str) -> dict:
        """Проверяем токен и возвращаем его метаданные"""
        try:
            payload = self.token_codec.decode(token)
            if not self.jti_store.seen(payload["jti"]):
                return {"active": False}
            if self.clock.is_expired(payload["exp"]):
                return {"active": False}
            if self.revocation_store.is_access_revoked(payload["jti"]):
                return {"active": False}
            return {"active": True, **payload}
        except InvalidSignatureError:
            return {"active": False}
