import logging

from http import HTTPStatus
from src.core.logging_config import configure_logging
from src.core.metrics import MetricsStore


from fastapi import FastAPI, HTTPException
from src.auth_server.config import AuthConfig
from src.auth_server.exceptions import (
    AccessDeniedError,
    InvalidClientError,
    InvalidGrantError,
    TokenReuseError,
    UnauthorizedClientError,
    UnsupportedGrantTypeError,
)
from src.auth_server.grant_service import GrantService
from src.auth_server.schemas import (
    TokenRequest, RefreshRequest, RevokeRequest, IntrospectRequest,
    TokenResponse, WellKnownResponse,
)
from src.constants import GRANT_PASSWORD, GRANT_CLIENT_CREDENTIALS

from src.auth_server.repositories import UserRepoFile, ClientRepoFile, RoleRepoFile
from src.core.clock import Clock
from src.core.jti_store import JtiStore
from src.core.password_hasher import PasswordHasher
from src.core.revocation_store import RevocationStore
from src.core.refresh_store import RefreshStore
from src.core.signer import SignerHS256
from src.core.token_codec import TokenCodec

app = FastAPI(title="mini-auth")

configure_logging()
logger = logging.getLogger(__name__)
cfg = AuthConfig.load()
signer = SignerHS256(cfg.auth_secret)
metrics = MetricsStore(f"{cfg.data_dir}/metrics.ndjson")
grant_service = GrantService(
    config=cfg,
    token_codec=TokenCodec(signer),
    user_repo=UserRepoFile(f"{cfg.data_dir}/users.json"),
    client_repo=ClientRepoFile(f"{cfg.data_dir}/clients.json"),
    role_repo=RoleRepoFile(f"{cfg.data_dir}/roles.json"),
    refresh_store=RefreshStore(f"{cfg.data_dir}/refresh_index.ndjson"),
    revocation_store=RevocationStore(f"{cfg.data_dir}/revocations.ndjson"),
    password_hasher=PasswordHasher(),
    clock=Clock(skew_sec=cfg.clock_skew_sec),
    metrics=metrics,
    jti_store=JtiStore(),
)


@app.post("/token", response_model=TokenResponse,
response_model_exclude_none=True)
def token(req: TokenRequest):
    """Выдать access-токен. Поддерживает `password` и `client_credentials`."""
    try:
        if req.grant_type == GRANT_PASSWORD:
            return grant_service.password_grant(
                req.username, req.password, req.client_id, req.client_secret, req.scopes
            )
        elif req.grant_type == GRANT_CLIENT_CREDENTIALS:
            return grant_service.client_credentials_grant(
                req.client_id, req.client_secret, req.scopes
            )
        else:
            raise UnsupportedGrantTypeError(f"grant_type={req.grant_type} не поддерживается")
    except InvalidClientError as e:
        logger.warning("invalid_client: %s", e)
        raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED, detail="invalid_client")
    except InvalidGrantError as e:
        logger.warning("invalid_grant: %s", e)
        raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED, detail="invalid_grant")
    except AccessDeniedError as e:
        logger.warning("access_denied: %s", e)
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="access_denied")
    except UnauthorizedClientError as e:
        logger.warning("unauthorized_client: %s", e)
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="unauthorized_client")
    except UnsupportedGrantTypeError as e:
        logger.warning("unsupported_grant_type: %s", e)
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail="unsupported_grant_type")


@app.post("/token/refresh", response_model=TokenResponse)
def token_refresh(req: RefreshRequest):
    """Ротировать refresh-токен и получить новую пару `access + refresh`. Старый `refresh` становится недействительным."""
    try:
        return grant_service.refresh_grant(req.refresh_token, req.client_id, req.client_secret)
    except InvalidClientError as e:
        logger.warning("invalid_client: %s", e)
        raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED, detail="invalid_client")
    except InvalidGrantError as e:
        logger.warning("invalid_grant on refresh: %s", e)
        raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED, detail="invalid_grant")
    except TokenReuseError as e:
        logger.warning("refresh token reuse detected: %s", e)
        raise HTTPException(status_code=HTTPStatus.CONFLICT, detail="token_reuse")
    except UnauthorizedClientError as e:
        logger.warning("unauthorized_client: %s", e)
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="unauthorized_client")


@app.post("/revoke")
def revoke(req: RevokeRequest):
    """Отозвать `access` или `refresh` токен."""
    grant_service.revoke(req.token, req.token_type_hint)
    return {}


@app.post("/introspect")
def introspect(req: IntrospectRequest):
    """Проверить валидность `access` токена и вернуть его метаданные."""
    return grant_service.introspect(req.token)


@app.get("/.well-known/config", response_model=WellKnownResponse)
def well_known():
    """Публичная конфигурация сервера авторизации: `issuer`, `aud`, `TTL` токенов."""
    return {
        "issuer": cfg.issuer,
        "aud": cfg.aud,
        "access_ttl_sec": cfg.access_ttl_sec,
        "refresh_ttl_days": cfg.refresh_ttl_days,
        "token_alg": cfg.token_alg,
    }
