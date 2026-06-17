import logging
from http import HTTPStatus

from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from src.core.clock import Clock
from src.core.logging_config import configure_logging
from src.core.revocation_store import RevocationStore
from src.core.signer import SignerHS256
from src.core.token_codec import TokenCodec
from src.resource_server.config import RSConfig
from src.resource_server.middleware import AuthError, AuthMiddleware
from src.resource_server.policy import ForbiddenError, PolicyEngine
from src.resource_server.schemas import (PaymentCreatedResponse,
                                         PaymentsResponse)

configure_logging()
logger = logging.getLogger(__name__)

app = FastAPI(title="payments-api")

cfg = RSConfig.load()
signer = SignerHS256(cfg.auth_secret)
auth_middleware = AuthMiddleware(
    token_codec=TokenCodec(signer),
    config=cfg,
    revocation_store=RevocationStore(f"{cfg.data_dir}/revocations.ndjson"),
    clock=Clock(skew_sec=cfg.clock_skew_sec),
)

bearer_scheme = HTTPBearer()


def get_payload(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> dict:
    try:
        payload = auth_middleware.authenticate(credentials.credentials)
        logger.info("auth ok: sub=%s", payload.get("sub"))
        return payload
    except AuthError as e:
        logger.warning("auth failed: %s", e)
        raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED, detail=str(e))


def require_scope(scope: str):
    def dependency(payload: dict = Depends(get_payload)):
        try:
            PolicyEngine.require_scope(payload, scope)
        except ForbiddenError:
            logger.warning("forbidden: sub=%s scope=%s", payload.get("sub"), scope)
            raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Scope not allowed")
        return payload
    return dependency


@app.get("/api/payments", response_model=PaymentsResponse)
def get_payments(payload: dict = Depends(require_scope("payments:read"))):
    """Получить список платежей. Требует scope `payments:read`."""
    logger.info("payments:read granted: sub=%s", payload["sub"])
    return {"payments": [], "sub": payload["sub"]}


@app.post("/api/payments", response_model=PaymentCreatedResponse)
def create_payment(payload: dict = Depends(require_scope("payments:write"))):
    """Создать платёж. Требует scope `payments:write`."""
    logger.info("payments:write granted: sub=%s", payload["sub"])
    return {"status": "created", "sub": payload["sub"]}
