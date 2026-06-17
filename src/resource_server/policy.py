class ForbiddenError(Exception):
    pass


class PolicyEngine:
    @staticmethod
    def require_scope(token_payload: dict, required_scope: str) -> None:
        scopes = token_payload["scopes"]
        if "*" not in scopes and required_scope not in scopes:
            raise ForbiddenError('Scope not allowed')

