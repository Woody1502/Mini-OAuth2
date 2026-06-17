class ScopeMatcher:
    @staticmethod
    def expand_roles(roles: list[str], role_definitions: dict) -> set[str]:
        union = set()
        for role in roles:
            scopes = role_definitions[role]['scopes']
            union.update(scopes)
        return union

    @staticmethod
    def intersect(requested: list[str], *allowed_sets: set[str]) -> list[str]:
        result = []
        for scope in requested:
            if all(scope in allowed_set or "*" in allowed_set for allowed_set in allowed_sets):
                result.append(scope)
        return result
