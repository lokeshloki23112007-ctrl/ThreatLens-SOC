def validate_token(token: str):
    return {"source": "authentication", "token_provided": bool(token)}
