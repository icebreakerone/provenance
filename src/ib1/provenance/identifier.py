
import secrets

def globally_unique_step_identifier():
    return secrets.token_urlsafe(15)
