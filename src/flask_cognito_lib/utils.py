import re
from base64 import urlsafe_b64encode
from dataclasses import dataclass
from hashlib import sha256
from os import urandom
from typing import Optional, Iterable

from flask_cognito_lib.exceptions import CognitoGroupRequiredError, TokenVerifyError, AuthorisationRequiredError


def get_session_args(sess):
    session_args = {}
    for k in sess.keys():
        session_args[k] = sess[k]
    return session_args


def get_client_id(cognito_auth, req=None, req_args=None, sess=None, sess_args=None):
    print(f"get_client_id(...)")
    if req_args is None:
        req_args = req.args
    print(f"req_args: {req_args}")
    if sess_args is None:
        sess_args = get_session_args(sess)
    print(f"sess_args: {sess_args}")
    client_id = req_args.get("client_id", None)
    if client_id is None:
        client_id = cognito_auth.cfg.user_pool_default_client_id
    print(f"client_id: {client_id}")
    return client_id


def validate_access(cognito_auth, req, sess, groups: Optional[Iterable[str]] = None, any_group: bool = False):
    # return early if the extension is disabled
    if cognito_auth.cfg.disabled:
        print(f"cognito auth is disabled")
        valid = True

    else:
        print(f"cognito auth is enabled")

        # Try and validate the access token stored in the cookie
        try:
            client_id = get_client_id(cognito_auth, req=req, sess=sess)
            access_token = req.cookies.get(cognito_auth.cfg.COOKIE_NAME)
            claims = cognito_auth.verify_access_token(
                token=access_token,
                client_id=client_id,
                leeway=cognito_auth.cfg.cognito_expiration_leeway,
            )
            print(f"access token is valid")
            valid = True

            # Check for required group membership
            if groups:
                print(f"checking group membership")
                if any_group:
                    valid = any(g in claims["cognito:groups"] for g in groups)
                else:
                    valid = all(g in claims["cognito:groups"] for g in groups)

                if not valid:
                    print(f"group membership check failed")
                    raise CognitoGroupRequiredError

        except (TokenVerifyError, KeyError):
            print(f"access token is not valid")
            valid = False

    if valid:
        pass
    else:
        raise AuthorisationRequiredError


def secure_random(n_bytes: int = 32) -> str:
    """Generate a secure URL-safe random string"""
    return urlsafe_b64encode(urandom(n_bytes)).decode("utf-8")


def generate_code_verifier(n_bytes: int = 32) -> str:
    """Create a code verification secret"""
    code_verifier = secure_random(n_bytes=n_bytes)
    code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)
    return code_verifier


def generate_code_challenge(code_verifier: str) -> str:
    """Create a code challenge (SHA256) from a code verifier"""
    code_challenge = sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = urlsafe_b64encode(code_challenge).decode("utf-8")
    return code_challenge.replace("=", "")


@dataclass
class CognitoTokenResponse:
    access_token: Optional[str] = None
    token_type: Optional[str] = None
    expires_in: Optional[int] = None
    refresh_token: Optional[str] = None
    id_token: Optional[str] = None
    error: Optional[str] = None
