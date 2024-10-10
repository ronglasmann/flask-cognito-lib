import os
from functools import wraps
from typing import Iterable, Optional, Union

from flask import Response
from flask import current_app as app
from flask import redirect, request, session
from werkzeug.local import LocalProxy

from flask_cognito_lib.config import Config
from flask_cognito_lib.exceptions import (
    AuthorisationRequiredError,
    CognitoError,
    CognitoGroupRequiredError,
    TokenVerifyError,
)
from flask_cognito_lib.plugin import CognitoAuth
from flask_cognito_lib.utils import (
    CognitoTokenResponse,
    generate_code_challenge,
    generate_code_verifier,
    secure_random,
    validate_access,
    get_client_id
)

cognito_auth: CognitoAuth = LocalProxy(
    lambda: app.extensions[Config.APP_EXTENSION_KEY]
)  # type: ignore


def remove_from_session(keys: Iterable[str]):
    """Remove an entry from the session"""
    for key in keys:
        if key in session:
            session.pop(key)


def validate_and_store_tokens(
    tokens: CognitoTokenResponse,
    nonce: Optional[str] = None,
) -> None:
    """Validate and store the access token and ID token (if present) in the session"""
    # validate the JWT and get the claims
    claims = cognito_auth.verify_access_token(
        token=tokens.access_token,
        client_id=get_client_id(cognito_auth, request),
        leeway=cognito_auth.cfg.cognito_expiration_leeway,
    )
    session.update({"claims": claims})

    # Grab the user info from the user endpoint and store in the session
    user_info = None
    # if cognito_auth.cfg.disabled:
    #     print(f"cognito auth disabled")
    #     user_id = os.getenv("AWS_COGNITO_DISABLED_USER_ID", None)
    #     email = os.getenv("AWS_COGNITO_DISABLED_USER_EMAIL", None)
    #     name = os.getenv("AWS_COGNITO_DISABLED_USER_NAME", None)
    #     if user_id is None or email is None or name is None:
    #         raise Exception(f"'AWS_COGNITO_DISABLED_USER_ID', 'AWS_COGNITO_DISABLED_USER_EMAIL', and "
    #                         f"'AWS_COGNITO_DISABLED_USER_NAME' must be set when 'AWS_COGNITO_DISABLED'")
    #     user_info = {
    #         'id': user_id,
    #         'email': email,
    #         'name': name,
    #         'is_active': 'True',
    #         # 'groups': '',
    #         # 'hashed_password': '',
    #     }

    if tokens.id_token is not None:
        user_info = cognito_auth.verify_id_token(
            token=tokens.id_token,
            client_id=get_client_id(cognito_auth, request),
            nonce=nonce,
            leeway=cognito_auth.cfg.cognito_expiration_leeway,
        )
        if 'email' in user_info:
            print(f"email in user_info")
            user_info['id'] = user_info['sub']
            user_info['name'] = user_info['email'][:user_info['email'].find('@')]
            user_info['is_active'] = 'True'
            # user_info['groups'] = ''
            # user_info['hashed_password'] = ''

        else:
            print(f"email not in user_info")
            user_info = None

    if user_info is not None:
        session.update({"user_info": user_info})
        session.update({"user": user_info})
    else:
        session.pop("user_info")
        session.pop("user")


def store_token_in_cookie(
    resp: Response,
    token: Union[str, None],
    cookie_name: str,
    max_age: int,
    encrypt: bool = False,
) -> None:
    """Store the token in an HTTP only secure cookie with the given name and max age

    Optionally symmetrically encrypt a token using Fernet with the Flask `SECRET_KEY`"""
    if encrypt:
        # Encrypt the token
        token = cognito_auth.token_service.encrypt_token(token)

    resp.set_cookie(
        key=cookie_name,
        value=token,
        max_age=max_age,
        httponly=True,
        secure=True,
        samesite=cognito_auth.cfg.cookie_samesite,
        domain=cognito_auth.cfg.cookie_domain,
    )


def get_token_from_cookie(cookie_name: str) -> Union[str, None]:
    """Get the token from the cookie"""
    token = request.cookies.get(cookie_name)

    if (
        token
        and cognito_auth.cfg.COOKIE_NAME_REFRESH == cookie_name
        and cognito_auth.cfg.refresh_cookie_encrypted
    ):
        # Decrypt the refresh token
        return cognito_auth.token_service.decrypt_token(token)

    return token


def cognito_login(fn):
    """A decorator that redirects to the Cognito hosted UI"""

    @wraps(fn)
    def wrapper(*args, **kwargs):

        if cognito_auth.cfg.disabled:
            resp = fn(*args, **kwargs)
            return resp

        # store parameters in the session that are passed to Cognito
        # and required for JWT verification
        code_verifier = generate_code_verifier()
        cognito_session = {
            "code_verifier": code_verifier,
            "code_challenge": generate_code_challenge(code_verifier),
            "nonce": secure_random(),
        }
        session.update(cognito_session)

        # Add suport for custom state values which are appended to a secure
        # random value for additional CRSF protection
        state = secure_random()
        custom_state = session.get("state")
        if custom_state:
            state += f"__{custom_state}"

        session.update({"state": state})

        # client_id = request.args.get("client_id", None)
        # identity_provider = request.args.get("identity_provider", None)

        login_url = cognito_auth.cognito_service.get_sign_in_url(
            code_challenge=session["code_challenge"],
            state=session["state"],
            nonce=session["nonce"],
            client_id=get_client_id(cognito_auth, request),
            scopes=cognito_auth.cfg.cognito_scopes,
            # client_id=client_id,
            # identity_provider=identity_provider
        )

        return redirect(login_url)

    return wrapper


def cognito_login_callback(fn):
    """
    A decorator to wrap the redirect after a user has logged in with Cognito.
    Stores the Cognito JWT in a http only cookie.
    """

    @wraps(fn)
    def wrapper(*args, **kwargs):

        if cognito_auth.cfg.disabled:
            print(f"cognito auth disabled adding the 'auth disabled' user to session")
            user_id = os.getenv("AWS_COGNITO_DISABLED_USER_ID", None)
            email = os.getenv("AWS_COGNITO_DISABLED_USER_EMAIL", None)
            name = os.getenv("AWS_COGNITO_DISABLED_USER_NAME", None)
            if user_id is None or email is None or name is None:
                raise Exception(f"'AWS_COGNITO_DISABLED_USER_ID', 'AWS_COGNITO_DISABLED_USER_EMAIL', and "
                                f"'AWS_COGNITO_DISABLED_USER_NAME' must be set when 'AWS_COGNITO_DISABLED'")
            user_info = {
                'id': user_id,
                'email': email,
                'name': name,
                'is_active': 'True',
            }
            session.update({"user": user_info})
            resp = fn(*args, **kwargs)
            return resp

        # Get the access token return after auth flow with Cognito
        code_verifier = session["code_verifier"]
        state = session["state"]
        nonce = session["nonce"]

        print(f"request.args: {request.args}")
        print(f"code_verifier: {code_verifier}")
        print(f"state: {state}")
        print(f"nonce: {nonce}")

        # exchange the code for an access token
        # also confirms the returned state is correct
        tokens = cognito_auth.get_tokens(
            req=request,
            expected_state=state,
            code_verifier=code_verifier,
            cognito_auth=cognito_auth
        )

        # Store the tokens in the session
        validate_and_store_tokens(tokens=tokens, nonce=nonce)

        # Remove one-time use variables now we have completed the auth flow
        remove_from_session(("code_challenge", "code_verifier", "nonce"))

        # split out the random part of the state value (in case the user
        # specified their own custom state value)
        state = session.get("state").split("__")[-1]
        session.update({"state": state})

        # return and set the JWT as a http only cookie
        resp = fn(*args, **kwargs)

        # Store the access token in a HTTP only secure cookie
        store_token_in_cookie(
            resp=resp,
            token=tokens.access_token,
            cookie_name=cognito_auth.cfg.COOKIE_NAME,
            max_age=cognito_auth.cfg.max_cookie_age_seconds,
        )

        # Grab the refresh token and store in a HTTP only secure cookie
        if cognito_auth.cfg.refresh_flow_enabled and tokens.refresh_token:
            store_token_in_cookie(
                resp=resp,
                token=tokens.refresh_token,
                cookie_name=cognito_auth.cfg.COOKIE_NAME_REFRESH,
                max_age=cognito_auth.cfg.max_refresh_cookie_age_seconds,
                encrypt=cognito_auth.cfg.refresh_cookie_encrypted,
            )

        return resp

    return wrapper


def cognito_refresh_callback(fn):
    """A decorator that handles token refresh with Cognito"""

    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not cognito_auth.cfg.refresh_flow_enabled:
            raise CognitoError("Refresh flow is not enabled")

        refresh_token = get_token_from_cookie(cognito_auth.cfg.COOKIE_NAME_REFRESH)

        if not refresh_token:
            raise CognitoError("No refresh token provided")

        # Exchange refresh token for the new access token.
        tokens = cognito_auth.exchange_refresh_token(
            refresh_token=refresh_token, client_id=get_client_id(cognito_auth, request)
        )

        # Store the tokens in the session
        validate_and_store_tokens(tokens=tokens)

        # Return and set the JWT as a http only cookie
        resp = fn(*args, **kwargs)

        # Store the access token in a HTTP only secure cookie
        store_token_in_cookie(
            resp=resp,
            token=tokens.access_token,
            cookie_name=cognito_auth.cfg.COOKIE_NAME,
            max_age=cognito_auth.cfg.max_cookie_age_seconds,
        )

        return resp

    return wrapper


def cognito_logout(fn):
    """A decorator that handles logging out with Cognito"""

    @wraps(fn)
    def wrapper(*args, **kwargs):
        # logout at cognito and remove the cookies
        resp = redirect(cognito_auth.cfg.logout_endpoint(get_client_id(cognito_auth, request)))
        resp.delete_cookie(
            key=cognito_auth.cfg.COOKIE_NAME, domain=cognito_auth.cfg.cookie_domain
        )

        # Revoke the refresh token if it exists
        if refresh_token := get_token_from_cookie(
            cognito_auth.cfg.COOKIE_NAME_REFRESH
        ):
            cognito_auth.revoke_refresh_token(refresh_token, get_client_id(cognito_auth, request))
            resp.delete_cookie(
                key=cognito_auth.cfg.COOKIE_NAME_REFRESH,
                domain=cognito_auth.cfg.cookie_domain,
            )

        # Cognito will redirect to the sign-out URL (if set) or else use
        # the callback URL
        return resp

    return wrapper


def auth_required(groups: Optional[Iterable[str]] = None, any_group: bool = False):
    """A decorator to protect a route with AWS Cognito"""

    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            validate_access(cognito_auth, request, groups=groups, any_group=any_group)

            return fn(*args, **kwargs)
            # # return early if the extension is disabled
            # if cognito_auth.cfg.disabled:
            #     return fn(*args, **kwargs)
            #
            # # Try and validate the access token stored in the cookie
            # try:
            #     access_token = request.cookies.get(cognito_auth.cfg.COOKIE_NAME)
            #     claims = cognito_auth.verify_access_token(
            #         token=access_token,
            #         leeway=cognito_auth.cfg.cognito_expiration_leeway,
            #     )
            #     valid = True
            #
            #     # Check for required group membership
            #     if groups:
            #         if any_group:
            #             valid = any(g in claims["cognito:groups"] for g in groups)
            #         else:
            #             valid = all(g in claims["cognito:groups"] for g in groups)
            #
            #         if not valid:
            #             raise CognitoGroupRequiredError
            #
            # except (TokenVerifyError, KeyError):
            #     valid = False
            #
            # if valid:
            #     return fn(*args, **kwargs)
            #
            # raise AuthorisationRequiredError

        return decorator

    return wrapper
