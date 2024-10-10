import pytest
from flask import Flask

from flask_cognito_lib import CognitoAuth
from flask_cognito_lib.exceptions import CognitoError


def test_plugin_init(cfg):
    app = Flask(__name__)
    CognitoAuth(app)
    assert cfg.APP_EXTENSION_KEY in app.extensions


def test_plugin_init_with_config_override(cfg_override):
    app = Flask(__name__)
    CognitoAuth(app, cfg=cfg_override)
    assert (
        app.extensions[cfg_override.APP_EXTENSION_KEY].cfg.logout_redirect
        == cfg_override.logout_redirect
    )


def test_plugin_lazy_init(cfg):
    app = Flask(__name__)
    CognitoAuth().init_app(app)
    assert cfg.APP_EXTENSION_KEY in app.extensions


def test_plugin_lazy_init_with_config_override(cfg_override):
    app = Flask(__name__)
    CognitoAuth().init_app(app, cfg=cfg_override)
    assert (
        app.extensions[cfg_override.APP_EXTENSION_KEY].cfg.logout_redirect
        == cfg_override.logout_redirect
    )


def test_plugin_get_tokens_parameters_state(app, cfg, client_id):
    cls = app.extensions[cfg.APP_EXTENSION_KEY]
    with pytest.raises(CognitoError):
        cls.get_tokens(
            request_args={"code": "asdf", "client_id": client_id}, expected_state="", code_verifier="", cognito_auth=cls
        )


def test_plugin_get_tokens_parameters_code(app, cfg):
    cls = app.extensions[cfg.APP_EXTENSION_KEY]
    with pytest.raises(CognitoError):
        cls.get_tokens(
            request_args={"state": "asdf"}, expected_state="", code_verifier="", cognito_auth=cls
        )


def test_plugin_get_tokens_state_invalid(app, cfg):
    cls = app.extensions[cfg.APP_EXTENSION_KEY]
    with pytest.raises(CognitoError):
        cls.get_tokens(
            request_args={"code": "asdf", "state": "qwer"},
            expected_state="1234",
            code_verifier="",
            cognito_auth=cls
        )


def test_plugin_get_tokens(app, cfg, mocker, client_id):
    cls = app.extensions[cfg.APP_EXTENSION_KEY]
    mocker.patch(
        "requests.post",
        return_value=mocker.Mock(json=lambda: {"access_token": "test_access_token"}),
    )
    tokens = cls.get_tokens(
        request_args={"code": "asdf", "state": "qwer", "client_id": client_id},
        expected_state="qwer",
        code_verifier="",
        cognito_auth=cls
    )
    assert tokens.access_token == "test_access_token"


def test_plugin_exchange_refresh_token(app, cfg, mocker, client_id):
    cls = app.extensions[cfg.APP_EXTENSION_KEY]
    mocker.patch(
        "requests.post",
        return_value=mocker.Mock(
            json=lambda: {
                "access_token": "new_test_access_token",
                "refresh_token": "new_test_refresh_token",
            }
        ),
    )
    tokens = cls.exchange_refresh_token(
        refresh_token="test_refresh_token", client_id=client_id
    )
    assert tokens.access_token == "new_test_access_token"
    assert tokens.refresh_token == "new_test_refresh_token"


def test_plugin_revoke_refresh_token(app, cfg, mocker, client_id):
    cls = app.extensions[cfg.APP_EXTENSION_KEY]
    mocker.patch(
        "requests.post",
    )

    cls.revoke_refresh_token(refresh_token="test_refresh_token", client_id=client_id)
