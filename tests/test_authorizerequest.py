import pytest

from provider.model.authorize_request import AuthorizeRequest, AuthorizeRequestError


def test_validate_scopes_with_valid_scopes():
    client = {
        'scope': 'read write'
    }
    ar = AuthorizeRequest(scope='read write')
    ar.validate_scopes(client)
    assert ar.scope == 'read write'


def test_validate_scopes_with_invalid_scopes():
    client = {
        'scope': 'openid'
    }
    ar = AuthorizeRequest(scope='read write')
    with pytest.raises(AuthorizeRequestError):
        ar.validate_scopes(client)


def test_validate_scopes_with_no_scopes():
    client = {
        'scope': 'read write'
    }
    ar = AuthorizeRequest()
    scopes = ar.validate_scopes(client)
    assert scopes == 'read write'
