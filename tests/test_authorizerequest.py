import pytest

from provider.model.authorize_request import AuthorizeRequest, AuthorizeRequestError


def test_validate_scopes_with_valid_scopes():
    """
      GIVEN: Client configured with given scope
      WHEN: AuthorizationRequest requesting same scope
      THEN: validate_scope returns requested scope
    """
    client = {
        'scope': 'read write'
    }
    ar = AuthorizeRequest(scope='read write')
    scopes = ar.validate_scopes(client)
    assert scopes == 'read write'


def test_validate_scopes_with_invalid_scopes():
    """
      GIVEN: Client configured with given scope
      WHEN: AuthorizationRequest requesting different scope
      THEN: validate_scope raises a AuthorizeRequestError
    """
    client = {
        'scope': 'openid'
    }
    ar = AuthorizeRequest(scope='read write')
    with pytest.raises(AuthorizeRequestError):
        ar.validate_scopes(client)


def test_validate_scopes_with_no_scopes():
    """
      GIVEN: Client configured with given scope
      WHEN: AuthorizationRequest with no specified scope
      THEN: validate_scope returns scope configured in client
    """
    client = {
        'scope': 'read write'
    }
    ar = AuthorizeRequest()
    scopes = ar.validate_scopes(client)
    assert scopes == 'read write'


def test_validate_pkce_raises_error_when_code_challenge_missing():
    """
      GIVEN: Public client configured
      WHEN: AuthorizationRequest with code_challenge attribute missing
      THEN: validate_pkce raises a AuthorizeRequestError
    """
    client = {
        'scope': 'read write',
        'token_endpoint_auth_method': 'None'
    }
    with pytest.raises(AuthorizeRequestError):
        ar = AuthorizeRequest()
        ar.validate_pkce(client)


def test_validate_pkce_raises_error_when_code_challenge_method_incorrect():
    """
      GIVEN: Public client configured
      WHEN: AuthorizationRequest with unsupported code_challenge_method attribute
      THEN: validate_pkce raises a AuthorizeRequestError
    """
    client = {
        'scope': 'read write',
        'token_endpoint_auth_method': 'None',
        'code_challenge_method': 'plain'
    }
    with pytest.raises(AuthorizeRequestError):
        ar = AuthorizeRequest()
        ar.validate_pkce(client)
