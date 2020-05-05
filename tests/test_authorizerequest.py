import pytest

from provider.model.oauth2.authorize_request import AuthorizeRequest, AuthorizeRequestError, BadAuthorizeRequestError


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
    with pytest.raises(AuthorizeRequestError) as ex:
        ar.validate_scopes(client)
    assert ex.value.args[0] == 'invalid_scope'
    assert ex.value.args[1] == 'One or more scopes are invalid'


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
    with pytest.raises(AuthorizeRequestError) as ex:
        ar = AuthorizeRequest()
        ar.validate_pkce(client)
    assert ex.value.args[0] == 'invalid_request'
    assert ex.value.args[1] == 'code challenge required'


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
    with pytest.raises(AuthorizeRequestError) as ex:
        ar = AuthorizeRequest(code_challenge='')
        ar.validate_pkce(client)
    assert ex.value.args[1] == 'invalid_request'
    assert ex.value.args[2] == 'Invalid code challenge method'


def test_override_redirect_uri_no_override():
    """
      GIVEN: Client configured with whitelisted redirect_uris
      WHEN: AuthorizationRequest without explicit redirect_uri
      THEN: override_redirect_uri uses first whitelisted redirect_uri
    """
    redirect_uri = 'https://localhost:5000/cb'
    client = {
        'redirect_uris': [redirect_uri]
    }
    ar = AuthorizeRequest()
    ar.override_redirect_uri(client)
    assert ar.redirect_uri == redirect_uri


def test_override_redirect_uri_with_override():
    """
      GIVEN: Client configured with whitelisted redirect_uris
      WHEN: AuthorizationRequest with explicit redirect_uri
      THEN: override_redirect_uri uses specified redirect_uri
    """
    redirect_uri1 = 'https://localhost:5001/cb'
    redirect_uri2 = 'https://localhost:5000/cb'
    client = {
        'redirect_uris': [redirect_uri1, redirect_uri2]
    }
    ar = AuthorizeRequest(redirect_uri=redirect_uri2)
    ar.override_redirect_uri(client)
    assert ar.redirect_uri == redirect_uri2


def test_override_redirect_uri_with_invalid_override():
    """
      GIVEN: Client configured with whitelisted redirect_uris
      WHEN: AuthorizationRequest with explicit redirect_uri that is not in whitelisted uris
      THEN: override_redirect_uri raises an AuthorizeRequestError
    """
    redirect_uri1 = 'https://localhost:5001/cb'
    redirect_uri2 = 'https://localhost:5000/cb'
    client = {
        'redirect_uris': [redirect_uri1, redirect_uri2]
    }
    with pytest.raises(BadAuthorizeRequestError) as ex:
        ar = AuthorizeRequest(redirect_uri='https://localhost:5002/cb')
        ar.override_redirect_uri(client)
    assert ex.value.args[0] == 'invalid_redirect_uri'
    assert ex.value.args[1] == 'Not a registered redirect uri'
