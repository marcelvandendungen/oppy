from provider.model.crypto import verify
import jwt
import requests
from functools import wraps
from flask import request
from jwcrypto import jwk


def get_public_key(url):
    response = requests.get(url, verify=False)
    key = jwk.JWK.from_json(response.content)
    return key.export_to_pem()


public_key = get_public_key('https://localhost:5000/jwk')


class AuthorizeError(Exception):
    def __init__(self, message, status):
        super().__init__(message)
        self.status = status


def validate_auth_header(headers, audience, scopes):
    if 'Authorization' not in headers:
        raise AuthorizeError('Missing authorization header', 401)

    auth_header = headers['Authorization']
    scheme, token = auth_header.split(' ')

    if scheme.lower() != 'bearer':
        raise AuthorizeError('Authorization scheme not supported', 401)
    claims = jwt.decode(str.encode(token), public_key,
                        audience=audience, algorithm=['RS256'])

    required_scopes = set(scopes.split(' '))
    granted_scopes = set(claims['scope'].split(' '))

    if not required_scopes.issubset(granted_scopes):
        raise AuthorizeError('required scope missing', 401)

    return claims


def authorize(audience, scopes):
    """
      Decorator to validate the authorization header of the incoming request.
      Pass required audience and scopes as arguments
    """
    def decorator(func):
        @wraps(func)
        def decorated(*args, **kwargs):
            claims = validate_auth_header(request.headers, audience, scopes)
            request.view_args['claims'] = claims
            return func(*args, **kwargs)
        return decorated
    return decorator
