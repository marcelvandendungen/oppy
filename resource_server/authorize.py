import jwt
from functools import wraps
from flask import request


def read_pem(filename):
    with open(filename, "rb") as f1:
        key = f1.read()
        return key


public_key = read_pem("./public.pem")


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

    required_scopes = {scopes.split(' ')}
    granted_scopes = {claims['scope'].split(' ')}

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
