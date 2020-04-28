import jwt
from functools import wraps
from flask import request
from util import init_config, init_logging


def get_public_key(filename):
    with open(filename, "rb") as f1:
        key = f1.read()
        return key


config = init_config('config.yml')
logger = init_logging(__name__)
public_key = get_public_key("./public.pem")


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
                        audience=audience, algorithms='RS256')

    required_scopes = set(scopes.split(' '))
    logger.info('required scopes: ' + ' '.join(required_scopes))
    granted_scopes = set(claims['scope'].split(' '))
    logger.info('granted scopes: ' + ' '.join(granted_scopes))

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
