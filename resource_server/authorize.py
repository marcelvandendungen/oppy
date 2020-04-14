from webclient.app import logger
import jwt
import requests
from functools import wraps
from flask import request
from jwcrypto import jwk
from util import init_config


def get_public_key(url):
    response = requests.get(url, verify=False)
    key = jwk.JWK.from_json(response.content)
    return key.export_to_pem()


config = init_config('config.yml')

public_key = get_public_key(config['endpoints']['issuer'] + config['endpoints']['jwks'])


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
