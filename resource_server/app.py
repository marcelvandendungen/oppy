from functools import wraps

import jwt
import os
import sys

from flask import Flask, request


def authorize(audience, scopes):
    def decorator(func):
        @wraps(func)
        def decorated(*args, **kwargs):
            auth_header = request.headers['Authorization']
            assert auth_header.startswith('Bearer ')
            claims = jwt.decode(str.encode(auth_header[7:]), public_key,
                                audience=audience, algorithm=['RS256'])
            request.view_args['claims'] = claims
            return func(*args, **kwargs)
        return decorated
    return decorator


app = Flask(__name__)
app.config['TESTING'] = os.environ.get('TESTING') == 'True'


def read_pem(filename):
    with open(filename, "rb") as f1:
        key = f1.read()
        return key


public_key = read_pem("./public.pem")


@app.route('/resource')
@authorize(audience='urn:my_service', scopes='read')    # must be innermost decorator
def resource():
    try:
        claims = request.view_args['claims']
        return str(claims)
    except KeyError as ex:
        return str(ex)


def main():
    print('running resource server')
    app.run(host='0.0.0.0', port=5001, debug=app.config['TESTING'])


if __name__ == "__main__":
    sys.exit(main())
