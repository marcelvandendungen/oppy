import jwt
import os
import sys

from flask import Flask
from provider.endpoints.authorize.authorize import create_blueprint as create_authorize_blueprint
from provider.endpoints.token.token import create_blueprint as create_token_blueprint
from provider.endpoints.register.register import create_blueprint as create_register_blueprint
from provider.endpoints.jwk.jwk import create_blueprint as create_jwk_blueprint
from provider.endpoints.metadata.metadata import create_blueprint as create_metadata_blueprint
from provider.endpoints.consent.consent import create_blueprint as create_consent_blueprint
from provider.endpoints.scim.scim import create_blueprint as create_scim_blueprint
from provider.endpoints.userinfo.userinfo import create_blueprint as create_userinfo_blueprint
from provider.model.store.client_store import client_store
from util import init_config, init_logging
from provider.model.authorize import AuthorizeError


def read_pem(filename):
    with open(filename, "rb") as f1:
        key = f1.read()
        return key


def init_crypto():
    """
      Read private and public key from PEM file on disk
    """
    if not os.path.exists("./private.pem"):
        raise IOError("private.pem not found or no permission to read")
    private_key = read_pem("./private.pem")
    if not os.path.exists("./public.pem"):
        raise IOError("public.pem not found or no permission to read")
    else:
        public_key = read_pem("./public.pem")

    return private_key, public_key


config = init_config('provider/config.yml')
logger = init_logging(__name__)

keypair = init_crypto()
app = Flask(__name__, static_url_path='')
# app.config['EXPLAIN_TEMPLATE_LOADING'] = True
app.config['TESTING'] = os.environ.get('TESTING') == 'True'
app.register_blueprint(create_authorize_blueprint(client_store, keypair[1], keypair[0]))
app.register_blueprint(create_token_blueprint(client_store, keypair[0], config))
app.register_blueprint(create_register_blueprint(client_store))
app.register_blueprint(create_jwk_blueprint())
app.register_blueprint(create_metadata_blueprint(config))
app.register_blueprint(create_consent_blueprint(config))
app.register_blueprint(create_scim_blueprint(config))
app.register_blueprint(create_userinfo_blueprint(config))


@app.errorhandler(Exception)
def error_handler(ex):
    logger.exception(ex)
    if isinstance(ex, (jwt.ExpiredSignatureError, jwt.DecodeError, AuthorizeError)):
        return str(ex), 401
    return str(ex), 500


def main():
    app.run(host='0.0.0.0', port=5000, debug=app.config['TESTING'],
            ssl_context=('cert.pem', 'key.pem'))


if __name__ == "__main__":
    sys.exit(main())
