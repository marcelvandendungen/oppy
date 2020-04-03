import os
import sys

from flask import Flask
from provider.endpoints.authorize.authorize import create_blueprint as create_authorize_blueprint
from provider.endpoints.token.token import create_blueprint as create_token_blueprint
from provider.endpoints.register.register import create_blueprint as create_register_blueprint
from provider.endpoints.jwk.jwk import create_blueprint as create_jwk_blueprint
from provider.endpoints.metadata.metadata import create_blueprint as create_metadata_blueprint
from provider.endpoints.consent.consent import create_blueprint as create_consent_blueprint
from provider.model.client_store import client_store
from util import init_config


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


config = init_config('config.yml')

keypair = init_crypto()
app = Flask(__name__, static_url_path='')
# app.config['EXPLAIN_TEMPLATE_LOADING'] = True
app.config['TESTING'] = os.environ.get('TESTING') == 'True'
app.register_blueprint(create_authorize_blueprint(client_store))
app.register_blueprint(create_token_blueprint(client_store, keypair, config))
app.register_blueprint(create_register_blueprint(client_store))
app.register_blueprint(create_jwk_blueprint())
app.register_blueprint(create_metadata_blueprint(config))
app.register_blueprint(create_consent_blueprint(config))


def main():
    print('running main')
    app.run(host='0.0.0.0', port=5000, debug=app.config['TESTING'],
            ssl_context=('cert.pem', 'key.pem'))


if __name__ == "__main__":
    sys.exit(main())
