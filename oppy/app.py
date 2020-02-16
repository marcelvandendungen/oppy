from flask import Flask
from oppy.authorize_endpoint.authorize_bp import authorize_bp
from oppy.token_endpoint.token_bp import token_bp

app = Flask(__name__)
app.register_blueprint(authorize_bp)
app.register_blueprint(token_bp)
