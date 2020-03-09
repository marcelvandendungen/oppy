from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from jwcrypto import jwk

import base64
import hashlib
import secrets
import string


AUTH_CODE_LEN = 12  # default length of issues authorization codes
VERIFIER_LEN = 43   # default length of PKCE code challenge
RSA_KEY_LEN = 2048  # minimal key length for RSA

DIGIT = string.digits
ALPHA = string.ascii_letters
alphabet = ALPHA + DIGIT
unreserved = alphabet + "-._~"


def generate_code(length=AUTH_CODE_LEN):
    code = ''.join(secrets.choice(alphabet) for i in range(length))
    return code


def generate_verifier(length=VERIFIER_LEN):
    length = max(length, VERIFIER_LEN)  # length should be at least 43 characters
    verifier = ''.join(secrets.choice(unreserved) for i in range(length))
    return verifier


def generate_challenge(code_verifier):
    m = hashlib.sha256()
    m.update(code_verifier.encode())
    return base64.urlsafe_b64encode(m.digest())


def require(parameters, key_name, error):
    if key_name not in parameters:
        raise error
    return parameters[key_name]


def generate_keypair(length=RSA_KEY_LEN):
    """
      Generates RSA keypair of at least RSA_KEY_LEN bytes
    """
    length = max(length, RSA_KEY_LEN)  # length should be at least 2048 bytes
    private_key = RSA.generate(length)
    public_key = private_key.publickey()
    return private_key, public_key


def sign(message, priv_key):
    """
      Signs message with private key and returns the signature
    """
    signer = PKCS1_v1_5.new(priv_key)
    digest = SHA256.new()
    digest.update(message)
    return signer.sign(digest)


def verify(message, signature, pub_key):
    """
      Verifies the message signature using the public key and True if correct
    """
    signer = PKCS1_v1_5.new(pub_key)
    digest = SHA256.new()
    digest.update(message)
    return signer.verify(digest, signature)


def get_jwk():
    """
      Returns public key in JWK (RFC 7517) format
    """
    with open("public.pem", "rb") as pemfile:
        key = jwk.JWK.from_pem(pemfile.read())

    return key.export(private_key=False)
