import base64
import hashlib
import secrets
import string


AUTH_CODE_LEN = 12  # default length of issues authorization codes
VERIFIER_LEN = 43   # default length of PKCE code challenge

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
