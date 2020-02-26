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
    code = ''.join(secrets.choice(alphabet) for i in range(AUTH_CODE_LEN))
    return code


def generate_verifier(length=VERIFIER_LEN):
    verifier = ''.join(secrets.choice(unreserved) for i in range(length))
    return verifier


def generate_challenge(code_verifier):
    m = hashlib.sha256()
    m.update(code_verifier.encode())
    return m.digest()
