import datetime
import logging
import yaml
from urllib.parse import urlencode  # , urlparse, urlsplit, parse_qsl


def init_logging(name):
    ""
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
    return logger


def require(parameters, key_name, error):
    if key_name not in parameters:
        raise error
    return parameters[key_name]


def init_config(path):
    config = yaml.safe_load(open(path, 'r'))
    return config


def create_url(path, **query_params):
    return path + '?' + urlencode(query_params)


def get_iso_datetime():
    d = datetime.datetime.utcnow()
    return d.isoformat("T") + "Z"
