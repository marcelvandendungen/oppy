import datetime
import logging
import os
import yaml
from urllib.parse import urlencode  # , urlparse, urlsplit, parse_qsl


def init_logging(name):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    filepath = os.getenv('LOG_PATH')
    if filepath:
        logging.basicConfig(filename=filepath, filemode='a',
                            format='%(asctime)s - %(message)s', level=logging.INFO)
    else:
        logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
    return logger


def require(parameters, key_name, error):
    if key_name not in parameters:
        raise error
    return parameters[key_name]


def init_config(path):
    config = yaml.load(open(path, 'r'), Loader=yaml.FullLoader)
    return config


def create_url(path, **query_params):
    return path + '?' + urlencode(query_params)


def get_iso_datetime():
    d = datetime.datetime.utcnow()
    return d.isoformat("T") + "Z"
