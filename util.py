import logging
import yaml


def init_logging(name):
    print('Init logging for ' + name)
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
    return logger


def require(parameters, key_name, error):
    if key_name not in parameters:
        raise error
    return parameters[key_name]


def init_config(path):
    config = yaml.load(open(path, 'r'), Loader=yaml.FullLoader)
    return config
