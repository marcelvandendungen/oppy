import logging


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
