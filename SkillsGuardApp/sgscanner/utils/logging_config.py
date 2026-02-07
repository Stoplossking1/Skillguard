import logging
import sys

def setup_logger(name: str, level: str | None=None, format_string: str | None=None) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    sgscanner_root = logging.getLogger('sgscanner')
    if sgscanner_root.level == logging.DEBUG and name.startswith('sgscanner'):
        logger.setLevel(logging.DEBUG)
    elif level:
        logger.setLevel(getattr(logging, level.upper()))
    else:
        logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logger.level)
    default_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    formatter = logging.Formatter(format_string or default_format)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.propagate = False
    return logger

def get_logger(name: str, level: str | None=None) -> logging.Logger:
    return setup_logger(name, level)

def set_verbose_logging(verbose: bool=False) -> None:
    target_level = logging.DEBUG if verbose else logging.INFO
    root_logger = logging.getLogger('sgscanner')
    root_logger.setLevel(target_level)
    for name in list(logging.Logger.manager.loggerDict.keys()):
        if name.startswith('sgscanner'):
            logger = logging.getLogger(name)
            logger.setLevel(target_level)
            for handler in logger.handlers:
                handler.setLevel(target_level)
