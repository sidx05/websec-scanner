"""
Logging setup utilities.
"""

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from config import get_config


def setup_logging():
    cfg = get_config()
    logs_dir = Path(cfg.get('logs_dir', 'logs'))
    logs_dir.mkdir(exist_ok=True)
    log_file = logs_dir / 'app.log'

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch_formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    ch.setFormatter(ch_formatter)

    # Rotating file handler
    fh = RotatingFileHandler(str(log_file), maxBytes=2_000_000, backupCount=3)
    fh.setLevel(logging.INFO)
    fh_formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    fh.setFormatter(fh_formatter)

    # Avoid duplicate handlers if reinitialized
    if not any(isinstance(h, RotatingFileHandler) for h in logger.handlers):
        logger.addHandler(ch)
        logger.addHandler(fh)
