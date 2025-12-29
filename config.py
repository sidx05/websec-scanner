"""
Configuration loader.
"""

from pathlib import Path
import yaml

_DEFAULTS = {
    'http_timeout': 10,
    'verify_ssl': False,
    'user_agent': 'WebsiteScanner/1.0',
    'auto_save_reports': True,
    'reports_dir': 'reports',
    'logs_dir': 'logs',
}

_cfg_cache = None


def get_config() -> dict:
    global _cfg_cache
    if _cfg_cache is not None:
        return _cfg_cache
    cfg = dict(_DEFAULTS)
    cfg_path = Path('config.yaml')
    if cfg_path.exists():
        with cfg_path.open('r', encoding='utf-8') as f:
            data = yaml.safe_load(f) or {}
            cfg.update(data)
    _cfg_cache = cfg
    return cfg
