"""Structured logging — terminal + per-target scan.log."""
import logging
import sys
from pathlib import Path
from colorama import Fore, Style, init as _ca_init

_ca_init(autoreset=True)


class _ColoredFormatter(logging.Formatter):
    COLORS = {
        "DEBUG": Fore.CYAN, "INFO": Fore.GREEN,
        "WARNING": Fore.YELLOW, "ERROR": Fore.RED,
        "CRITICAL": Fore.RED + Style.BRIGHT,
    }

    def format(self, record):
        color = self.COLORS.get(record.levelname, "")
        tag = f"{color}[{record.levelname[:4]}]{Style.RESET_ALL}"
        return f"{tag} {record.getMessage()}"


class _PlainFormatter(logging.Formatter):
    def format(self, record):
        ts = self.formatTime(record, "%Y-%m-%dT%H:%M:%S")
        return f"{ts} {record.levelname} {record.name} {record.getMessage()}"


def setup_logging(level=logging.INFO) -> logging.Logger:
    root = logging.getLogger("main")
    root.setLevel(level)
    root.handlers.clear()
    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(_ColoredFormatter())
    root.addHandler(sh)
    return root


def attach_file_handler(logger: logging.Logger, log_path: Path):
    for h in list(logger.handlers):
        if isinstance(h, logging.FileHandler):
            logger.removeHandler(h)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    fh = logging.FileHandler(log_path, mode="a")
    fh.setFormatter(_PlainFormatter())
    logger.addHandler(fh)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"main.{name}")
