"""Structured JSON logging — shared across all MCP servers."""
import json
import logging
import os
import sys
import time


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        payload: dict = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, val in vars(record).items():
            if key.startswith("ctx_"):
                payload[key[4:]] = val
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(_JsonFormatter())
        logger.addHandler(handler)
    logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
    return logger


class ToolTimer:
    """Context manager that logs tool duration + outcome."""

    def __init__(self, logger: logging.Logger, tool: str, **ctx):
        self._log = logger
        self._tool = tool
        self._ctx = ctx
        self._start = 0.0

    def __enter__(self):
        self._start = time.monotonic()
        self._log.info(
            "tool_start",
            extra={f"ctx_{k}": v for k, v in {**self._ctx, "tool": self._tool}.items()},
        )
        return self

    def __exit__(self, exc_type, exc_val, _tb):
        elapsed_ms = round((time.monotonic() - self._start) * 1000)
        level = logging.ERROR if exc_type else logging.INFO
        outcome = "error" if exc_type else "ok"
        self._log.log(
            level,
            "tool_end",
            extra={
                f"ctx_{k}": v
                for k, v in {
                    **self._ctx,
                    "tool": self._tool,
                    "duration_ms": elapsed_ms,
                    "outcome": outcome,
                }.items()
            },
            exc_info=exc_val if exc_type else None,
        )
        return False  # never suppress exceptions
