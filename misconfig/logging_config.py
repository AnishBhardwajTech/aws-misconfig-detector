"""JSON-lines logging so Logstash/Filebeat can ship scan events into Elasticsearch."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone

STD = set(vars(logging.LogRecord("", 0, "", 0, "", (), None))) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    def format(self, record):
        doc = {
            "@timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "app": "aws-misconfig-detector",
        }
        doc.update({k: v for k, v in vars(record).items() if k not in STD})
        return json.dumps(doc, default=str)


def setup_logging(log_file: str | None = None, level: str | None = None) -> None:
    root = logging.getLogger()
    root.setLevel(level or os.environ.get("LOG_LEVEL", "INFO"))
    root.handlers.clear()
    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root.addHandler(console)
    path = log_file or os.environ.get("SCAN_LOG_FILE")
    if path:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        fh = logging.FileHandler(path)
        fh.setFormatter(JsonFormatter())
        root.addHandler(fh)
