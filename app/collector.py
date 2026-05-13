from pathlib import Path
from .config import LOG_SOURCES
from .parsers import parse_line
from .db import insert_event

def existing_file(paths):
    for p in paths:
        path = Path(p)
        if path.exists() and path.is_file():
            return path
    return None

def ingest_tail(lines_per_file=2000):
    count = 0
    for source, paths in LOG_SOURCES.items():
        path = existing_file(paths)
        if not path:
            continue
        try:
            with path.open("r", errors="ignore") as f:
                lines = f.readlines()[-lines_per_file:]
        except PermissionError:
            continue
        for line in lines:
            if not line.strip():
                continue
            event = parse_line(source, line)
            insert_event(event)
            count += 1
    return count
