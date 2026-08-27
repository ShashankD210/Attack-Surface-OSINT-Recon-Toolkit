#!/usr/bin/env python3
"""
json_io.py — shared helpers for reading/writing JSON with optional gzip compression.
"""
import gzip
import json
import os


def load_json(path: str):
    """Load JSON from a plain or .json.gz file."""
    if not os.path.isfile(path):
        gz_path = path + ".gz"
        if os.path.isfile(gz_path):
            path = gz_path
        else:
            return None
    if path.endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8") as f:
            return json.load(f)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(data, path: str, compress: bool = False):
    """Save data as JSON, optionally gzip-compressed."""
    if compress:
        path = path + ".gz"
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if compress:
        with gzip.open(path, "wt", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
    else:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
    return path
