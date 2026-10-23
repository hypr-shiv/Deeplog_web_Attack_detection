from __future__ import annotations

import csv
import io
import re
from typing import Any


# Required columns for CSV upload (case-insensitive)
REQUIRED_CSV_COLUMNS = {"timestamp", "source_ip", "method", "url", "status_code", "content_length"}

# Alternative column names that are acceptable
URL_ALTERNATIVES = {"url", "uri", "path", "request"}
METHOD_ALTERNATIVES = {"method", "http_method"}
TIMESTAMP_ALTERNATIVES = {"timestamp", "time", "date"}
SOURCE_IP_ALTERNATIVES = {"source_ip", "ip", "client_ip"}
STATUS_CODE_ALTERNATIVES = {"status_code", "status"}
CONTENT_LENGTH_ALTERNATIVES = {"content_length", "length", "size"}
CONTENT_ALTERNATIVES = {"content", "body", "payload", "data"}
CONTENT_TYPE_ALTERNATIVES = {"content_type", "content-type", "contenttype"}

def _safe_int(val: Any, default: int = 0) -> int:
    if val is None:
        return default
    cleaned = str(val).strip()
    if not cleaned or cleaned == "-":
        return default
    try:
        return int(float(cleaned))
    except (ValueError, TypeError):
        return default


def validate_csv_columns(fields: dict[str, str]) -> None:
    """
    Validate that the CSV has the required columns.
    Raises ValueError with a descriptive message if validation fails.
    """
    missing = []
    required_checks = [
        ("URL/request column", URL_ALTERNATIVES),
        ("HTTP method column", METHOD_ALTERNATIVES),
        ("Timestamp column", TIMESTAMP_ALTERNATIVES),
        ("Source IP column", SOURCE_IP_ALTERNATIVES),
        ("Status code column", STATUS_CODE_ALTERNATIVES),
        ("Content length column", CONTENT_LENGTH_ALTERNATIVES),
    ]

    for label, alternatives in required_checks:
        if not any(name in fields for name in alternatives):
            missing.append(label)

    if missing:
        raise ValueError(
            "CSV missing required columns: " + ", ".join(missing)
        )


def parse_csv_rows(text: str) -> list[dict[str, Any]]:
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ValueError("CSV file has no header row")

    fields = {field.strip().lower(): field for field in reader.fieldnames if field}
    validate_csv_columns(fields)

    url_field = next((fields[name] for name in URL_ALTERNATIVES if name in fields), None)
    method_field = next((fields[name] for name in METHOD_ALTERNATIVES if name in fields), None)
    timestamp_field = next((fields[name] for name in TIMESTAMP_ALTERNATIVES if name in fields), None)
    source_ip_field = next((fields[name] for name in SOURCE_IP_ALTERNATIVES if name in fields), None)
    status_code_field = next((fields[name] for name in STATUS_CODE_ALTERNATIVES if name in fields), None)
    content_length_field = next((fields[name] for name in CONTENT_LENGTH_ALTERNATIVES if name in fields), None)
    content_field = next((fields[name] for name in CONTENT_ALTERNATIVES if name in fields), None)
    content_type_field = next((fields[name] for name in CONTENT_TYPE_ALTERNATIVES if name in fields), None)

    results = []
    for row_index, row in enumerate(reader, start=2):
        status_code = _safe_int(row.get(status_code_field, 0), 0)
        content_length = _safe_int(row.get(content_length_field, 0), 0)

        req = {
            "timestamp": row.get(timestamp_field, ""),
            "source_ip": row.get(source_ip_field, "Unknown"),
            "method": row.get(method_field, "GET"),
            "url": row.get(url_field, ""),
            "status_code": status_code,
            "content_length": content_length,
            "content": row.get(content_field, "") if content_field else "",
            "content_type": row.get(content_type_field, "") if content_type_field else "",
        }
        results.append(req)
    return results


COMBINED_LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Za-z]+)\s+(?P<url>[^\s"]+)[^"]*"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
)
SIMPLE_HTTP_PATTERN = re.compile(
    r'"?(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+([^\s"]+)',
    re.IGNORECASE,
)
IP_EXTRACT_PATTERN = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')


def parse_text_rows(text: str) -> list[dict[str, Any]]:
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        match_combined = COMBINED_LOG_PATTERN.match(line)
        if match_combined:
            size_val = match_combined.group("size")
            rows.append({
                "source_ip": match_combined.group("ip"),
                "timestamp": match_combined.group("time"),
                "method": match_combined.group("method").upper(),
                "url": match_combined.group("url"),
                "status_code": _safe_int(match_combined.group("status"), 200),
                "content_length": _safe_int(size_val, 0),
                "content": "",
                "content_type": "",
            })
            continue

        match_simple = SIMPLE_HTTP_PATTERN.search(line)
        if match_simple:
            ip_match = IP_EXTRACT_PATTERN.search(line)
            rows.append({
                "source_ip": ip_match.group(1) if ip_match else "Unknown",
                "method": match_simple.group(1).upper(),
                "url": match_simple.group(2),
                "status_code": 200,
                "content_length": 0,
                "content": "",
                "content_type": "",
            })
    return rows
