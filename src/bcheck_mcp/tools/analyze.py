"""analyze_request — parse a raw HTTP request and map every injection point."""

from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any


# Headers that are interesting for security testing
INTERESTING_HEADERS = {
    "authorization", "x-forwarded-for", "x-real-ip", "x-forwarded-host",
    "x-original-url", "x-rewrite-url", "referer", "origin", "host",
    "x-api-key", "x-auth-token", "x-access-token", "cookie",
    "content-type", "x-requested-with", "x-custom-ip-authorization",
    "x-forwarded-proto", "x-amz-security-token",
}

# Header → likely vuln class hints
HEADER_VULN_HINTS: dict[str, list[str]] = {
    "x-forwarded-for": ["ssrf", "header_injection"],
    "x-real-ip": ["ssrf", "header_injection"],
    "referer": ["open_redirect", "ssrf"],
    "origin": ["cors"],
    "x-forwarded-host": ["host_header_injection", "ssrf"],
    "x-original-url": ["ssrf", "path_traversal"],
    "authorization": ["auth_bypass", "idor"],
    "x-api-key": ["auth_bypass"],
}

# Content-type → body format
BODY_FORMATS = {
    "application/x-www-form-urlencoded": "form",
    "application/json": "json",
    "application/xml": "xml",
    "text/xml": "xml",
    "multipart/form-data": "multipart",
    "application/graphql": "graphql",
    "text/plain": "raw",
}


def analyze_request(
    raw_request: str,
    raw_response: str | None = None,
) -> dict[str, Any]:
    """
    Parse a raw HTTP/1.x request string and map every testable injection point.

    Args:
        raw_request: Raw HTTP request text (e.g. from Burp proxy history).
        raw_response: Optional raw HTTP response text (improves vuln suggestions).

    Returns:
        Structured dict with injection_points, suggested_vuln_classes, and
        bcheck_writing_hints for Claude to use when authoring BCheck DSL.
    """
    lines = raw_request.replace("\r\n", "\n").split("\n")
    if not lines:
        return {"error": "Empty request"}

    # ── Request line ──────────────────────────────────────────────────────
    request_line = lines[0].strip()
    parts = request_line.split(" ")
    method = parts[0] if len(parts) >= 1 else "GET"
    raw_path = parts[1] if len(parts) >= 2 else "/"
    protocol = parts[2] if len(parts) >= 3 else "HTTP/1.1"

    # Split path and query string
    if "?" in raw_path:
        path, query_string = raw_path.split("?", 1)
    else:
        path, query_string = raw_path, ""

    # ── Headers ───────────────────────────────────────────────────────────
    headers: dict[str, str] = {}
    body_start = None
    for i, line in enumerate(lines[1:], 1):
        if line.strip() == "":
            body_start = i + 1
            break
        if ":" in line:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()

    host = headers.get("host", "")
    content_type = headers.get("content-type", "").split(";")[0].strip().lower()
    body = "\n".join(lines[body_start:]) if body_start else ""

    # ── Determine scheme (guess from headers/port) ─────────────────────────
    scheme = "https" if (
        headers.get("x-forwarded-proto") == "https"
        or ":443" in host
    ) else "http"
    base_url = f"{scheme}://{host}{path}" if host else path

    # ── Query parameters ──────────────────────────────────────────────────
    query_params = _parse_query_string(query_string)

    # ── Body parameters ───────────────────────────────────────────────────
    body_format = BODY_FORMATS.get(content_type, "raw")
    body_params = _parse_body(body, body_format)

    # ── Path segments ─────────────────────────────────────────────────────
    path_segments = _parse_path_segments(path)

    # ── Cookies ───────────────────────────────────────────────────────────
    cookie_params = _parse_cookies(headers.get("cookie", ""))

    # ── Interesting headers for injection ─────────────────────────────────
    interesting_headers = [
        {"name": k, "value": v}
        for k, v in headers.items()
        if k in INTERESTING_HEADERS and k not in ("content-type", "host")
    ]

    # ── Injection point map ───────────────────────────────────────────────
    injection_points: list[dict] = []

    for p in query_params:
        injection_points.append({
            "location": "query",
            "name": p["name"],
            "value": p["value"],
            "bcheck_target": f'param value named "{p["name"]}"',
        })

    for p in body_params:
        injection_points.append({
            "location": "body",
            "name": p["name"],
            "value": p["value"],
            "body_format": body_format,
            "bcheck_target": f'param value named "{p["name"]}"' if body_format == "form"
                             else f'body param "{p["name"]}" (in {body_format} body)',
        })

    for seg in path_segments:
        if seg["is_numeric"]:
            injection_points.append({
                "location": "path",
                "name": f"path_segment_{seg['index']}",
                "value": seg["segment"],
                "bcheck_target": f'path segment at position {seg["index"]} (numeric: {seg["segment"]})',
            })

    for c in cookie_params:
        injection_points.append({
            "location": "cookie",
            "name": c["name"],
            "value": c["value"],
            "bcheck_target": f'cookie value named "{c["name"]}"',
        })

    for h in interesting_headers:
        injection_points.append({
            "location": "header",
            "name": h["name"],
            "value": h["value"],
            "bcheck_target": f'header value named "{h["name"]}"',
        })

    # ── Suggest vulnerability classes ─────────────────────────────────────
    suggested = _suggest_vulns(
        method=method,
        path=path,
        query_params=query_params,
        body_params=body_params,
        body_format=body_format,
        headers=headers,
        path_segments=path_segments,
        raw_response=raw_response or "",
    )

    # ── Response analysis (if provided) ───────────────────────────────────
    response_info: dict[str, Any] = {}
    if raw_response:
        response_info = _analyze_response(raw_response)

    # ── BCheck writing hints ──────────────────────────────────────────────
    bcheck_hints = _build_bcheck_hints(
        method=method,
        body_format=body_format,
        injection_points=injection_points,
        suggested_vulns=suggested,
        response_info=response_info,
    )

    return {
        "parsed": {
            "method": method,
            "url": base_url,
            "host": host,
            "path": path,
            "query_string": query_string,
            "protocol": protocol,
            "body_format": body_format,
            "body_length": len(body),
            "body_preview": body[:300] if body else "",
        },
        "query_params": query_params,
        "body_params": body_params,
        "path_segments": path_segments,
        "cookie_params": cookie_params,
        "interesting_headers": interesting_headers,
        "injection_points": injection_points,
        "suggested_vuln_classes": suggested,
        "response_info": response_info,
        "bcheck_hints": bcheck_hints,
        "total_injection_points": len(injection_points),
    }


# ── Parsers ───────────────────────────────────────────────────────────────────

def _parse_query_string(qs: str) -> list[dict]:
    if not qs:
        return []
    params = []
    for pair in qs.split("&"):
        if "=" in pair:
            name, _, value = pair.partition("=")
            params.append({
                "name": urllib.parse.unquote_plus(name),
                "value": urllib.parse.unquote_plus(value),
                "type": _infer_param_type(urllib.parse.unquote_plus(value)),
            })
        elif pair:
            params.append({"name": urllib.parse.unquote_plus(pair), "value": "", "type": "flag"})
    return params


def _parse_body(body: str, body_format: str) -> list[dict]:
    body = body.strip()
    if not body:
        return []

    if body_format == "form":
        return _parse_query_string(body)

    if body_format == "json":
        try:
            data = json.loads(body)
            return _flatten_json(data)
        except json.JSONDecodeError:
            return [{"name": "_raw_body", "value": body[:100], "type": "raw"}]

    if body_format in ("xml",):
        # Extract tag values via simple regex
        params = []
        for match in re.finditer(r"<([^/>\s]+)[^>]*>([^<]+)</\1>", body):
            params.append({
                "name": match.group(1),
                "value": match.group(2),
                "type": _infer_param_type(match.group(2)),
            })
        return params

    return [{"name": "_raw_body", "value": body[:100], "type": "raw"}]


def _flatten_json(data: Any, prefix: str = "") -> list[dict]:
    result = []
    if isinstance(data, dict):
        for k, v in data.items():
            key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (dict, list)):
                result.extend(_flatten_json(v, key))
            else:
                result.append({"name": key, "value": str(v), "type": _infer_param_type(str(v))})
    elif isinstance(data, list):
        for i, item in enumerate(data):
            result.extend(_flatten_json(item, f"{prefix}[{i}]"))
    else:
        result.append({"name": prefix or "_value", "value": str(data), "type": _infer_param_type(str(data))})
    return result


def _parse_path_segments(path: str) -> list[dict]:
    segments = [s for s in path.split("/") if s]
    result = []
    for i, seg in enumerate(segments):
        result.append({
            "segment": seg,
            "index": i,
            "is_numeric": bool(re.match(r"^\d+$", seg)),
            "is_uuid": bool(re.match(
                r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                seg, re.I
            )),
            "looks_like_id": bool(re.match(r"^\d+$", seg)) or bool(re.match(
                r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                seg, re.I
            )),
        })
    return result


def _parse_cookies(cookie_header: str) -> list[dict]:
    if not cookie_header:
        return []
    cookies = []
    for part in cookie_header.split(";"):
        part = part.strip()
        if "=" in part:
            name, _, value = part.partition("=")
            cookies.append({
                "name": name.strip(),
                "value": value.strip(),
                "type": _infer_param_type(value.strip()),
            })
    return cookies


def _infer_param_type(value: str) -> str:
    if re.match(r"^\d+$", value):
        return "integer"
    if re.match(r"^\d+\.\d+$", value):
        return "float"
    if value.lower() in ("true", "false"):
        return "boolean"
    if re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", value, re.I):
        return "uuid"
    if value.startswith("http://") or value.startswith("https://"):
        return "url"
    if "/" in value or ".." in value:
        return "path"
    try:
        json.loads(value)
        return "json_string"
    except Exception:
        pass
    return "string"


def _analyze_response(raw_response: str) -> dict:
    lines = raw_response.replace("\r\n", "\n").split("\n")
    status_line = lines[0] if lines else ""
    status_code = 0
    try:
        status_code = int(status_line.split(" ")[1])
    except (IndexError, ValueError):
        pass

    headers: dict[str, str] = {}
    body_start = None
    for i, line in enumerate(lines[1:], 1):
        if line.strip() == "":
            body_start = i + 1
            break
        if ":" in line:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()

    body = "\n".join(lines[body_start:]) if body_start else ""
    content_type = headers.get("content-type", "")

    return {
        "status_code": status_code,
        "content_type": content_type,
        "content_length": len(body),
        "body_preview": body[:300],
        "reflects_input": None,  # Claude will determine this
        "error_strings": _find_error_strings(body),
        "server": headers.get("server", ""),
        "x_powered_by": headers.get("x-powered-by", ""),
    }


def _find_error_strings(body: str) -> list[str]:
    patterns = [
        r"SQL syntax", r"mysql_fetch", r"ORA-\d+", r"PostgreSQL",
        r"SQLITE_ERROR", r"stack trace", r"exception", r"error",
        r"undefined variable", r"warning:", r"fatal error",
    ]
    found = []
    for p in patterns:
        if re.search(p, body, re.I):
            found.append(p.replace(r"\d+", "*"))
    return found


# ── Vuln class suggester ──────────────────────────────────────────────────────

def _suggest_vulns(
    method: str,
    path: str,
    query_params: list[dict],
    body_params: list[dict],
    body_format: str,
    headers: dict[str, str],
    path_segments: list[dict],
    raw_response: str,
) -> list[str]:
    vulns: list[str] = []

    all_params = query_params + body_params

    # Always suggest sqli if there are params
    if all_params:
        vulns.append("sqli")
        vulns.append("xss")

    # URL/path type params → ssrf, open_redirect, path_traversal
    for p in all_params:
        if p.get("type") == "url":
            if "open_redirect" not in vulns:
                vulns.append("open_redirect")
            if "ssrf" not in vulns:
                vulns.append("ssrf")
        if p.get("type") == "path" or "file" in p["name"].lower() or "path" in p["name"].lower():
            if "path_traversal" not in vulns:
                vulns.append("path_traversal")

    # XML body → XXE
    if body_format == "xml":
        vulns.append("xxe")

    # JSON body → still sqli/cmdi/ssrf depending on field names
    if body_format == "json":
        for p in body_params:
            name_lower = p["name"].lower()
            if any(x in name_lower for x in ("url", "uri", "redirect", "callback", "webhook", "endpoint")):
                if "ssrf" not in vulns:
                    vulns.append("ssrf")
            if any(x in name_lower for x in ("cmd", "exec", "command", "shell", "ping", "host")):
                if "cmdi" not in vulns:
                    vulns.append("cmdi")

    # Numeric path segments → IDOR
    if any(seg["is_numeric"] or seg["is_uuid"] for seg in path_segments):
        vulns.append("idor")

    # Header injection hints
    for h_name, hint_vulns in HEADER_VULN_HINTS.items():
        if h_name in headers:
            for v in hint_vulns:
                if v not in vulns:
                    vulns.append(v)

    # Path-based hints
    path_lower = path.lower()
    if any(x in path_lower for x in ("/exec", "/cmd", "/run", "/shell", "/ping")):
        if "cmdi" not in vulns:
            vulns.append("cmdi")
    if any(x in path_lower for x in ("/file", "/download", "/upload", "/read", "/include")):
        if "path_traversal" not in vulns:
            vulns.append("path_traversal")
    if any(x in path_lower for x in ("/redirect", "/forward", "/goto", "/out")):
        if "open_redirect" not in vulns:
            vulns.append("open_redirect")
    if any(x in path_lower for x in ("/fetch", "/proxy", "/request", "/url")):
        if "ssrf" not in vulns:
            vulns.append("ssrf")

    return vulns


# ── BCheck writing hints ──────────────────────────────────────────────────────

def _build_bcheck_hints(
    method: str,
    body_format: str,
    injection_points: list[dict],
    suggested_vulns: list[str],
    response_info: dict,
) -> dict:
    """Build concrete hints for Claude to use when writing BCheck DSL."""

    # BCheck DSL param targeting syntax
    param_targets: list[str] = []
    for pt in injection_points:
        loc = pt["location"]
        name = pt["name"]
        if loc == "query":
            param_targets.append(f'replacing param value named "{name}"')
        elif loc == "body" and body_format == "form":
            param_targets.append(f'replacing param value named "{name}"')
        elif loc == "body" and body_format == "json":
            param_targets.append(f'replacing json param value named "{name}"')
        elif loc == "cookie":
            param_targets.append(f'replacing cookie value named "{name}"')
        elif loc == "header":
            param_targets.append(f'replacing header value named "{name}"')
        elif loc == "path":
            param_targets.append('replacing each numeric path segment with <payload>')

    has_xml_body = body_format == "xml"
    has_json_body = body_format == "json"

    hints = {
        "bcheck_param_targets": list(dict.fromkeys(param_targets)),  # dedupe
        "use_send_payload_syntax": True,
        "body_replacement_needed": method in ("POST", "PUT", "PATCH") and body_format != "raw",
        "has_xml_body": has_xml_body,
        "has_json_body": has_json_body,
        "collaborator_useful_for": [v for v in ("ssrf", "xxe", "cmdi") if v in suggested_vulns],
        "time_based_useful_for": [v for v in ("sqli", "cmdi") if v in suggested_vulns],
        "writing_notes": [],
    }

    if has_json_body:
        hints["writing_notes"].append(
            "JSON body: use 'replacing json param value named \"<key>\"' syntax in BCheck DSL"
        )
    if has_xml_body:
        hints["writing_notes"].append(
            "XML body: replace full request.body with malicious XML payload for XXE testing"
        )
    if method == "GET":
        hints["writing_notes"].append(
            "GET request: all params are in query string, use 'replacing param value named ...' syntax"
        )
    if response_info.get("error_strings"):
        hints["writing_notes"].append(
            f"Response already contains error strings: {response_info['error_strings']} — "
            "error-based detection may have false positives; prefer time-based or OOB"
        )

    return hints
