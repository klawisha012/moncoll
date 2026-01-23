#/usr/bin/env python3

import pytest
import requests
import time
import subprocess
import json

# Test data: rule_id -> payload info
# Each entry has 'payload', 'method', 'headers', 'params', 'data', 'files'
protocol_payloads = {
    "920100": {
        "payload": "invalid request line",
        "method": "GET",
        "headers": {},
        "params": {},
        "data": None,
        "files": None,
        "note": "Invalid HTTP Request Line - hard to test with requests, skip"
    },
    "920120": {
        "payload": "file\";=",
        "method": "POST",
        "headers": {"Content-Type": "multipart/form-data"},
        "params": {},
        "data": None,
        "files": {"file": ("file\";=", "content")},
        "note": "Multipart name evasion"
    },
    "920160": {
        "payload": "abc",
        "method": "POST",
        "headers": {"Content-Length": "abc"},
        "params": {},
        "data": "some data",
        "files": None,
        "note": "Content-Length not numeric"
    },
    "920170": {
        "payload": "body",
        "method": "GET",
        "headers": {"Content-Length": "4"},
        "params": {},
        "data": "body",
        "files": None,
        "note": "GET with body"
    },
    "920171": {
        "payload": "body",
        "method": "GET",
        "headers": {"Transfer-Encoding": "chunked"},
        "params": {},
        "data": "body",
        "files": None,
        "note": "GET with Transfer-Encoding"
    },
    "920180": {
        "payload": "post data",
        "method": "POST",
        "headers": {},
        "params": {},
        "data": "post data",
        "files": None,
        "note": "POST without Content-Length or Transfer-Encoding"
    },
    "920181": {
        "payload": "data",
        "method": "POST",
        "headers": {"Content-Length": "4", "Transfer-Encoding": "chunked"},
        "params": {},
        "data": "data",
        "files": None,
        "note": "Content-Length and Transfer-Encoding present"
    },
    "920190": {
        "payload": "bytes=10-5",
        "method": "GET",
        "headers": {"Range": "bytes=10-5"},
        "params": {},
        "data": None,
        "files": None,
        "note": "Invalid Range: first > second"
    },
    "920210": {
        "payload": "keep-alive, keep-alive",
        "method": "GET",
        "headers": {"Connection": "keep-alive, keep-alive"},
        "params": {},
        "data": None,
        "files": None,
        "note": "Duplicate Connection header values"
    },
    "920220": {
        "payload": "%'/",
        "method": "GET",
        "headers": {},
        "params": {"param": "%'/ "},
        "data": None,
        "files": None,
        "note": "URL encoding abuse"
    },
    "920221": {
        "payload": "file%",
        "method": "GET",
        "headers": {},
        "params": {},
        "data": None,
        "files": None,
        "note": "URL encoding in basename"
    },
    "920250": {
        "payload": "\x80",
        "method": "GET",
        "headers": {},
        "params": {"param": "\x80"},
        "data": None,
        "files": None,
        "note": "UTF8 encoding abuse"
    },
    "920260": {
        "payload": "%uff00",
        "method": "GET",
        "headers": {},
        "params": {"param": "%uff00"},
        "data": None,
        "files": None,
        "note": "Unicode full/half width"
    },
    "920270": {
        "payload": "\x00",
        "method": "GET",
        "headers": {},
        "params": {"param": "\x00"},
        "data": None,
        "files": None,
        "note": "Invalid character (null)"
    },
    "920280": {
        "payload": None,
        "method": "GET",
        "headers": {},
        "params": {},
        "data": None,
        "files": None,
        "note": "Missing Host header"
    },
    "920290": {
        "payload": "",
        "method": "GET",
        "headers": {"Host": ""},
        "params": {},
        "data": None,
        "files": None,
        "note": "Empty Host header"
    },
    "920310": {
        "payload": "",
        "method": "GET",
        "headers": {"Accept": ""},
        "params": {},
        "data": None,
        "files": None,
        "note": "Empty Accept header"
    },
    "920311": {
        "payload": "",
        "method": "GET",
        "headers": {"Accept": ""},
        "params": {},
        "data": None,
        "files": None,
        "note": "Empty Accept header without UA"
    },
    "920330": {
        "payload": "",
        "method": "GET",
        "headers": {"User-Agent": ""},
        "params": {},
        "data": None,
        "files": None,
        "note": "Empty User-Agent header"
    },
    "920340": {
        "payload": "data",
        "method": "POST",
        "headers": {"Content-Length": "4"},
        "params": {},
        "data": "data",
        "files": None,
        "note": "Content with missing Content-Type"
    },
    "920350": {
        "payload": "127.0.0.1",
        "method": "GET",
        "headers": {"Host": "127.0.0.1"},
        "params": {},
        "data": None,
        "files": None,
        "note": "Host header is IP address"
    },
    "920360": {
        "payload": "a" * 200,
        "method": "GET",
        "headers": {},
        "params": {"a" * 200: "value"},
        "data": None,
        "files": None,
        "note": "Arg name too long"
    },
    "920370": {
        "payload": "b" * 500,
        "method": "GET",
        "headers": {},
        "params": {"param": "b" * 500},
        "data": None,
        "files": None,
        "note": "Arg value too long"
    },
    "920380": {
        "payload": "too many args",
        "method": "GET",
        "headers": {},
        "params": {f"arg{i}": "value" for i in range(200)},
        "data": None,
        "files": None,
        "note": "Too many arguments"
    },
    "920390": {
        "payload": "total size exceeded",
        "method": "GET",
        "headers": {},
        "params": {"param": "x" * 10000},
        "data": None,
        "files": None,
        "note": "Total args size exceeded"
    },
    "920400": {
        "payload": "large file",
        "method": "POST",
        "headers": {"Content-Type": "multipart/form-data"},
        "params": {},
        "data": None,
        "files": {"file": ("file", "x" * 100000)},
        "note": "Uploaded file size too large"
    },
    "920410": {
        "payload": "combined large files",
        "method": "POST",
        "headers": {"Content-Type": "multipart/form-data"},
        "params": {},
        "data": None,
        "files": {"file1": ("f1", "x" * 50000), "file2": ("f2", "y" * 50000)},
        "note": "Combined file sizes too large"
    },
    "920420": {
        "payload": "application/octet-stream",
        "method": "POST",
        "headers": {"Content-Type": "application/octet-stream"},
        "params": {},
        "data": "data",
        "files": None,
        "note": "Content-Type not allowed"
    },
    "920430": {
        "payload": "HTTP/1.0",
        "method": "GET",
        "headers": {},
        "params": {},
        "data": None,
        "files": None,
        "note": "HTTP protocol version not allowed"
    },
    "920440": {
        "payload": ".exe",
        "method": "GET",
        "headers": {},
        "params": {},
        "data": None,
        "files": None,
        "note": "File extension restricted"
    },
    "920450": {
        "payload": "proxy",
        "method": "GET",
        "headers": {"Proxy": "bad"},
        "params": {},
        "data": None,
        "files": None,
        "note": "Restricted header"
    },
    "920460": {
        "payload": "\\c",
        "method": "GET",
        "headers": {},
        "params": {"param": "\\c"},
        "data": None,
        "files": None,
        "note": "Abnormal character escapes"
    },
    "920470": {
        "payload": "invalid; ;",
        "method": "POST",
        "headers": {"Content-Type": "invalid; ;"},
        "params": {},
        "data": "data",
        "files": None,
        "note": "Illegal Content-Type header"
    },
    "920480": {
        "payload": "invalid-charset",
        "method": "POST",
        "headers": {"Content-Type": "text/plain; charset=invalid-charset"},
        "params": {},
        "data": "data",
        "files": None,
        "note": "Content-Type charset not allowed"
    },
    "920490": {
        "payload": "utf-8",
        "method": "POST",
        "headers": {"x-up-devcap-post-charset": "utf-8", "User-Agent": "UP Browser"},
        "params": {},
        "data": "data",
        "files": None,
        "note": "x-up-devcap-post-charset with UP UA"
    },
    "920500": {
        "payload": "file~",
        "method": "GET",
        "headers": {},
        "params": {},
        "data": None,
        "files": None,
        "note": "Backup file extension"
    },
    "920510": {
        "payload": "invalid-directive",
        "method": "GET",
        "headers": {"Cache-Control": "invalid-directive"},
        "params": {},
        "data": None,
        "files": None,
        "note": "Invalid Cache-Control header"
    },
    "920520": {
        "payload": "x" * 60,
        "method": "GET",
        "headers": {"Accept-Encoding": "x" * 60},
        "params": {},
        "data": None,
        "files": None,
        "note": "Accept-Encoding too long"
    },
    "920521": {
        "payload": "invalid-encoding",
        "method": "GET",
        "headers": {"Accept-Encoding": "invalid-encoding"},
        "params": {},
        "data": None,
        "files": None,
        "note": "Illegal Accept-Encoding"
    },
    "920530": {
        "payload": "charset=utf-8; charset=utf-8",
        "method": "POST",
        "headers": {"Content-Type": "text/plain; charset=utf-8; charset=utf-8"},
        "params": {},
        "data": "data",
        "files": None,
        "note": "Multiple charsets in Content-Type"
    },
    "920540": {
        "payload": "\\u0041",
        "method": "GET",
        "headers": {},
        "params": {"param": "\\u0041"},
        "data": None,
        "files": None,
        "note": "Unicode character bypass"
    },
    "920600": {
        "payload": "invalid-charset",
        "method": "GET",
        "headers": {"Accept": "text/html; charset=invalid-charset"},
        "params": {},
        "data": None,
        "files": None,
        "note": "Illegal Accept header charset"
    },
    "920610": {
        "payload": "#",
        "method": "GET",
        "headers": {},
        "params": {},
        "data": None,
        "files": None,
        "note": "Raw fragment in request URI"
    },
    "920620": {
        "payload": "double",
        "method": "POST",
        "headers": {"Content-Type": "application/json", "Content-Type": "text/plain"},
        "params": {},
        "data": '{"key": "value"}',
        "files": None,
        "note": "Multiple Content-Type headers"
    },
    "920200": {
        "payload": "bytes=1-1,2-2,3-3,4-4,5-5,6-6,7-7",
        "method": "GET",
        "headers": {"Range": "bytes=1-1,2-2,3-3,4-4,5-5,6-6,7-7"},
        "params": {},
        "data": None,
        "files": None,
        "note": "Range with too many fields"
    },
    "920201": {
        "payload": "bytes=" + ",".join([f"{i}-{i}" for i in range(63)]),
        "method": "GET",
        "headers": {"Range": "bytes=" + ",".join([f"{i}-{i}" for i in range(63)])},
        "params": {},
        "data": None,
        "files": None,
        "note": "Range with 63 fields for PDF"
    },
    "920202": {
        "payload": "bytes=" + ",".join([f"{i}-{i}" for i in range(6)]),
        "method": "GET",
        "headers": {"Range": "bytes=" + ",".join([f"{i}-{i}" for i in range(6)])},
        "params": {},
        "data": None,
        "files": None,
        "note": "Range with 6 fields for PDF PL4"
    },
    "920230": {
        "payload": "%25",
        "method": "GET",
        "headers": {},
        "params": {"param": "%25"},
        "data": None,
        "files": None,
        "note": "Multiple URL encoding"
    },
    "920240": {
        "payload": "%",
        "method": "POST",
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        "params": {},
        "data": "param=%",
        "files": None,
        "note": "URL encoding abuse in body"
    },
    "920271": {
        "payload": "\x01",
        "method": "GET",
        "headers": {},
        "params": {"param": "\x01"},
        "data": None,
        "files": None,
        "note": "Invalid character PL2"
    },
    "920272": {
        "payload": "\x1f",
        "method": "GET",
        "headers": {},
        "params": {"param": "\x1f"},
        "data": None,
        "files": None,
        "note": "Invalid character PL3"
    },
    "920273": {
        "payload": "@",
        "method": "GET",
        "headers": {},
        "params": {"param": "@"},
        "data": None,
        "files": None,
        "note": "Invalid character PL4 in args"
    },
    "920274": {
        "payload": "@",
        "method": "GET",
        "headers": {"X-Test": "@"},
        "params": {},
        "data": None,
        "files": None,
        "note": "Invalid character PL4 in headers"
    },
    "920275": {
        "payload": "?2",
        "method": "GET",
        "headers": {"Sec-Fetch-User": "?2"},
        "params": {},
        "data": None,
        "files": None,
        "note": "Invalid structured header"
    },
    "920300": {
        "payload": None,
        "method": "GET",
        "headers": {},
        "params": {},
        "data": None,
        "files": None,
        "note": "Missing Accept header PL3"
    },
    "920320": {
        "payload": None,
        "method": "GET",
        "headers": {},
        "params": {},
        "data": None,
        "files": None,
        "note": "Missing User-Agent header PL2"
    },
    "920121": {
        "payload": "\"",
        "method": "POST",
        "headers": {"Content-Type": "multipart/form-data"},
        "params": {},
        "data": None,
        "files": {"file": ("file\"", "content")},
        "note": "Multipart bypass PL2"
    },
    "920341": {
        "payload": "data",
        "method": "POST",
        "headers": {"Content-Length": "4"},
        "params": {},
        "data": "data",
        "files": None,
        "note": "Missing Content-Type PL2"
    },
    "920451": {
        "payload": "proxy",
        "method": "GET",
        "headers": {"Proxy": "bad"},
        "params": {},
        "data": None,
        "files": None,
        "note": "Restricted header PL2"
    }
}

@pytest.fixture(scope="function")
def setup_teardown():
    """Fixture for setup and teardown: clear logs before test"""
    try:
        subprocess.run(
            ["docker", "exec", "waf-angie-1", "truncate", "-s", "0", "/var/log/angie/modsec_audit.log"],
            capture_output=True,
            text=True,
            check=True
        )
    except subprocess.CalledProcessError:
        pass  # Ignore if truncate fails
    yield
    # Teardown: optionally clean up after test
    pass

@pytest.mark.parametrize("rule_id,payload_info", list(protocol_payloads.items()))
def test_protocol_rule_trigger(setup_teardown, rule_id, payload_info):
    """Test that each protocol enforcement rule is triggered by its payload"""

    payload = payload_info["payload"]
    method = payload_info["method"]
    headers = payload_info["headers"]
    params = payload_info["params"]
    data = payload_info["data"]
    files = payload_info["files"]

    # For missing headers, remove them if None
    if "Host" not in headers and payload_info["note"] and "Missing" in payload_info["note"]:
        headers = {k: v for k, v in headers.items() if k != "Host"}
    if "User-Agent" not in headers and payload_info["note"] and "Missing" in payload_info["note"]:
        headers = {k: v for k, v in headers.items() if k != "User-Agent"}
    if "Accept" not in headers and payload_info["note"] and "Missing" in payload_info["note"]:
        headers = {k: v for k, v in headers.items() if k != "Accept"}

    # Build URL
    url = "http://localhost/"
    if method == "GET" and params:
        url += "?" + "&".join([f"{k}={requests.utils.quote(str(v))}" for k, v in params.items()])

    try:
        if method == "GET":
            response = requests.get(url, headers=headers, timeout=10)
        elif method == "POST":
            if files:
                response = requests.post(url, headers=headers, data=data, files=files, timeout=10)
            else:
                response = requests.post(url, headers=headers, data=data, timeout=10)
        else:
            response = requests.request(method, url, headers=headers, data=data, params=params, files=files, timeout=10)
    except requests.RequestException as e:
        pytest.fail(f"Request failed: {e}")

    time.sleep(1)

    # Get logs from Docker container
    try:
        result = subprocess.run(
            ["docker", "exec", "waf-angie-1", "cat", "/var/log/angie/modsec_audit.log"],
            capture_output=True,
            text=True,
            check=True
        )
        log_content = result.stdout.strip()
    except subprocess.CalledProcessError as e:
        pytest.fail(f"Error executing docker command: {e}")

    if not log_content:
        pytest.fail("Log file is empty or not found")

    # Parse JSON log
    try:
        log_data = json.loads(log_content)
    except json.JSONDecodeError as e:
        pytest.fail(f"Error parsing JSON log: {e}")

    # Extract messages with ruleId
    messages = log_data.get("messages", [])
    rule_ids_in_log = [msg.get("ruleId") for msg in messages if "ruleId" in msg]

    # Assert that the expected rule_id is triggered
    assert rule_id in rule_ids_in_log, f"Rule {rule_id} not triggered. Found rules: {rule_ids_in_log}. Payload: {payload_info}"

if __name__ == "__main__":
    pytest.main([__file__])