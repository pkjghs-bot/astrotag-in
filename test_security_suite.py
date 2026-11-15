"""
Astrotag Automated Security & Integrity Verification Suite
===========================================================
Executes full regression, security, rate limit, payload size,
and OWASP compliance testing against the hardened Astrotag application.
"""

import sys
import time
import json
import socket
import http.client
import urllib.request
import urllib.error
import threading
import uvicorn
from main import app

def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

SERVER_PORT = find_free_port()
BASE_URL = f"http://127.0.0.1:{SERVER_PORT}"

def run_request(path, method="GET", body=None, headers=None):
    url = f"{BASE_URL}{path}"
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
    
    data = None
    if body is not None:
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode("utf-8")
        elif isinstance(body, bytes):
            data = body
        elif isinstance(body, str):
            data = body.encode("utf-8")
            
    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp_body = resp.read().decode("utf-8")
            return resp.status, resp.headers, resp_body
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8") if e.fp else ""
        return e.code, e.headers, err_body
    except Exception as exc:
        raise exc

def test_security_headers():
    print("[TEST 1/7] Testing Security Headers (OWASP A05: Security Misconfiguration)...")
    status, headers, _ = run_request("/")
    assert status == 200, f"Expected 200, got {status}"
    
    header_map = {k.lower(): v for k, v in headers.items()}
    
    assert header_map.get("x-content-type-options") == "nosniff", "Missing X-Content-Type-Options: nosniff"
    assert header_map.get("x-frame-options") == "DENY", "Missing X-Frame-Options: DENY"
    assert "strict-transport-security" in header_map, "Missing Strict-Transport-Security"
    assert "strict-origin-when-cross-origin" in header_map.get("referrer-policy", ""), "Missing Referrer-Policy"
    assert "camera=()" in header_map.get("permissions-policy", ""), "Missing Permissions-Policy"
    print("  --> PASS: All 5 required security headers verified successfully.")

def test_payload_size_limit_413():
    print("[TEST 2/7] Testing Payload Size Limit (OWASP API4: Unrestricted Resource Consumption)...")
    conn = http.client.HTTPConnection("127.0.0.1", SERVER_PORT, timeout=5)
    body = b"X" * (300 * 1024)
    conn.putrequest("POST", "/api/kundali")
    conn.putheader("Content-Type", "application/json")
    conn.putheader("Content-Length", str(len(body)))
    conn.endheaders()
    try:
        conn.send(body)
    except (ConnectionResetError, BrokenPipeError, socket.error):
        pass  # Server closed connection early upon detecting Content-Length > 256 KB
        
    resp = conn.getresponse()
    body_text = resp.read().decode("utf-8")
    assert resp.status == 413, f"Expected HTTP 413 for oversized body, got {resp.status}"
    assert "payload exceeds" in body_text.lower(), f"Unexpected 413 body: {body_text}"
    print("  --> PASS: HTTP 413 returned when body exceeds 256 KB threshold.")

def test_input_validation_and_sanitization():
    print("[TEST 3/7] Testing Input Validation & XSS Sanitization (OWASP A03: Injection)...")
    
    # 1. Malicious HTML script tags in 'name'
    payload = {
        "name": "<script>alert('xss')</script>Aarav Sharma",
        "dob": "1995-10-15",
        "tob": "08:30",
        "country": "India",
        "state": "Delhi",
        "city": "New Delhi",
        "ayanamsa": "lahiri"
    }
    status, _, body = run_request("/api/kundali", method="POST", body=payload)
    assert status == 200, f"Expected HTTP 200, got {status}: {body}"
    data = json.loads(body)
    cleaned_name = data["profile"]["name"]
    assert "<script>" not in cleaned_name and "</script>" not in cleaned_name, f"XSS tags not stripped: {cleaned_name}"
    print(f"  --> PASS: Malicious tags stripped from input. Cleaned output: '{cleaned_name}'")

    # 2. Invalid date format (regex and format rejection)
    bad_dob_payload = dict(payload, dob="1995/13/45")
    status, _, _ = run_request("/api/kundali", method="POST", body=bad_dob_payload)
    assert status == 422, f"Expected HTTP 422 for bad dob, got {status}"

    # 3. Invalid time format
    bad_tob_payload = dict(payload, tob="25:70")
    status, _, _ = run_request("/api/kundali", method="POST", body=bad_tob_payload)
    assert status == 422, f"Expected HTTP 422 for bad tob, got {status}"

    # 4. Invalid ayanamsa mode
    bad_ayanamsa = dict(payload, ayanamsa="unsupported_ayanamsa")
    status, _, _ = run_request("/api/kundali", method="POST", body=bad_ayanamsa)
    assert status == 422, f"Expected HTTP 422 for invalid ayanamsa, got {status}"
    print("  --> PASS: Pydantic strict schemas successfully rejected invalid DOB, TOB, and Ayanamsa with HTTP 422.")

def test_rate_limiting_429():
    print("[TEST 4/7] Testing Sliding-Window Rate Limiter (OWASP API4: Unrestricted Resource Consumption)...")
    # Rate limit for /api/ask-astrologer is 6 requests per minute
    test_body = {
        "question": "What is my Lagna lord and Moon sign strength?",
        "context_data": {"test": True}
    }
    
    responses = []
    for i in range(8):
        st, hdrs, bdy = run_request("/api/ask-astrologer", method="POST", body=test_body)
        responses.append((st, hdrs, bdy))
        time.sleep(0.05)
        
    statuses = [r[0] for r in responses]
    print(f"  --> Sent 8 consecutive requests. Status sequence: {statuses}")
    
    # At least request 7 and 8 should be rate-limited (HTTP 429)
    assert 429 in statuses, f"Expected HTTP 429 in response sequence, got {statuses}"
    rate_limited_resp = next(r for r in responses if r[0] == 429)
    assert "Retry-After" in rate_limited_resp[1], "HTTP 429 response missing Retry-After header"
    print("  --> PASS: Sliding-window rate limiter triggered HTTP 429 with Retry-After header.")

def test_ai_prompt_injection_guardrails():
    print("[TEST 5/7] Testing AI Prompt Injection & Guardrails (OWASP LLM01: Prompt Injection)...")
    # 1. Question exceeding 500 characters
    long_question = "Explain my horoscope in extreme detail. " * 30  # ~1200 chars
    payload = {"question": long_question, "context_data": {}}
    status, _, _ = run_request("/api/ask-astrologer", method="POST", body=payload)
    assert status == 422, f"Expected HTTP 422 for question > 500 chars, got {status}"
    print("  --> PASS: Prompt character cap (>500 chars) enforced with HTTP 422.")

def test_ephemeris_calculation_integrity():
    print("[TEST 6/7] Testing Ephemeris & Kundali Functional Calculation Integrity...")
    payload = {
        "name": "Arjun Sharma",
        "dob": "1992-04-14",
        "tob": "14:15",
        "country": "India",
        "state": "Maharashtra",
        "city": "Mumbai",
        "ayanamsa": "lahiri"
    }
    status, _, body = run_request("/api/kundali", method="POST", body=payload)
    assert status == 200, f"Calculation failed with status {status}"
    data = json.loads(body)
    
    # Check 16 Divisional Charts
    expected_vargas = ["D1", "D2", "D3", "D4", "D7", "D9", "D10", "D12", "D16", "D20", "D24", "D27", "D30", "D40", "D45", "D60"]
    for varga in expected_vargas:
        assert varga in data["charts"], f"Missing Divisional Chart {varga}"
    print(f"  --> PASS: All 16 Divisional Charts generated successfully.")
    
    # Check 9 Grahas + Ascendant
    table = data["planet_table"]
    planets_found = {p["planet"] for p in table}
    expected_planets = {"Ascendant (Lagna)", "Sun", "Moon", "Mars", "Mercury", "Jupiter", "Venus", "Saturn", "Rahu", "Ketu"}
    assert expected_planets.issubset(planets_found), f"Missing planets in table: {expected_planets - planets_found}"
    
    # Check Ascendant is first row
    assert table[0]["planet"] == "Ascendant (Lagna)" and table[0]["is_ascendant"] is True, "Ascendant is not top row"
    print("  --> PASS: All 9 Grahas + Ascendant calculated. Ascendant correctly pinned to row 1.")
    
    # Check 6-Level Dasha Chain
    active_chain = data["active_dasha_chain"]
    assert len(active_chain) == 6, f"Expected 6 active Dasha levels, got {len(active_chain)}"
    print(f"  --> PASS: 6-Level Vimshottari Dasha hierarchy generated.")
    
    # Check 3 Gochar transit charts
    transit = data["transit"]
    assert "delhi_chart" in transit and "asc_chart" in transit and "moon_chart" in transit, "Missing transit charts"
    print("  --> PASS: 3-Chart Transit snapshot (Delhi Lagna, Birth Lagna, Chandra Lagna) calculated.")

def test_transit_and_dasha_api():
    print("[TEST 7/7] Testing Sub-period Dasha and Custom Transit Endpoints...")
    # 1. Test Dasha sublevels
    sub_payload = {
        "parent_lord": "Jupiter",
        "start_iso": "2024-01-01T00:00:00",
        "end_iso": "2026-05-01T00:00:00",
        "level": 1
    }
    status, _, body = run_request("/api/dasha-sublevels", method="POST", body=sub_payload)
    assert status == 200, f"Expected 200 for sublevels, got {status}"
    sub_data = json.loads(body)
    assert len(sub_data["periods"]) == 9, "Expected 9 sub-periods"
    print("  --> PASS: /api/dasha-sublevels returned 9 child periods.")

    # 2. Test Custom Transit endpoint
    transit_payload = {
        "natal_meta": {
            "d9_signs": {"Sun": 1, "Moon": 2, "Mars": 3, "Mercury": 4, "Jupiter": 5, "Venus": 6, "Saturn": 7, "Rahu": 8, "Ketu": 2},
            "active_dasha_4": ["Jupiter", "Saturn", "Mercury", "Venus"],
            "d1_asc_sign": 1,
            "natal_moon_sign": 4,
            "ayanamsa": "lahiri"
        },
        "transit_date": "2026-11-15",
        "transit_time": "12:00"
    }
    status, _, body = run_request("/api/transit", method="POST", body=transit_payload)
    assert status == 200, f"Expected 200 for transit, got {status}"
    transit_data = json.loads(body)
    assert "delhi_chart" in transit_data and "asc_chart" in transit_data and "moon_chart" in transit_data
    print("  --> PASS: /api/transit successfully calculated Gochar for custom target date.")

def main_suite():
    print("=" * 70)
    print("ASTROTAG FULL AUTOMATED SECURITY & FUNCTIONAL VERIFICATION SUITE")
    print("=" * 70)
    
    # Launch uvicorn in a background thread
    config = uvicorn.Config(app, host="127.0.0.1", port=SERVER_PORT, log_level="error")
    server = uvicorn.Server(config)
    srv_thread = threading.Thread(target=server.run, daemon=True)
    srv_thread.start()
    time.sleep(1.5)
    
    try:
        test_security_headers()
        test_payload_size_limit_413()
        test_input_validation_and_sanitization()
        test_rate_limiting_429()
        test_ai_prompt_injection_guardrails()
        test_ephemeris_calculation_integrity()
        test_transit_and_dasha_api()
        
        print("=" * 70)
        print("ALL 7 AUTOMATED VERIFICATION TESTS PASSED SUCCESSFULLY (100% GREEN)")
        print("=" * 70)
        return 0
    except AssertionError as err:
        print(f"\n[!] TEST FAILED: {err}")
        return 1
    except Exception as exc:
        print(f"\n[!] UNEXPECTED ERROR: {exc}")
        return 1
    finally:
        server.should_exit = True

if __name__ == "__main__":
    sys.exit(main_suite())
