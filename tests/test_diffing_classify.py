from __future__ import annotations

from amac.diffing.compare import analyze_summary


def test_analyze_summary_basic_findings():
    summary = {
        "rows": [
            # Case 1: Spec says auth required, but unauth got 200 and bodies look similar → two findings
            {
                "index": 1,
                "method": "GET",
                "url": "https://api.example.com/private/data",
                "requires_auth": True,
                "noauth_status": 200,
                "auth_status": 200,
                "noauth_size": 1000,
                "auth_size": 1020,  # within 10%
            },
            # Case 2: Normal behavior (401 unauth, 200 auth) → no findings
            {
                "index": 2,
                "method": "GET",
                "url": "https://api.example.com/users/me",
                "requires_auth": True,
                "noauth_status": 401,
                "auth_status": 200,
                "noauth_size": 120,
                "auth_size": 900,
            },
            # Case 3: Unknown auth; suspicious private-ish path with very similar sizes 200 vs 200 → one finding
            {
                "index": 3,
                "method": "GET",
                "url": "https://api.example.com/me",
                "requires_auth": None,
                "noauth_status": 200,
                "auth_status": 200,
                "noauth_size": 500,
                "auth_size": 510,  # within 5%
            },
        ]
    }

    findings = analyze_summary(summary)
    by_type = findings["counts"]["by_type"]

    # We expect:
    # - Case 1: UNEXPECTED_2XX_OR_3XX_UNAUTH + POSSIBLE_CONTENT_LEAK
    # - Case 2: no findings
    # - Case 3: SUSPECT_PRIVATE_ENDPOINT_OPEN
    assert by_type.get("UNEXPECTED_2XX_OR_3XX_UNAUTH", 0) == 1
    assert by_type.get("POSSIBLE_CONTENT_LEAK", 0) == 1
    assert by_type.get("SUSPECT_PRIVATE_ENDPOINT_OPEN", 0) == 1

    assert findings["counts"]["total_findings"] == 3
