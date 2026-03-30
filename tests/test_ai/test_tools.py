"""Tests for AI tool executor."""

import json

from containervul.ai.tools import ToolExecutor


def test_scan_dockerfile_tool():
    executor = ToolExecutor()
    result = json.loads(executor.execute("scan_dockerfile", {
        "dockerfile_content": "FROM ubuntu:16.04\nUSER root\nENV PASSWORD=secret\nCMD echo"
    }))
    assert result["vulnerabilities_found"] > 0
    assert result["risk_level"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def test_unknown_tool_returns_error():
    executor = ToolExecutor()
    result = json.loads(executor.execute("nonexistent_tool", {}))
    assert "error" in result


def test_list_cloud_accounts_empty():
    executor = ToolExecutor()
    result = json.loads(executor.execute("list_cloud_accounts", {"provider": "all"}))
    assert "accounts" in result
    assert isinstance(result["accounts"], list)


def test_calculate_risk_score_empty():
    executor = ToolExecutor()
    result = json.loads(executor.execute("calculate_risk_score", {"vulnerability_ids": ["all"]}))
    assert "risk_level" in result
