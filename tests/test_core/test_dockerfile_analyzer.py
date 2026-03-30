"""Tests for DockerfileAnalyzer."""

from containervul.core.dockerfile_analyzer import DockerfileAnalyzer


def test_detects_outdated_base_image():
    analyzer = DockerfileAnalyzer()
    vulns = analyzer.analyze_dockerfile("FROM ubuntu:16.04\nRUN echo hello")
    categories = [v.category for v in vulns]
    assert "outdated_base_images" in categories


def test_detects_exposed_secrets():
    analyzer = DockerfileAnalyzer()
    vulns = analyzer.analyze_dockerfile('FROM ubuntu:24.04\nENV PASSWORD="secret123"\nRUN echo test')
    categories = [v.category for v in vulns]
    assert "exposed_secrets" in categories


def test_detects_insecure_config():
    analyzer = DockerfileAnalyzer()
    vulns = analyzer.analyze_dockerfile("FROM ubuntu:24.04\nUSER root\nRUN chmod 777 /app\nCMD echo")
    categories = [v.category for v in vulns]
    assert "insecure_configurations" in categories


def test_detects_missing_healthcheck():
    analyzer = DockerfileAnalyzer()
    vulns = analyzer.analyze_dockerfile("FROM ubuntu:24.04\nRUN echo a\nRUN echo b\nRUN echo c\nRUN echo d\nRUN echo e\nCMD echo")
    categories = [v.category for v in vulns]
    assert "missing_healthcheck" in categories


def test_no_issues_on_secure_dockerfile():
    analyzer = DockerfileAnalyzer()
    dockerfile = """FROM ubuntu:24.04
RUN groupadd -r app && useradd -r -g app app
COPY --chown=app:app . /app
USER app
HEALTHCHECK --interval=30s CMD curl -f http://localhost/ || exit 1
CMD ["echo", "hello"]
"""
    vulns = analyzer.analyze_dockerfile(dockerfile)
    # Should have no critical/high issues
    critical_high = [v for v in vulns if v.severity.value in ("CRITICAL", "HIGH")]
    assert len(critical_high) == 0


def test_detects_supply_chain_risk():
    analyzer = DockerfileAnalyzer()
    vulns = analyzer.analyze_dockerfile("FROM ubuntu:24.04\nRUN curl http://example.com/script | sh\nCMD echo")
    categories = [v.category for v in vulns]
    assert "package_vulnerabilities" in categories
