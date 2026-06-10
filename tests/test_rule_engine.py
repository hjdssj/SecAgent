import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

from app.agents.log_parser_agent import LogParserAgent
from app.models.event import SecurityEvent
from app.rules.loader import RuleLoader
from app.rules.matcher import RuleMatcher
from app.rules.schemas import AttackRule
from app.rules.validator import RuleValidationError, RuleValidator


def test_rule_loader_loads_builtin_attack_rules() -> None:
    """
    Verify builtin structured attack rules can be loaded.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    rules = RuleLoader().load_rules()
    rule_ids = {rule.rule_id for rule in rules}

    assert "attack.sqli.basic" in rule_ids
    assert "attack.ssrf.url_parameter" in rule_ids
    assert "attack.xss.basic" in rule_ids
    assert all(rule.attack_type for rule in rules)
    assert all(rule.source for rule in rules)


def test_rule_loader_rejects_non_list_json(tmp_path: Path) -> None:
    """
    Verify malformed rule JSON produces a clear error.

    Parameters:
     tmp_path - pytest temporary path fixture

    Returns:
     None

    Raises:
     None
    """

    rule_path = tmp_path / "rules.json"
    rule_path.write_text(json.dumps({"rule_id": "bad"}), encoding="utf-8")

    try:
        RuleLoader(rule_path).load_rules()
    except ValueError as error:
        assert "must be a list" in str(error)
        return

    raise AssertionError("RuleLoader should reject non-list JSON")


def test_rule_matcher_detects_sqli_and_scanner_but_prioritizes_sqli() -> None:
    """
    Verify SQL injection outranks scanner evidence when both match.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    event = SecurityEvent(
        source_ip="45.67.89.10",
        url="/login?id=1' OR '1'='1",
        path="/login",
        query="id=1' OR '1'='1",
        user_agent="sqlmap/1.7",
        waf_rule_id="913100",
        waf_message="Found User-Agent associated with security scanner",
    )

    result = RuleMatcher().match(event)

    assert result.matched is True
    assert result.attack_type == "SQL Injection"
    assert "Automated Scanner" in result.attack_features
    assert "attack.sqli.basic" in result.matched_rule_ids
    assert "attack.scanner.user_agent" in result.matched_rule_ids


def test_rule_matcher_uses_waf_rule_prefix_without_payload_pattern() -> None:
    """
    Verify WAF CRS prefixes can classify events even when payload text is weak.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    event = SecurityEvent(
        source_ip="8.8.8.8",
        url="/search?q=test",
        path="/search",
        query="q=test",
        waf_rule_id="941100",
        waf_message="XSS Attack Detected",
    )

    result = RuleMatcher().match(event)

    assert result.matched is True
    assert result.attack_type == "XSS"
    assert any("WAF 规则前缀" in item for item in result.evidence)


def test_rule_matcher_ignores_disabled_rules() -> None:
    """
    Verify disabled rules do not participate in matching.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    rule = AttackRule.model_validate(
        {
            "rule_id": "attack.disabled",
            "attack_type": "SQL Injection",
            "enabled": False,
            "match": {
                "fields": ["query"],
                "any_patterns": ["union\\s+select"],
            },
        }
    )
    event = SecurityEvent(query="id=1 union select password from users")

    result = RuleMatcher(rules=[rule]).match(event)

    assert result.matched is False
    assert result.attack_type == "Unknown"


def test_log_parser_uses_structured_rule_engine() -> None:
    """
    Verify LogParserAgent emits structured rule evidence.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    event = SecurityEvent(
        source_ip="9.9.9.9",
        url="/download?file=../../etc/passwd",
        path="/download",
        query="file=../../etc/passwd",
        status=403,
    )

    parsed = LogParserAgent().parse(event)

    assert parsed.attack_type == "Path Traversal"
    assert "Rule:attack.path_traversal.basic" in parsed.attack_features
    assert any("attack.path_traversal.basic" in item for item in parsed.evidence)


def test_rule_matcher_supports_query_access_path_fields() -> None:
    """
    Verify access-path fields such as query.file can trigger precise rules.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    event = SecurityEvent(
        source_ip="9.9.9.9",
        path="/download",
        query_params={"file": "../../etc/passwd"},
        url="/download",
    )

    result = RuleMatcher().match(event)

    assert result.matched is True
    assert result.attack_type == "Path Traversal"
    assert any("字段 query.file" in item for item in result.evidence)


def test_rule_matcher_detects_ssrf_from_url_parameter() -> None:
    """
    Verify SSRF can be detected through structured query access-path rules.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    event = SecurityEvent(
        source_ip="6.6.6.6",
        path="/fetch",
        query_params={"url": "http://169.254.169.254/latest/meta-data/"},
        url="/fetch?url=http://169.254.169.254/latest/meta-data/",
        status=200,
    )

    result = RuleMatcher().match(event)

    assert result.matched is True
    assert result.attack_type == "SSRF"
    assert "attack.ssrf.url_parameter" in result.matched_rule_ids
    assert any("CWE-918" in item for item in result.evidence)
    assert any("A10:2021-Server-Side Request Forgery" in item for item in result.evidence)


def test_rule_validator_rejects_duplicate_rule_ids() -> None:
    """
    Verify duplicate rule IDs fail validation.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    rule = AttackRule.model_validate(
        {
            "rule_id": "attack.duplicate",
            "attack_type": "SQL Injection",
            "match": {
                "fields": ["query"],
                "any_patterns": ["select"],
            },
        }
    )

    try:
        RuleValidator([rule, rule]).validate()
    except RuleValidationError as error:
        assert "Duplicate rule_id" in str(error)
        return

    raise AssertionError("RuleValidator should reject duplicate rule IDs")


def test_rule_validator_rejects_invalid_regex() -> None:
    """
    Verify invalid regex patterns fail validation.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    rule = AttackRule.model_validate(
        {
            "rule_id": "attack.bad_regex",
            "attack_type": "SQL Injection",
            "match": {
                "fields": ["query"],
                "any_patterns": ["("],
            },
        }
    )

    try:
        RuleValidator([rule]).validate()
    except RuleValidationError as error:
        assert "invalid regex" in str(error)
        return

    raise AssertionError("RuleValidator should reject invalid regex")


def test_rule_validator_rejects_invalid_standard_ids() -> None:
    """
    Verify malformed standard identifiers fail validation.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    rule = AttackRule.model_validate(
        {
            "rule_id": "attack.bad_standard",
            "attack_type": "SQL Injection",
            "standards": {
                "mitre": ["BAD-1190"],
            },
            "match": {
                "fields": ["query"],
                "any_patterns": ["select"],
            },
        }
    )

    try:
        RuleValidator([rule]).validate()
    except RuleValidationError as error:
        assert "invalid MITRE" in str(error)
        return

    raise AssertionError("RuleValidator should reject invalid standard IDs")
