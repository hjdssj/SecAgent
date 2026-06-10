from pydantic import BaseModel, Field


class RuleMatchCondition(BaseModel):
    """
    Describe how one attack rule should match a normalized event.

    Parameters:
     fields - event fields searched by regular expressions
     any_patterns - case-insensitive regex patterns where any match is enough
     waf_rule_ids - exact WAF rule IDs that trigger this rule
     waf_rule_prefixes - WAF rule ID prefixes that trigger this rule
     required_indicators - feature indicators that must all be present

    Returns:
     Structured match condition for an attack rule

    Raises:
     None
    """

    fields: list[str] = Field(default_factory=list)
    any_patterns: list[str] = Field(default_factory=list)
    waf_rule_ids: list[str] = Field(default_factory=list)
    waf_rule_prefixes: list[str] = Field(default_factory=list)
    required_indicators: list[str] = Field(default_factory=list)


class RuleStandards(BaseModel):
    """
    Represent security standards mapped to one attack rule.

    Parameters:
     mitre - MITRE ATT&CK technique identifiers
     cwe - CWE identifiers
     owasp_top10 - OWASP Top 10 references
     crs - OWASP CRS rule families or IDs

    Returns:
     Standards mapping for a rule

    Raises:
     None
    """

    mitre: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    owasp_top10: list[str] = Field(default_factory=list)
    crs: list[str] = Field(default_factory=list)


class AttackRule(BaseModel):
    """
    Represent one structured attack detection rule.

    Parameters:
     rule_id - stable rule identifier
     attack_type - normalized attack type emitted when the rule matches
     enabled - whether the rule participates in matching
     priority - rule priority used to choose the primary attack type
     confidence - confidence assigned when this rule is the primary match
     source - rule source such as builtin, uploaded, vendor, or enterprise
     provenance - rule provenance such as manual or ai_assisted
     reference - human-readable source reference
     standards - security standards mapped to this rule
     match - rule match condition

    Returns:
     Validated attack rule

    Raises:
     None
    """

    rule_id: str
    attack_type: str
    enabled: bool = True
    priority: int = 0
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    source: str = "builtin"
    provenance: str = "manual"
    reference: str = ""
    standards: RuleStandards = Field(default_factory=RuleStandards)
    match: RuleMatchCondition


class LogFeatures(BaseModel):
    """
    Represent normalized runtime log features used by rule matching.

    Parameters:
     fields - normalized event field values
     indicators - extracted boolean-style indicators

    Returns:
     Feature object consumed by RuleMatcher

    Raises:
     None
    """

    fields: dict[str, str] = Field(default_factory=dict)
    indicators: set[str] = Field(default_factory=set)


class RuleEvidence(BaseModel):
    """
    Represent one concrete reason why a rule matched.

    Parameters:
     rule_id - matched rule identifier
     attack_type - matched attack type
     field - event field that matched
     reason - human-readable evidence text

    Returns:
     Evidence item for a structured rule match

    Raises:
     None
    """

    rule_id: str
    attack_type: str
    field: str = ""
    reason: str


class RuleMatch(BaseModel):
    """
    Represent one matched attack rule and its evidence.

    Parameters:
     rule - attack rule that matched
     evidence - concrete evidence items

    Returns:
     Matched rule with evidence

    Raises:
     None
    """

    rule: AttackRule
    evidence: list[RuleEvidence] = Field(default_factory=list)


class RuleMatchResult(BaseModel):
    """
    Represent the final output of structured rule matching.

    Parameters:
     matched - whether at least one rule matched
     attack_type - chosen primary attack type
     confidence - confidence of the selected rule result
     attack_features - attack features emitted to the parser
     evidence - evidence text emitted to the parser
     matched_rule_ids - identifiers of all matched rules

    Returns:
     Structured rule matching result

    Raises:
     None
    """

    matched: bool = False
    attack_type: str = "Unknown"
    confidence: float = 0.0
    attack_features: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    matched_rule_ids: list[str] = Field(default_factory=list)
