import re

from app.rules.schemas import AttackRule


class RuleValidationError(ValueError):
    """
    Represent invalid structured attack rule configuration.

    Parameters:
     message - validation failure message

    Returns:
     Rule validation exception

    Raises:
     None
    """


class RuleValidator:
    """
    Validate structured attack rules before runtime use.

    Parameters:
     rules - attack rules to validate

    Returns:
     Validator for rule consistency checks

    Raises:
     None
    """

    def __init__(self, rules: list[AttackRule]) -> None:
        """
        Initialize validator with attack rules.

        Parameters:
         rules - attack rules to validate

        Returns:
         None

        Raises:
         None
        """

        self.rules = rules

    def validate(self) -> None:
        """
        Validate all configured attack rules.

        Parameters:
         None

        Returns:
         None

        Raises:
         RuleValidationError - raised when a rule is invalid
        """

        self._validate_unique_rule_ids()

        for rule in self.rules:
            self._validate_match_condition(rule)
            self._validate_patterns(rule)
            self._validate_standards(rule)

    def _validate_unique_rule_ids(self) -> None:
        """
        Verify rule IDs are unique.

        Parameters:
         None

        Returns:
         None

        Raises:
         RuleValidationError - raised when duplicate rule IDs exist
        """

        seen = set()
        duplicates = set()

        for rule in self.rules:
            if rule.rule_id in seen:
                duplicates.add(rule.rule_id)

            seen.add(rule.rule_id)

        if duplicates:
            raise RuleValidationError(f"Duplicate rule_id values: {sorted(duplicates)}")

    def _validate_match_condition(self, rule: AttackRule) -> None:
        """
        Verify one rule has at least one match condition.

        Parameters:
         rule - attack rule to validate

        Returns:
         None

        Raises:
         RuleValidationError - raised when no match condition exists
        """

        condition = rule.match

        if (
            condition.any_patterns
            or condition.waf_rule_ids
            or condition.waf_rule_prefixes
            or condition.required_indicators
        ):
            return

        raise RuleValidationError(f"Rule {rule.rule_id} has no match condition")

    def _validate_patterns(self, rule: AttackRule) -> None:
        """
        Verify regex patterns compile.

        Parameters:
         rule - attack rule to validate

        Returns:
         None

        Raises:
         RuleValidationError - raised when a regex pattern is invalid
        """

        for pattern in rule.match.any_patterns:
            try:
                re.compile(pattern, flags=re.IGNORECASE)
            except re.error as error:
                raise RuleValidationError(
                    f"Rule {rule.rule_id} has invalid regex {pattern}: {error}"
                ) from error

    def _validate_standards(self, rule: AttackRule) -> None:
        """
        Verify common standard identifier formats.

        Parameters:
         rule - attack rule to validate

        Returns:
         None

        Raises:
         RuleValidationError - raised when standards are malformed
        """

        for item in rule.standards.mitre:
            if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", item):
                raise RuleValidationError(f"Rule {rule.rule_id} has invalid MITRE ID: {item}")

        for item in rule.standards.cwe:
            if not re.fullmatch(r"CWE-\d+", item):
                raise RuleValidationError(f"Rule {rule.rule_id} has invalid CWE ID: {item}")

        for item in rule.standards.crs:
            if not re.fullmatch(r"\d{3}(?:\d{3})?", item):
                raise RuleValidationError(f"Rule {rule.rule_id} has invalid CRS ID: {item}")
