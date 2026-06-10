import json
from pathlib import Path

from app.rules.schemas import AttackRule
from app.rules.validator import RuleValidator

DEFAULT_RULE_PATH = Path(__file__).resolve().parent / "attack_rules.json"


class RuleLoader:
    """
    Load structured attack rules from JSON.

    Parameters:
     rule_path - path to the attack rule JSON file

    Returns:
     Loader for validated attack rules

    Raises:
     None
    """

    def __init__(self, rule_path: Path = DEFAULT_RULE_PATH) -> None:
        """
        Initialize the rule loader.

        Parameters:
         rule_path - path to the attack rule JSON file

        Returns:
         None

        Raises:
         None
        """

        self.rule_path = rule_path

    def load_rules(self) -> list[AttackRule]:
        """
        Load enabled and disabled attack rules from JSON.

        Parameters:
         None

        Returns:
         List of validated attack rules

        Raises:
         ValueError - raised when the rule file is malformed
        """

        try:
            raw = json.loads(self.rule_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise ValueError(f"Invalid attack rule JSON: {self.rule_path}") from error

        if not isinstance(raw, list):
            raise ValueError("Attack rule JSON must be a list")

        rules = [AttackRule.model_validate(item) for item in raw]
        RuleValidator(rules).validate()
        return rules
