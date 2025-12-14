import yaml
from jsonschema import validate, ValidationError

from .schema import POLICY_SCHEMA


def load_policy(path: str) -> dict:
    """
    Load and validate a policy YAML file.
    Raises an exception if invalid.
    """
    try:
        with open(path, "r") as f:
            policy = yaml.safe_load(f)
    except Exception as e:
        raise RuntimeError(f"Unable to read policy file '{path}': {e}")

    try:
        validate(instance=policy, schema=POLICY_SCHEMA)
    except ValidationError as e:
        raise RuntimeError(f"Invalid policy '{path}': {e.message}")

    return policy
