POLICY_SCHEMA = {
    "type": "object",
    "required": ["policy_name", "version", "rules"],
    "properties": {
        "policy_name": {"type": "string"},
        "version": {"type": "number"},
        "rules": {
            "type": "object",
            "properties": {
                "severity": {
                    "type": "object",
                    "patternProperties": {
                        "^[A-Z]+$": {"type": "string"}
                    },
                    "additionalProperties": False
                },
                "block_if_cwe": {
                    "type": "array",
                    "items": {"type": "string"}
                }
            },
            "additionalProperties": False,
            "minProperties": 1  # At least one of severity or block_if_cwe
        },
        "actions": {
            "type": "object",
            "properties": {
                "on_fail": {
                    "type": "object",
                    "properties": {
                        "block_pipeline": {"type": "boolean"},
                        "notify": {"type": "string"}
                    },
                    "additionalProperties": True
                },
                "on_pass": {
                    "type": "object",
                    "properties": {
                        "block_pipeline": {"type": "boolean"}
                    },
                    "additionalProperties": True
                }
            },
            "additionalProperties": True
        }
    },
    "additionalProperties": False
}
