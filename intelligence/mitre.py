class MitreMapper:
    """
    Maps detection rules to MITRE ATT&CK techniques.
    """

    TECHNIQUES = {
        "SEC-4625": {
            "id": "T1110",
            "name": "Brute Force",
        },

        "SEC-4688": {
            "id": "T1059",
            "name": "Command and Scripting Interpreter",
        },

        "SEC-4672": {
            "id": "T1078",
            "name": "Valid Accounts",
        },
    }

    @classmethod
    def get_technique(cls, rule_id: str) -> dict | None:
        return cls.TECHNIQUES.get(rule_id)

    @classmethod
    def get_technique_id(
        cls,
        rule_id: str
    ) -> str | None:

        technique = cls.get_technique(rule_id)

        if technique is None:
            return None

        return technique["id"]

    @classmethod
    def get_technique_name(
        cls,
        rule_id: str
    ) -> str | None:

        technique = cls.get_technique(rule_id)

        if technique is None:
            return None

        return technique["name"]