#!/usr/bin/env python3
"""
Policy Parser and Validator
Validates policies against JSON schemas and checks for common issues.
"""

import json
import yaml
import jsonschema
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum


class ValidationResult(Enum):
    VALID = "valid"
    INVALID = "invalid"
    WARNING = "warning"


@dataclass
class ValidationIssue:
    severity: ValidationResult
    message: str
    path: str
    detail: Optional[str] = None


class PolicyParser:
    # Base schema for governance policies
    BASE_SCHEMA = {
        "type": "object",
        "properties": {
            "apiVersion": {"type": "string"},
            "kind": {"type": "string", "const": "Policy"},
            "metadata": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "description": {"type": "string"},
                    "severity": {
                        "type": "string",
                        "enum": ["low", "medium", "high", "critical"]
                    }
                },
                "required": ["name", "severity"]
            },
            "spec": {
                "type": "object",
                "properties": {
                    "targetResource": {"type": "string"},
                    "rules": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "condition": {"type": "string"},
                                "message": {"type": "string"}
                            },
                            "required": ["condition"]
                        }
                    }
                },
                "required": ["targetResource", "rules"]
            }
        },
        "required": ["apiVersion", "kind", "metadata", "spec"]
    }
    
    def __init__(self, schema: Optional[Dict] = None):
        self.schema = schema or self.BASE_SCHEMA
        self.issues: List[ValidationIssue] = []
    
    def load_policy(self, file_path: str) -> Dict:
        """Load policy from YAML or JSON file."""
        with open(file_path, 'r') as f:
            if file_path.endswith(('.yaml', '.yml')):
                return yaml.safe_load(f)
            else:
                return json.load(f)
    
    def validate_schema(self, policy: Dict) -> bool:
        """Validate policy against JSON schema."""
        try:
            jsonschema.validate(instance=policy, schema=self.schema)
            return True
        except jsonschema.ValidationError as e:
            self.issues.append(ValidationIssue(
                severity=ValidationResult.INVALID,
                message="Schema validation failed",
                path=e.json_path,
                detail=str(e)
            ))
            return False
    
    def validate_semantics(self, policy: Dict) -> bool:
        """Perform semantic validation beyond schema."""
        valid = True
        
        # Check rule conditions are valid JSONPath expressions
        rules = policy.get('spec', {}).get('rules', [])
        for i, rule in enumerate(rules):
            condition = rule.get('condition', '')
            if not self._is_valid_jsonpath(condition):
                self.issues.append(ValidationIssue(
                    severity=ValidationResult.INVALID,
                    message=f"Invalid JSONPath expression in rule {i}",
                    path=f"$.spec.rules[{i}].condition",
                    detail=f"Expression: {condition}"
                ))
                valid = False
        
        # Check severity matches rule criticality
        severity = policy.get('metadata', {}).get('severity', 'medium')
        
        # Additional semantic checks can be added here
        
        return valid
    
    def _is_valid_jsonpath(self, expression: str) -> bool:
        """Basic JSONPath expression validation."""
        if not expression:
            return False
        
        # Simple check for common JSONPath patterns
        valid_starters = ['$', '@']
        if expression[0] not in valid_starters:
            return False
        
        return True
    
    def validate_policy(self, policy_path: str) -> Dict[str, Any]:
        """Validate a policy file."""
        self.issues.clear()
        
        try:
            policy = self.load_policy(policy_path)
        except Exception as e:
            return {
                "valid": False,
                "issues": [{
                    "severity": ValidationResult.INVALID.value,
                    "message": f"Failed to load policy: {str(e)}",
                    "path": "",
                    "detail": None
                }]
            }
        
        schema_valid = self.validate_schema(policy)
        semantics_valid = self.validate_semantics(policy)
        
        return {
            "valid": schema_valid and semantics_valid,
            "policy": {
                "name": policy.get('metadata', {}).get('name', 'unknown'),
                "severity": policy.get('metadata', {}).get('severity', 'unknown')
            },
            "issues": [
                {
                    "severity": issue.severity.value,
                    "message": issue.message,
                    "path": issue.path,
                    "detail": issue.detail
                }
                for issue in self.issues
            ]
        }
    
    def parse_rules(self, policy: Dict) -> List[Dict]:
        """Extract and parse rules from policy."""
        rules = policy.get('spec', {}).get('rules', [])
        parsed_rules = []
        
        for rule in rules:
            parsed_rule = {
                "name": rule.get('name', 'unnamed_rule'),
                "condition": rule.get('condition'),
                "message": rule.get('message', ''),
                "parsed_condition": self._parse_condition(rule.get('condition', ''))
            }
            parsed_rules.append(parsed_rule)
        
        return parsed_rules
    
    def _parse_condition(self, condition: str) -> Dict:
        """Parse JSONPath condition into structured format."""
        # This is a simplified parser - in production, use a proper JSONPath library
        return {
            "expression": condition,
            "type": self._determine_condition_type(condition)
        }
    
    def _determine_condition_type(self, condition: str) -> str:
        """Determine the type of condition."""
        if '==' in condition:
            return 'equality'
        elif '!=' in condition:
            return 'inequality'
        elif '>' in condition or '<' in condition:
            return 'comparison'
        elif ' in ' in condition:
            return 'membership'
        else:
            return 'existence'


def main():
    """CLI interface for policy validation."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Validate governance policies')
    parser.add_argument('policy_files', nargs='+', help='Policy files to validate')
    parser.add_argument('--schema', help='Custom JSON schema file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    schema = None
    if args.schema:
        with open(args.schema, 'r') as f:
            schema = json.load(f)
    
    parser = PolicyParser(schema)
    
    all_valid = True
    
    for policy_file in args.policy_files:
        result = parser.validate_policy(policy_file)
        
        if result['valid']:
            print(f"✅ {policy_file}: VALID")
            if args.verbose:
                print(f"   Policy: {result['policy']['name']} (severity: {result['policy']['severity']})")
        else:
            print(f"❌ {policy_file}: INVALID")
            all_valid = False
        
        if result['issues'] and (not result['valid'] or args.verbose):
            for issue in result['issues']:
                print(f"   {issue['severity'].upper()}: {issue['message']}")
                if issue['detail']:
                    print(f"      {issue['detail']}")
    
    exit(0 if all_valid else 1)


if __name__ == "__main__":
    main()
