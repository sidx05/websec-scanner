"""Custom compliance standards engine."""
import yaml
from typing import Dict, List
from pathlib import Path


class CustomComplianceStandard:
    """Define custom compliance checks."""
    
    def __init__(self, config_file: str = None):
        """Load custom standard from YAML."""
        self.checks = []
        if config_file and Path(config_file).exists():
            with open(config_file) as f:
                self.config = yaml.safe_load(f)
                self.name = self.config.get('name', 'Custom Standard')
                self.checks = self.config.get('checks', [])
    
    def evaluate(self, scan_results: Dict) -> Dict:
        """Evaluate scan results against custom standard."""
        results = {
            'standard': self.name,
            'checks': {},
            'passed': 0,
            'total': len(self.checks)
        }
        
        for check in self.checks:
            check_id = check['id']
            compliant = self._evaluate_check(check, scan_results)
            
            results['checks'][check_id] = {
                'name': check['name'],
                'compliant': compliant,
                'severity': check.get('severity', 'MEDIUM'),
                'description': check.get('description', ''),
                'remediation': check.get('remediation', '')
            }
            
            if compliant:
                results['passed'] += 1
        
        results['score'] = (results['passed'] / results['total'] * 100) if results['total'] > 0 else 0
        return results
    
    def _evaluate_check(self, check: Dict, scan_results: Dict) -> bool:
        """Evaluate a single check condition."""
        conditions = check.get('conditions', [])
        operator = check.get('operator', 'AND')  # AND or OR
        
        evaluations = []
        for condition in conditions:
            result = self._evaluate_condition(condition, scan_results)
            evaluations.append(result)
        
        if operator == 'AND':
            return all(evaluations)
        else:  # OR
            return any(evaluations)
    
    def _evaluate_condition(self, condition: Dict, scan_results: Dict) -> bool:
        """Evaluate a single condition."""
        path = condition['path']  # e.g., "url_info.https_enabled"
        operator = condition['operator']  # equals, not_equals, greater_than, less_than, contains, exists
        expected = condition.get('value')
        
        # Navigate to the value in scan_results
        value = self._get_nested_value(scan_results, path)
        
        # Evaluate based on operator
        if operator == 'equals':
            return value == expected
        elif operator == 'not_equals':
            return value != expected
        elif operator == 'greater_than':
            return value > expected if value is not None else False
        elif operator == 'less_than':
            return value < expected if value is not None else False
        elif operator == 'greater_or_equal':
            return value >= expected if value is not None else False
        elif operator == 'less_or_equal':
            return value <= expected if value is not None else False
        elif operator == 'contains':
            return expected in value if value else False
        elif operator == 'not_contains':
            return expected not in value if value else True
        elif operator == 'exists':
            return value is not None
        elif operator == 'not_exists':
            return value is None
        elif operator == 'in_list':
            return value in expected if isinstance(expected, list) else False
        else:
            return False
    
    def _get_nested_value(self, data: Dict, path: str):
        """Get value from nested dictionary using dot notation."""
        keys = path.split('.')
        value = data
        
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return None
        
        return value


def load_custom_standards(directory: str = "compliance_standards") -> List[CustomComplianceStandard]:
    """Load all custom standards from directory."""
    standards = []
    standards_dir = Path(directory)
    
    if standards_dir.exists():
        for yaml_file in standards_dir.glob("*.yaml"):
            try:
                standard = CustomComplianceStandard(str(yaml_file))
                standards.append(standard)
            except Exception as e:
                print(f"Error loading {yaml_file}: {e}")
    
    return standards


def evaluate_custom_compliance(scan_results: Dict, standards_dir: str = "compliance_standards") -> Dict:
    """Evaluate against all custom compliance standards."""
    standards = load_custom_standards(standards_dir)
    
    results = {
        'custom_standards': {},
        'total_standards': len(standards),
        'passed_standards': 0
    }
    
    for standard in standards:
        standard_result = standard.evaluate(scan_results)
        results['custom_standards'][standard.name] = standard_result
        
        if standard_result['score'] >= 80:  # 80% threshold for "passing"
            results['passed_standards'] += 1
    
    return results
