import json  
import typer  
import sys  
from pathlib import Path  
  
app = typer.Typer(help="Policy Evaluator CLI - AccuKnox Style")  
  
def load_json(path: str):  
    file_path = Path(path)  
    if not file_path.exists():  
        typer.echo(f"File not found: {path}")  
        sys.exit(2)  
    return json.loads(file_path.read_text())  
  
def evaluate_policy(policy_data: dict, scan_data: dict, policy_name: str) -> dict:    
    """Evaluate scan against flexible policy formats"""    
        
    # Extract policy rules (handle missing sections gracefully)    
    rules = policy_data.get("rules", {})    
    severity_thresholds = rules.get("severity_thresholds", {})    
    block_if_cwe = rules.get("block_if_cwe", [])    
    actions = policy_data.get("actions", {})    
        
    # Support legacy format for backward compatibility    
    if not severity_thresholds and not block_if_cwe:    
        # Legacy format: conditions.severities with "block" action    
        conditions = policy_data.get("conditions", {})    
        legacy_sev_rules = conditions.get("severities", {})    
        severity_thresholds = {    
            sev: 0 if action == "block" else 999     
            for sev, action in legacy_sev_rules.items()    
        }    
        
    failed = []    
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}    
        
    # Evaluate each finding    
    for f in scan_data.get("findings", []):    
        sev = f.get("severity", "").upper()    
        cwe = f.get("cwe", "")    
            
        # Count severity for threshold checking    
        if sev in severity_counts:    
            severity_counts[sev] += 1    
            
        # Check CWE blocking (if CWE rules exist)    
        if block_if_cwe and cwe in block_if_cwe:    
            failed.append(f)    
            continue    
            
        # Check severity thresholds (if severity rules exist)    
        if severity_thresholds and sev in severity_thresholds:    
            threshold = severity_thresholds[sev]    
            if threshold == 0 and severity_counts[sev] > 0:    
                failed.append(f)    
            elif severity_counts[sev] > threshold:    
                failed.append(f)    
        
    return {    
        "policy_name": policy_data.get("policy_name", policy_name),    
        "policy_version": policy_data.get("version", "unknown"),    
        "status": "FAILED" if failed else "PASSED",    
        "failed_count": len(failed),    
        "severity_counts": severity_counts,    
        "failed_items": failed,    
        "actions": actions.get("on_fail" if failed else "on_pass", {}),    
        "evaluation_type": "severity_and_cwe" if (severity_thresholds and block_if_cwe)     
                          else "severity_only" if severity_thresholds     
                          else "cwe_only"    
    }  
  
def validate_policy(policy_data: dict, policy_name: str):    
    """Validate policy structure for all supported formats"""    
        
    # Check for new format    
    has_rules = "rules" in policy_data    
    has_actions = "actions" in policy_data    
        
    # Check for legacy format    
    has_conditions = "conditions" in policy_data    
        
    if not (has_rules or has_conditions):    
        typer.echo(f"❌ Policy {policy_name} must have either 'rules' or 'conditions' field", err=True)    
        sys.exit(2)    
        
    # Validate new format    
    if has_rules:    
        rules = policy_data["rules"]    
        if not rules.get("severity_thresholds") and not rules.get("block_if_cwe"):    
            typer.echo(f"❌ Policy {policy_name} 'rules' must contain 'severity_thresholds' or 'block_if_cwe'", err=True)    
            sys.exit(2)    
        
    # Validate legacy format    
    if has_conditions:    
        conditions = policy_data["conditions"]    
        if "severities" not in conditions:    
            typer.echo(f"❌ Policy {policy_name} 'conditions' must contain 'severities'", err=True)    
            sys.exit(2)  
  
@app.command()  
def evaluate(  
    policy: str = typer.Option(..., "--policy", "-p", help="Policy JSON file"),  
    scan: str = typer.Option(..., "--scan", "-s", help="Scan result JSON file"),  
    output: str = typer.Option(None, "--output", "-o", help="Save result to file")  
):  
    # Load and validate policy  
    policy_data = load_json(policy)  
    validate_policy(policy_data, policy)  
      
    # Load scan data  
    scan_data = load_json(scan)  
      
    # Evaluate using enhanced logic  
    result = evaluate_policy(policy_data, scan_data, policy)  
  
    # Output results  
    typer.echo(json.dumps(result, indent=2))  
  
    if output:  
        Path(output).write_text(json.dumps(result, indent=2))  
        typer.echo(f"📄 Saved to {output}")  
  
    sys.exit(1 if result["status"] == "FAILED" else 0)  
  
if __name__ == "__main__":  
    app()