import json
import os
from datetime import datetime
from typing import List, Dict, Any

TICKETS_FILE = os.path.join("data", "tickets.jsonl")

def create_ticket(alert_text: str, iocs: List[Dict[str, str]], classification: Any, 
                  response_text: str, status: str, guardrail_reason: str, 
                  retrieved_docs: List[Dict], processing_time: float) -> Dict:
    """Generates a structured incident ticket aligned with MITRE ATT&CK."""
    
    ticket = {
        "ticket_id": f"INC-{int(datetime.now().timestamp())}",
        "timestamp": datetime.now().isoformat(),
        "threat_vector": classification.threat_vector,
        "severity": classification.severity,
        "mitre_tactics": classification.tactics,
        "iocs": iocs,
        "status": status,
        "guardrail_reason": guardrail_reason,
        "remediation_plan": response_text,
        "sources_cited": [doc['source'] for doc in retrieved_docs],
        "processing_time_seconds": round(processing_time, 2)
    }
    
    # Append to JSONL file
    with open(TICKETS_FILE, "a") as f:
        f.write(json.dumps(ticket) + "\n")
        
    return ticket

def get_dashboard_stats() -> Dict:
    """Calculates summary statistics for the terminal dashboard."""
    if not os.path.exists(TICKETS_FILE):
        return {"error": "No tickets found."}
        
    total = 0
    escalated = 0
    severities = {}
    vectors = {}
    tactics = {}
    times = []
    
    with open(TICKETS_FILE, "r") as f:
        for line in f:
            if not line.strip(): continue
            t = json.loads(line)
            total += 1
            if t["status"] == "Escalated": escalated += 1
            
            sev = t.get("severity", "Unknown")
            severities[sev] = severities.get(sev, 0) + 1
            
            vec = t.get("threat_vector", "Unknown")
            vectors[vec] = vectors.get(vec, 0) + 1
            
            for tactic in t.get("mitre_tactics", []):
                tactics[tactic] = tactics.get(tactic, 0) + 1
                
            times.append(t.get("processing_time_seconds", 0))
            
    avg_time = sum(times) / total if total > 0 else 0
    escalation_rate = (escalated / total * 100) if total > 0 else 0
    
    return {
        "total_incidents": total,
        "escalation_rate": f"{escalation_rate:.1f}%",
        "average_processing_time": f"{avg_time:.2f}s",
        "by_severity": severities,
        "by_vector": vectors,
        "by_tactic": tactics
    }