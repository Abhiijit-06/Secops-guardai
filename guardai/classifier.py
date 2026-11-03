from pydantic import BaseModel, Field
from typing import List, Dict
from guardai.llm import get_llm
from guardai.prompts import CLASSIFICATION_PROMPT

# The 14 official MITRE ATT&CK Enterprise Tactics
VALID_TACTICS = {
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact"
}

class Classification(BaseModel):
    threat_vector: str = Field(description="Threat category (e.g., Phishing, Malware, Brute Force)")
    severity: str = Field(description="Severity level: Low, Medium, High, Critical")
    tactics: List[str] = Field(description="Applicable MITRE ATT&CK tactics")
    rationale: str = Field(description="Brief explanation for this classification")

def format_iocs(iocs: List[Dict[str, str]]) -> str:
    if not iocs: 
        return "None detected."
    return "\n".join([f"- {ioc['type']}: {ioc['value']}" for ioc in iocs])

def classify(alert: str, iocs: List[Dict[str, str]]) -> Classification:
    """Classifies the threat vector, assigns severity, and maps to MITRE tactics."""
    llm = get_llm()
    # Force Gemini to return the structured Pydantic object
    structured_llm = llm.with_structured_output(Classification)
    chain = CLASSIFICATION_PROMPT | structured_llm
    
    result: Classification = chain.invoke({"alert": alert, "iocs": format_iocs(iocs)})
    
    # Filter out any hallucinated tactics to ensure accurate ATT&CK mapping
    result.tactics = [t for t in result.tactics if t in VALID_TACTICS]
    
    return result