from typing import List, Dict, Tuple
from guardai.llm import get_llm
from guardai.prompts import GENERATION_PROMPT
from guardai.guardrail import check_retrieval_sufficiency, check_grounding

def format_context(docs: List[Dict]) -> str:
    """Formats retrieved chunks with strict document IDs."""
    if not docs: 
        return "No internal documentation found."
    formatted = []
    for i, doc in enumerate(docs):
        formatted.append(f"[Doc-{i+1}] Source: {doc['source']}\n{doc['content']}\n")
    return "\n".join(formatted)

def generate_response(alert: str, iocs: str, threat_class: str, severity: str, docs: List[Dict]) -> Tuple[str, str, str]:
    """Generates a grounded RAG response or triggers the escalation guardrail."""
    
    # Check if we retrieved enough context to safely generate advice
    if not check_retrieval_sufficiency(docs):
        return ("No remediation advice provided. Escalate to Tier 3 Incident Response Lead.", 
                "Escalated", 
                "Failed retrieval sufficiency check.")

    context_str = format_context(docs)
    llm = get_llm()
    chain = GENERATION_PROMPT | llm
    
    # Generate the response
    result = chain.invoke({
        "alert": alert,
        "iocs": iocs,
        "threat_class": threat_class,
        "severity": severity,
        "context": context_str
    })
    
    # Safely handle string vs list content returned by Gemini
    if isinstance(result.content, list):
        parts = []
        for part in result.content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict) and "text" in part:
                parts.append(part["text"])
            else:
                parts.append(str(part))
        response_text = "\n".join(parts)
    else:
        response_text = str(result.content)
    
    # Verify the response is grounded in the retrieved sources
    is_grounded, guardrail_reason = check_grounding(response_text, docs)
    
    if not is_grounded:
        return ("No remediation advice provided. Escalate to Tier 3 Incident Response Lead.", 
                "Escalated", 
                guardrail_reason)
                
    return response_text, "Processed", "Passed"