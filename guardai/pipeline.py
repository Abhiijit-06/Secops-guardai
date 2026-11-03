import time
from guardai.iocs import extract_iocs
from guardai.classifier import classify, format_iocs
from guardai.knowledge_base import retrieve
from guardai.generator import generate_response
from guardai.tickets import create_ticket

class GuardAI:
    """Main pipeline integrating extraction, RAG, and guardrails."""
    
    def analyze(self, alert_text: str, save_ticket: bool = True):
        start_time = time.time()
        
        # 1. Extract IoCs
        iocs = extract_iocs(alert_text)
        
        # 2. Classify Threat and Severity
        classification = classify(alert_text, iocs)
        
        # 3. Retrieve Context
        # Query combines alert and threat vector for better semantic matching
        query_text = f"Threat: {classification.threat_vector}. Alert: {alert_text}"
        docs = retrieve(query_text, k=4)
        
        # 4. Generate Response with Guardrails
        formatted_iocs = format_iocs(iocs)
        response_text, status, guardrail_reason = generate_response(
            alert=alert_text,
            iocs=formatted_iocs,
            threat_class=classification.threat_vector,
            severity=classification.severity,
            docs=docs
        )
        
        processing_time = time.time() - start_time
        
        # 5. Create Ticket
        ticket = None
        if save_ticket:
            ticket = create_ticket(
                alert_text=alert_text,
                iocs=iocs,
                classification=classification,
                response_text=response_text,
                status=status,
                guardrail_reason=guardrail_reason,
                retrieved_docs=docs,
                processing_time=processing_time
            )
            
        return {
            "iocs": iocs,
            "classification": classification,
            "retrieved_docs": docs,
            "response": response_text,
            "status": status,
            "reason": guardrail_reason,
            "time": processing_time,
            "ticket": ticket
        }