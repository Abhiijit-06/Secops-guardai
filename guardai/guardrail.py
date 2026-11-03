import re
from typing import List, Dict, Tuple

def check_retrieval_sufficiency(docs: List[Dict], min_docs: int = 2, threshold: float = 0.30) -> bool:
    """Checks if enough high-quality context was retrieved."""
    valid_docs = [d for d in docs if d.get("score", 1.0) >= threshold]
    return len(valid_docs) >= min_docs

def extract_citations(text: str) -> List[str]:
    """Finds all document citations in the text formatted like [Doc-1]."""
    return re.findall(r'\[Doc-\d+\]', text)

def check_grounding(response_text, retrieved_docs: List[Dict]) -> Tuple[bool, str]:
    """Validates that every cited document was actually retrieved."""
    if isinstance(response_text, list):
        response_text = "\n".join(str(item) for item in response_text)
    
    response_text = str(response_text)

    if "insufficient context" in response_text.lower():
        return False, "Model reported insufficient context."
        
    citations = extract_citations(response_text)
    if not citations:
        return False, "No sources cited in the response."
        
    # Create a list of valid citation labels based on the retrieved docs
    valid_labels = [f"[Doc-{i+1}]" for i in range(len(retrieved_docs))]
    
    for citation in citations:
        if citation not in valid_labels:
            return False, f"Hallucinated citation found: {citation}"
            
    return True, "Passed"