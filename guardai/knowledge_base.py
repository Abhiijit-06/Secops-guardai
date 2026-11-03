import os
import glob
import chromadb
from chromadb.utils import embedding_functions
from langchain_text_splitters import RecursiveCharacterTextSplitter

DB_PATH = os.path.join("data", "chroma_db")
KB_PATH = os.path.join("data", "knowledge_base")
COLLECTION_NAME = "secops_playbooks"

def get_chroma_client():
    return chromadb.PersistentClient(path=DB_PATH)

def ingest():
    """Reads synthetic playbooks, chunks them, and stores them in ChromaDB."""
    if not os.path.exists(KB_PATH):
        os.makedirs(KB_PATH)

    client = get_chroma_client()
    # The default embedding function uses all-MiniLM-L6-v2
    emb_fn = embedding_functions.DefaultEmbeddingFunction()
    
    # We use cosine similarity to match the report's relevance threshold logic
    collection = client.get_or_create_collection(
        name=COLLECTION_NAME, 
        embedding_function=emb_fn,
        metadata={"hnsw:space": "cosine"}
    )
    
    # Split rules: 800 chars with 100 char overlap
    splitter = RecursiveCharacterTextSplitter(chunk_size=800, chunk_overlap=100)
    
    documents, metadatas, ids = [], [], []
    file_paths = glob.glob(os.path.join(KB_PATH, "*.txt"))
    
    if not file_paths:
        print(f"No documents found in {KB_PATH}")
        return
        
    for doc_idx, file_path in enumerate(file_paths):
        with open(file_path, "r", encoding="utf-8") as f:
            text = f.read()
            
        filename = os.path.basename(file_path)
        chunks = splitter.split_text(text)
        
        for i, chunk in enumerate(chunks):
            documents.append(chunk)
            metadatas.append({"source": filename, "chunk_index": i})
            ids.append(f"doc_{doc_idx}_chunk_{i}")
            
    if documents:
        collection.add(documents=documents, metadatas=metadatas, ids=ids)
        print(f"Indexed {len(file_paths)} documents as {len(documents)} chunks.")

def retrieve(query_text: str, k: int = 4):
    """Retrieves top-k relevant chunks based on the query."""
    client = get_chroma_client()
    emb_fn = embedding_functions.DefaultEmbeddingFunction()
    
    try:
        collection = client.get_collection(name=COLLECTION_NAME, embedding_function=emb_fn)
    except Exception:
        return []
        
    results = collection.query(query_texts=[query_text], n_results=k)
    
    retrieved_docs = []
    if results and results['documents'] and results['documents'][0]:
        for i in range(len(results['documents'][0])):
            # In Chroma with cosine space, distance is 1 - cosine_similarity.
            score = 1.0 - results['distances'][0][i] 
            retrieved_docs.append({
                "content": results['documents'][0][i],
                "source": results['metadatas'][0][i]["source"],
                "score": score
            })
    return retrieved_docs