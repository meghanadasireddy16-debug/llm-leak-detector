import chromadb
from chromadb.utils import embedding_functions
import uuid

class VaultManager:
    def __init__(self, db_path="./security_vault"):
        # 1. Initialize persistent client
        self.client = chromadb.PersistentClient(path=db_path)
        
        # 2. Use the same embedding function as your detector for consistency
        # MiniLM-L6-v2 is the industry standard for this
        self.emb_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name="all-MiniLM-L6-v2"
        )
        
        # 3. Get or create the "forbidden_code" collection
        self.collection = self.client.get_or_create_collection(
            name="forbidden_vault",
            embedding_function=self.emb_fn,
            metadata={"hnsw:space": "cosine"} # We use cosine similarity
        )

    def add_to_vault(self, code_snippet, metadata=None):
        """Adds a new snippet to the forbidden database."""
        self.collection.add(
            documents=[code_snippet],
            metadatas=[metadata or {"type": "proprietary_code"}],
            ids=[str(uuid.uuid4())]
        )

    def query_vault(self, text, n_results=1):
        """Queries the DB for the most similar forbidden snippets."""
        return self.collection.query(
            query_texts=[text],
            n_results=n_results
        )

    def get_all_snippets(self):
        """Returns all protected snippets (for the UI)."""
        return self.collection.get()

    def clear_vault(self):
        """Wipes the database."""
        ids = self.collection.get()['ids']
        if ids:
            self.collection.delete(ids=ids)