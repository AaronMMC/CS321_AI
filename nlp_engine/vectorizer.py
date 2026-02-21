import math
import pickle
import os
from collections import Counter
from .preprocessor import clean_and_tokenize


# ASSIGNED TO: Aaron
class CustomTFIDF:
    def __init__(self):
        self.idf = {}
        self.doc_vectors = []
        self.is_fitted = False

    def fit_transform(self, documents: list[str]) -> list[dict]:
        """Calculates TF-IDF from scratch for a list of texts."""
        tokenized_docs = [clean_and_tokenize(doc) for doc in documents]
        N = len(tokenized_docs)

        df = Counter()
        for tokens in tokenized_docs:
            unique_tokens = set(tokens)
            for token in unique_tokens:
                df[token] += 1

        for word, count in df.items():
            self.idf[word] = math.log((1 + N) / (1 + count)) + 1

        self.doc_vectors = [self._compute_vector(tokens) for tokens in tokenized_docs]
        self.is_fitted = True

        return self.doc_vectors

    def _compute_vector(self, tokens: list[str]) -> dict:
        """Helper to compute L2-normalized vector."""
        tf = Counter(tokens)
        doc_len = len(tokens)
        vector = {}
        if doc_len == 0: return vector

        norm = 0.0
        for word, count in tf.items():
            if word in self.idf:
                weight = (count / doc_len) * self.idf[word]
                vector[word] = weight
                norm += weight ** 2

        norm = math.sqrt(norm)
        if norm > 0:
            for word in vector:
                vector[word] /= norm

        return vector

    def transform(self, text: str) -> dict:
        if not self.is_fitted:
            raise ValueError("Model not fitted.")
        tokens = clean_and_tokenize(text)
        return self._compute_vector(tokens)

    def save(self, filepath: str):
        """Saves the resulting matrix so it doesn't need to recalculate on restart."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'wb') as f:
            pickle.dump({'idf': self.idf, 'doc_vectors': self.doc_vectors}, f)

    def load(self, filepath: str) -> bool:
        """Loads the pre-calculated data if vectors.pkl exists."""
        if os.path.exists(filepath):
            with open(filepath, 'rb') as f:
                data = pickle.load(f)
                self.idf = data['idf']
                self.doc_vectors = data['doc_vectors']
                self.is_fitted = True
            return True
        return False