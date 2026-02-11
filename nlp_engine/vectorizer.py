import pandas as pd
# TODO: Import TfidfVectorizer from sklearn.feature_extraction.text
# TODO: Import pickle

# ASSIGNED TO: Aaron
class Vectorizer:
    def __init__(self):
        self.model = None # TODO: Initialize TfidfVectorizer here
        self.vectors = None

    def fit_transform(self, data: pd.DataFrame, text_column: str):
        """
        TODO:
        1. Fit the TF-IDF model on the 'text_column'.
        2. Save the resulting matrix to self.vectors.
        3. (Bonus) Save the model to 'data/raw/vectors.pkl' using pickle.
        """
        pass