import re

# ASSIGNED TO: Aaron
# A basic set of stopwords to ignore common words without needing NLTK
STOPWORDS = {"a", "an", "the", "and", "or", "but", "is", "are", "am", "in", "on", "at", "to", "for", "with", "of", "it",
             "this", "that", "i", "want", "looking"}


def clean_and_tokenize(text: str) -> list[str]:
    """
    Implemented text cleaning logic.
    1. Converts 'text' to lowercase.
    2. Removes punctuation and special characters.
    3. Removes stopwords.
    4. Returns a list of the cleaned words.
    """
    if not isinstance(text, str):
        return []

    # Convert to lowercase
    text = text.lower()

    # Remove punctuation and special characters using regex
    text = re.sub(r'[^a-z0-9\s]', '', text)

    # Split into individual words
    tokens = text.split()

    # Filter out common stopwords
    return [word for word in tokens if word not in STOPWORDS]