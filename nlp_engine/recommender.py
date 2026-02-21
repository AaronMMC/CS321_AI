from .vectorizer import CustomTFIDF
from .crowd_logic import apply_crowd_penalty


# ASSIGNED TO: Brent

def _cosine_similarity(vec1: dict, vec2: dict) -> float:
    """Calculates the dot product of two L2-normalized sparse vectors."""
    similarity = 0.0
    if len(vec1) > len(vec2):
        vec1, vec2 = vec2, vec1

    for word, weight in vec1.items():
        if word in vec2:
            similarity += weight * vec2[word]

    return similarity


def get_recommendations(user_input: str, locations_data: list[dict], vectorizer_obj: CustomTFIDF, top_n=5):
    """
    1. Transforms user_input into a vector using the trained vectorizer.
    2. Calculates cosine similarity against all locations in the database.
    3. Applies the crowd penalty logic.
    4. Returns the top N locations.
    """
    user_vector = vectorizer_obj.transform(user_input)

    if not user_vector:
        return []

    results = []

    for i, loc in enumerate(locations_data):
        loc_vector = vectorizer_obj.doc_vectors[i]

        # Calculate base relevance match
        relevance = _cosine_similarity(user_vector, loc_vector)

        # Apply crowd penalty
        crowd_level = int(loc.get('crowd_level', 1))
        final_score = apply_crowd_penalty(relevance, crowd_level)

        # Store results temporarily
        loc_result = loc.copy()
        loc_result['relevance'] = relevance
        loc_result['final_score'] = final_score
        results.append(loc_result)

    # Sort from best match to worst match based on the penalized score
    results.sort(key=lambda x: x['final_score'], reverse=True)

    return results[:top_n]