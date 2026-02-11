# ASSIGNED TO: Brent
def apply_crowd_penalty(base_score: float, crowd_level: int) -> float:
    """
    TODO: Implement the logic to penalize crowded spots.

    Formula Suggestion:
    Final Score = base_score * (1 - (crowd_level / 10))

    Args:
    - base_score: The cosine similarity score (0.0 to 1.0)
    - crowd_level: An integer from 1 (Empty) to 10 (Full)
    """
    return 0.0