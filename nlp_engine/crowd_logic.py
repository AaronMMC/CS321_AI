# ASSIGNED TO: Brent
def apply_crowd_penalty(base_score: float, crowd_level: int) -> float:
    """
    Adjusts the final score based on how crowded a place is.
    Formula: Final Score = base_score * (1 - (crowd_level / 10))

    Args:
    - base_score: The cosine similarity score (0.0 to 1.0)
    - crowd_level: An integer from 1 (Empty) to 10 (Full)
    """
    # Ensure crowd_level stays within logical bounds
    crowd_level = max(1, min(10, crowd_level))

    # Calculate penalty
    penalty_multiplier = 1.0 - (crowd_level / 10.0)

    return base_score * penalty_multiplier