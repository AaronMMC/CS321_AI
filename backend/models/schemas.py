from pydantic import BaseModel
from typing import List, Optional

# ASSIGNED TO: Gav

class UserPreference(BaseModel):
    """
    TODO: Define the input data structure.
    Fields needed:
    - text_query: str (e.g., "I want coffee")
    - max_crowd_tolerance: int (1-10)
    """
    pass

class SpotRecommendation(BaseModel):
    """
    TODO: Define the output data structure for a single spot.
    Fields needed:
    - id: int
    - name: str
    - description: str
    - crowd_level: int
    - score: float
    """
    pass