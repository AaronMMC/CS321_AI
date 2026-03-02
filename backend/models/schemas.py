from pydantic import BaseModel, Field
from typing import List, Optional

# ASSIGNED TO: Gav

class UserPreference(BaseModel):
    """
    Defines what we expect from the user.
    """
    text_query: str = Field(..., description="What the user is looking for (e.g., 'quiet beach with seafood')")
    max_crowd_tolerance: int = Field(10, ge=1, le=10, description="Crowd tolerance level from 1 (Hates crowds) to 10 (Loves crowds)")

class SpotRecommendation(BaseModel):
    """
    Defines what we return to the user.
    """
    id: int
    name: str
    description: str
    category: str
    city: str
    crowd_level: int
    lat: float
    lon: float
    relevance: float = Field(..., description="How well the text matched (0-1)")
    final_score: float = Field(..., description="Score after crowd penalty applied")