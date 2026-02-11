from fastapi import APIRouter

from backend.models.schemas import SpotRecommendation, UserPreference

# TODO: Import UserPreference and SpotRecommendation from models.schemas

router = APIRouter()

# ASSIGNED TO: Gav
@router.post("/recommend", response_model=list[SpotRecommendation])
async def get_travel_recommendations(prefs: UserPreference):
    """
    TODO:
    1. Import the global dataframe and vectorizer from main.py (or load them here).
    2. Call nlp_engine.recommender.get_recommendations().
    3. Return the list of recommended spots.
    """
    pass