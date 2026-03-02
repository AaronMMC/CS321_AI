from fastapi import APIRouter, HTTPException, Request
from typing import List
from backend.models.schemas import SpotRecommendation, UserPreference
from nlp_engine.recommender import get_recommendations

router = APIRouter()

@router.post("/recommend", response_model=List[SpotRecommendation])
async def get_travel_recommendations(request: Request, prefs: UserPreference):
    # 1. Get data from app.state (This fixes the previous bug)
    locations_data = getattr(request.app.state, "locations_data", [])
    vectorizer = getattr(request.app.state, "vectorizer", None)

    if not vectorizer or not locations_data:
        raise HTTPException(status_code=503, detail="System initializing or data missing.")

    # 2. Run NLP Logic
    try:
        results = get_recommendations(
            user_input=prefs.text_query,
            locations_data=locations_data,
            vectorizer_obj=vectorizer,
            top_n=5
        )
    except Exception as e:
        print(f"Error: {e}")
        raise HTTPException(status_code=500, detail="Processing error")

    return results