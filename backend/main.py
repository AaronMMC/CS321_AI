from fastapi import FastAPI
# TODO: Import the recommendations router

# ASSIGNED TO: Renzo
app = FastAPI(title="CrowdAware API")

# TODO: Include the router from backend/routers/recommendations.py

@app.on_event("startup")
async def startup_event():
    """
    TODO:
    1. Load the CSV data using Pandas.
    2. Initialize the NLP Vectorizer and fit it on the data.
    3. Store these in app.state so the router can access them.
    """
    print("Starting up...")

@app.get("/")
def read_root():
    return {"message": "System is Online"}