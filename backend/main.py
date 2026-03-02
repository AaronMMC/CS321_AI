import pandas as pd
from contextlib import asynccontextmanager
from fastapi import FastAPI, BackgroundTasks
from backend.config import settings
from backend.routers import recommendations
from nlp_engine.vectorizer import CustomTFIDF
from backend.fetch_data import fetch_and_update_data
# Import DB components to create tables
from backend.database import engine, Base
from backend.models import sql_models


def load_data_into_memory(app: FastAPI):
    """Loads CSV data and retrains the NLP model."""
    try:
        print(f"🔄 Loading data from {settings.RAW_DATA_PATH}...")
        df = pd.read_csv(settings.RAW_DATA_PATH)
        df.fillna('', inplace=True)

        # Store data in app state
        app.state.locations_data = df.to_dict(orient='records')

        print("🧠 Retraining NLP model...")
        vectorizer = CustomTFIDF()
        corpus = [f"{loc['description']} {loc['category']}" for loc in app.state.locations_data]
        vectorizer.fit_transform(corpus)
        app.state.vectorizer = vectorizer

        # Save vectorizer to processed folder (data/processed/vectors.pkl)
        settings.MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        vectorizer.save(settings.MODEL_PATH)

        print(f"✅ System Updated! {len(df)} locations loaded.")
    except Exception as e:
        print(f"⚠️ Error loading data: {e}")
        app.state.locations_data = []
        app.state.vectorizer = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Create DB Tables automatically (The "DDL Auto" feature)
    Base.metadata.create_all(bind=engine)
    print("📂 Database tables checked/created.")

    # 2. Load CSV Data for the NLP engine
    load_data_into_memory(app)
    yield


app = FastAPI(title="CrowdAware Travel", lifespan=lifespan)

app.include_router(recommendations.router)


@app.post("/admin/trigger-update")
async def trigger_live_update(background_tasks: BackgroundTasks):
    background_tasks.add_task(run_scraper_and_reload)
    return {"message": "Update started in background."}


def run_scraper_and_reload():
    print("🚀 Background Task: Fetching new data...")
    try:
        fetch_and_update_data()
        load_data_into_memory(app)
        print("✨ Update Complete!")
    except Exception as e:
        print(f"❌ Task Failed: {e}")


@app.get("/")
def read_root():
    return {"status": "Online", "locations": len(getattr(app.state, "locations_data", []))}