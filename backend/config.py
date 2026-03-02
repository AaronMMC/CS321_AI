import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# CS321_AI root directory
BASE_DIR = Path(__file__).resolve().parent.parent


class Settings:
    PROJECT_NAME: str = "CrowdAware Travel"

    # 1. Raw Data (The CSV you download from Google)
    # matches: CS321_AI/data/raw/tourist_spots.csv
    RAW_DATA_PATH: Path = BASE_DIR / "data" / "raw" / "tourist_spots.csv"

    # 2. Processed Models (The AI brain)
    # matches: CS321_AI/data/processed/vectors.pkl
    MODEL_PATH: Path = BASE_DIR / "data" / "processed" / "vectors.pkl"

    # 3. Database File (The SQLite DB)
    # matches: CS321_AI/data/tourism.db
    DB_PATH: Path = BASE_DIR / "data" / "tourism.db"


settings = Settings()