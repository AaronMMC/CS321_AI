# ASSIGNED TO: Renzo
import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    # TODO: Load these variables from the .env file
    PROJECT_NAME: str = "CrowdAware Travel"
    DATA_PATH: str = os.getenv("DATA_PATH", "data/processed/tourist_spots.csv")


settings = Settings()