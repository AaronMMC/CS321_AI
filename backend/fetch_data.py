import googlemaps
import populartimes
import pandas as pd
import time
import datetime
import os
from backend.config import settings

# TODO: Add your key to .env file as GOOGLE_API_KEY=xyz
API_KEY = os.getenv("GOOGLE_API_KEY")

CITY_LOCATION = (16.4023, 120.5960)  # Baguio
SEARCH_QUERIES = ["Cafe", "Park", "Tourist Attraction", "Restaurant with view"]
RADIUS_METERS = 3000


def fetch_and_update_data():
    if not API_KEY:
        print("❌ Error: Missing GOOGLE_API_KEY in .env file.")
        return

    print("--- Starting Data Update ---")
    gmaps = googlemaps.Client(key=API_KEY)

    all_spots = []
    seen_ids = set()

    for query in SEARCH_QUERIES:
        print(f"Searching for: {query}...")
        results = gmaps.places_nearby(location=CITY_LOCATION, radius=RADIUS_METERS, keyword=query)

        for place in results.get('results', []):
            place_id = place['place_id']
            if place_id in seen_ids: continue
            seen_ids.add(place_id)

            name = place.get('name')
            crowd_level = 1

            try:
                # Attempt to fetch live crowd data
                pop_data = populartimes.get_id(API_KEY, place_id)
                current_pop = pop_data.get('current_popularity')

                if current_pop is not None:
                    crowd_level = max(1, int(current_pop / 10))
                    print(f"  [LIVE] {name}: {crowd_level}/10")
                else:
                    # Fallback to historical average
                    now = datetime.datetime.now()
                    week_data = pop_data.get('populartimes', [])
                    if week_data:
                        today_sched = week_data[now.weekday()]['data']
                        hist_pop = today_sched[now.hour]
                        crowd_level = max(1, int(hist_pop / 10))
                        print(f"  [HIST] {name}: {crowd_level}/10")
                    else:
                        print(f"  [----] {name}: No data")
            except Exception as e:
                print(f"  [ERR ] {name}: {e}")
                crowd_level = 1

            # Determine Category
            types = place.get('types', [])
            category = "General"
            if "park" in types:
                category = "Park"
            elif "cafe" in types:
                category = "Cafe"
            elif "food" in types:
                category = "Food"
            elif "museum" in types:
                category = "History"

            all_spots.append({
                "id": place_id,
                "name": name,
                "description": f"{name} is a {category} spot located at {place.get('vicinity')}.",
                "category": category,
                "city": "Baguio",
                "crowd_level": crowd_level,
                "lat": place['geometry']['location']['lat'],
                "lon": place['geometry']['location']['lng']
            })
            time.sleep(0.5)

    # SAVE TO RAW DATA PATH (CS321_AI/data/raw/tourist_spots.csv)
    if all_spots:
        df = pd.DataFrame(all_spots)
        settings.RAW_DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(settings.RAW_DATA_PATH, index=False)
        print(f"\n✅ Successfully saved {len(df)} spots to: {settings.RAW_DATA_PATH}")
    else:
        print("No spots found.")


if __name__ == "__main__":
    fetch_and_update_data()