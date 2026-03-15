"""
Script to download and prepare datasets for training.
Run: python scripts/download_datasets.py
"""
import os
import requests
import pandas as pd
from pathlib import Path


def download_combined_fraud_dataset():
    """Download the comprehensive fraud detection dataset [citation:4]"""
    url = "https://raw.githubusercontent.com/RockENZO/data/main/combined_fraud_detection_dataset.csv"
    save_path = Path("data/raw/combined_fraud_detection_dataset.csv")

    if not save_path.exists():
        print("Downloading combined fraud dataset...")
        response = requests.get(url)
        save_path.parent.mkdir(parents=True, exist_ok=True)
        save_path.write_bytes(response.content)
        print(f"Saved to {save_path}")

    return save_path


def load_and_preview():
    """Load dataset and show sample"""
    df = pd.read_csv("data/raw/combined_fraud_detection_dataset.csv")
    print(f"Dataset shape: {df.shape}")
    print(f"Columns: {df.columns.tolist()}")
    print(f"\nSample:\n{df.head(3)}")
    print(f"\nFraud ratio: {df['label'].mean():.2%}")

    # Filter for email data only
    email_df = df[df['data_type'] == 'Email Classification']
    print(f"\nEmail samples: {len(email_df)}")

    return email_df


if __name__ == "__main__":
    download_combined_fraud_dataset()
    email_data = load_and_preview()

    # Save email subset for training
    email_data.to_csv("data/raw/email_subset.csv", index=False)
    print("Email subset saved for training")