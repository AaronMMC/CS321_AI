"""
Data collection module - downloads and prepares datasets for training.
"""

import os
import pandas as pd
import requests
from pathlib import Path
from typing import Optional, Dict, List
from loguru import logger
from zipfile import ZipFile
import io


class DataCollector:
    """Download and prepare datasets for training"""

    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.raw_dir = self.data_dir / "raw"
        self.processed_dir = self.data_dir / "processed"

        # Create directories
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.processed_dir.mkdir(parents=True, exist_ok=True)

        # Dataset sources
        self.datasets = {
            "combined_fraud": {
                "url": "https://raw.githubusercontent.com/RockENZO/data/main/combined_fraud_detection_dataset.csv",
                "filename": "combined_fraud_detection_dataset.csv",
                "description": "Comprehensive fraud detection dataset (194k samples)",
                "type": "csv"
            },
            "enron_spam": {
                "url": "https://github.com/MWiechmann/enron_spam_data/raw/master/enron_spam_data.csv",
                "filename": "enron_spam_data.csv",
                "description": "Enron email spam dataset",
                "type": "csv"
            },
            "phishing_emails": {
                "url": "https://raw.githubusercontent.com/astudentinearth/phishing-email-detection/master/Phishing_Email.csv",
                "filename": "phishing_emails.csv",
                "description": "Phishing email dataset",
                "type": "csv"
            }
        }

    def download_dataset(self, dataset_key: str) -> Optional[Path]:
        """Download a specific dataset"""

        if dataset_key not in self.datasets:
            logger.error(f"Unknown dataset: {dataset_key}")
            return None

        dataset = self.datasets[dataset_key]
        save_path = self.raw_dir / dataset["filename"]

        if save_path.exists():
            logger.info(f"Dataset already exists: {save_path}")
            return save_path

        logger.info(f"Downloading {dataset_key} from {dataset['url']}")

        try:
            response = requests.get(dataset["url"], timeout=30)
            response.raise_for_status()

            # Save file
            with open(save_path, 'wb') as f:
                f.write(response.content)

            logger.success(f"Downloaded {dataset_key} to {save_path}")
            return save_path

        except requests.RequestException as e:
            logger.error(f"Failed to download {dataset_key}: {e}")
            return None

    def download_all_datasets(self) -> Dict[str, Optional[Path]]:
        """Download all available datasets"""
        results = {}
        for key in self.datasets:
            results[key] = self.download_dataset(key)
        return results

    def load_and_preview(self, dataset_key: str) -> Optional[pd.DataFrame]:
        """Load dataset and show preview"""

        file_path = self.raw_dir / self.datasets[dataset_key]["filename"]

        if not file_path.exists():
            logger.error(f"Dataset not found: {file_path}")
            return None

        try:
            # Load based on file type
            if file_path.suffix == '.csv':
                df = pd.read_csv(file_path)
            else:
                logger.error(f"Unsupported file type: {file_path.suffix}")
                return None

            # Show dataset info
            logger.info(f"Dataset: {dataset_key}")
            logger.info(f"Shape: {df.shape}")
            logger.info(f"Columns: {df.columns.tolist()}")

            # Show sample
            logger.info(f"\nSample:\n{df.head(3)}")

            return df

        except Exception as e:
            logger.error(f"Failed to load dataset: {e}")
            return None

    def prepare_training_data(self, sample_frac: float = 0.2) -> Path:
        """
        Prepare training data from multiple sources.
        Args:
            sample_frac: Fraction of data to use (for quick training)
        """
        logger.info("Preparing training data...")

        all_data = []

        # Try to load each dataset
        for key in self.datasets:
            df = self.load_and_preview(key)
            if df is not None:
                all_data.append(df)

        if not all_data:
            logger.error("No datasets available")
            # Create a minimal synthetic dataset as fallback
            return self._create_synthetic_data()

        # Combine datasets (if multiple)
        combined = pd.concat(all_data, ignore_index=True)

        # Sample if needed
        if sample_frac < 1.0:
            combined = combined.sample(frac=sample_frac, random_state=42)

        # Ensure we have text and label columns
        # (This will need adjustment based on actual dataset structure)
        if 'text' not in combined.columns and 'message' in combined.columns:
            combined['text'] = combined['message']

        if 'label' not in combined.columns and 'spam' in combined.columns:
            combined['label'] = combined['spam']

        # Save processed data
        save_path = self.processed_dir / "training_data.csv"
        combined.to_csv(save_path, index=False)

        logger.success(f"Saved {len(combined)} samples to {save_path}")
        return save_path

    def _create_synthetic_data(self) -> Path:
        """Create synthetic training data as fallback"""
        logger.warning("Creating synthetic training data")

        # Simple synthetic dataset
        data = {
            'text': [
                # Legitimate emails
                "Meeting scheduled for tomorrow at 10am",
                "Please find attached the quarterly report",
                "Your leave request has been approved",
                # Phishing emails
                "URGENT: Your account will be suspended. Click here to verify",
                "You won $1,000,000! Claim your prize now",
                "Verify your GCash account immediately",
                "Your password is expiring. Update here",
                "Unusual login detected. Confirm your identity",
            ],
            'label': [0, 0, 0, 1, 1, 1, 1, 1]  # 0=legit, 1=phishing
        }

        df = pd.DataFrame(data)

        # Duplicate to have more samples
        df = pd.concat([df] * 100, ignore_index=True)

        save_path = self.processed_dir / "synthetic_training_data.csv"
        df.to_csv(save_path, index=False)

        logger.success(f"Created synthetic dataset with {len(df)} samples")
        return save_path