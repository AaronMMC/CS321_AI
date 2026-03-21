#!/usr/bin/env python3
"""
Dataset download script for Email Security Gateway.
Downloads all required datasets for training and testing.
"""

import os
import sys
import requests
import pandas as pd
from pathlib import Path
from typing import Dict, Optional
import zipfile
import io
from loguru import logger

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

# Configure logger
logger.add(sys.stdout, level="INFO")

# Data directories
DATA_DIR = Path(__file__).parent.parent / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"

# Create directories
RAW_DIR.mkdir(parents=True, exist_ok=True)
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)


class DatasetDownloader:
    """Download and prepare datasets for training"""

    DATASETS = {
        "combined_fraud": {
            "url": "https://raw.githubusercontent.com/RockENZO/data/main/combined_fraud_detection_dataset.csv",
            "filename": "combined_fraud_detection_dataset.csv",
            "description": "Combined fraud detection dataset (194k samples)",
            "size_mb": 45,
            "format": "csv"
        },
        "enron_spam": {
            "url": "https://github.com/MWiechmann/enron_spam_data/raw/master/enron_spam_data.csv",
            "filename": "enron_spam_data.csv",
            "description": "Enron email spam dataset",
            "size_mb": 12,
            "format": "csv"
        },
        "phishing_emails": {
            "url": "https://raw.githubusercontent.com/astudentinearth/phishing-email-detection/master/Phishing_Email.csv",
            "filename": "phishing_emails.csv",
            "description": "Phishing email dataset",
            "size_mb": 8,
            "format": "csv"
        },
        "sms_spam": {
            "url": "https://raw.githubusercontent.com/justmarkham/pydata-dc-2016-tutorial/master/sms.tsv",
            "filename": "sms_spam.csv",
            "description": "SMS spam dataset",
            "size_mb": 1,
            "format": "csv"
        }
    }

    def __init__(self, data_dir: Path = DATA_DIR):
        self.data_dir = data_dir
        self.raw_dir = self.data_dir / "raw"
        self.processed_dir = self.data_dir / "processed"

    def download_dataset(self, dataset_key: str) -> Optional[Path]:
        """Download a single dataset"""

        if dataset_key not in self.DATASETS:
            logger.error(f"Unknown dataset: {dataset_key}")
            return None

        dataset = self.DATASETS[dataset_key]
        save_path = self.raw_dir / dataset["filename"]

        if save_path.exists():
            logger.info(f"Dataset already exists: {save_path} ({save_path.stat().st_size / 1024 / 1024:.1f} MB)")
            return save_path

        logger.info(f"Downloading {dataset_key} from {dataset['url']}")
        logger.info(f"Size: ~{dataset['size_mb']} MB")

        try:
            response = requests.get(dataset["url"], timeout=60, stream=True)
            response.raise_for_status()

            # Download with progress
            total_size = int(response.headers.get('content-length', 0))
            block_size = 8192

            with open(save_path, 'wb') as f:
                downloaded = 0
                for chunk in response.iter_content(chunk_size=block_size):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total_size:
                            percent = (downloaded / total_size) * 100
                            logger.info(f"  Progress: {percent:.1f}%", end='\r')

            logger.info(f"\n✓ Downloaded to {save_path} ({save_path.stat().st_size / 1024 / 1024:.1f} MB)")
            return save_path

        except requests.RequestException as e:
            logger.error(f"Failed to download {dataset_key}: {e}")
            return None

    def download_all(self) -> Dict[str, Optional[Path]]:
        """Download all datasets"""
        logger.info("="*50)
        logger.info("DOWNLOADING ALL DATASETS")
        logger.info("="*50)

        results = {}
        for key in self.DATASETS:
            results[key] = self.download_dataset(key)

        return results

    def load_and_preview(self, dataset_key: str) -> Optional[pd.DataFrame]:
        """Load dataset and show preview"""

        dataset = self.DATASETS[dataset_key]
        file_path = self.raw_dir / dataset["filename"]

        if not file_path.exists():
            logger.error(f"Dataset not found: {file_path}")
            return None

        try:
            if dataset["format"] == "csv":
                df = pd.read_csv(file_path)
            else:
                logger.error(f"Unsupported format: {dataset['format']}")
                return None

            logger.info(f"\n{dataset['description']}")
            logger.info(f"  Shape: {df.shape}")
            logger.info(f"  Columns: {df.columns.tolist()[:5]}...")
            logger.info(f"  Sample:\n{df.head(2)}")

            return df

        except Exception as e:
            logger.error(f"Failed to load dataset: {e}")
            return None

    def create_training_data(self, sample_frac: float = 1.0) -> Path:
        """Create combined training dataset"""
        logger.info("\n" + "="*50)
        logger.info("CREATING TRAINING DATASET")
        logger.info("="*50)

        all_data = []

        # Try to load available datasets
        for key in self.DATASETS:
            file_path = self.raw_dir / self.DATASETS[key]["filename"]
            if file_path.exists():
                try:
                    df = pd.read_csv(file_path)

                    # Try to map to standard format
                    if 'text' not in df.columns:
                        # Try common column names
                        for col in ['message', 'email', 'content', 'body']:
                            if col in df.columns:
                                df['text'] = df[col]
                                break

                    if 'label' not in df.columns:
                        # Try common label columns
                        for col in ['spam', 'phishing', 'fraud', 'is_fraud']:
                            if col in df.columns:
                                df['label'] = df[col]
                                break

                    if 'text' in df.columns and 'label' in df.columns:
                        all_data.append(df[['text', 'label']])
                        logger.info(f"✓ Added {key}: {len(df)} samples")
                    else:
                        logger.warning(f"⚠ Skipped {key}: no text/label columns")

                except Exception as e:
                    logger.error(f"Failed to load {key}: {e}")

        if not all_data:
            logger.error("No datasets available - creating synthetic data")
            return self._create_synthetic_data()

        # Combine datasets
        combined = pd.concat(all_data, ignore_index=True)

        # Sample if needed
        if sample_frac < 1.0:
            combined = combined.sample(frac=sample_frac, random_state=42)

        # Save processed data
        save_path = self.processed_dir / "training_data.csv"
        combined.to_csv(save_path, index=False)

        logger.info(f"\n✓ Combined dataset saved: {save_path}")
        logger.info(f"  Total samples: {len(combined)}")
        logger.info(f"  Label distribution:\n{combined['label'].value_counts()}")

        return save_path

    def _create_synthetic_data(self) -> Path:
        """Create synthetic training data as fallback"""
        logger.warning("Creating synthetic training data")

        # Legitimate emails
        legitimate = [
            "Meeting scheduled for tomorrow at 10am",
            "Please find attached the quarterly report",
            "Your leave request has been approved",
            "Reminder: Team building event this Friday",
            "Project update: All milestones achieved",
            "Invoice #12345 for services rendered",
        ]

        # Phishing emails
        phishing = [
            "URGENT: Your account will be suspended. Click here to verify",
            "You won $1,000,000! Claim your prize now",
            "Verify your GCash account immediately",
            "Your password is expiring. Update here",
            "Unusual login detected. Confirm your identity",
            "Your Netflix subscription is expiring. Update payment",
        ]

        # Create dataset
        texts = legitimate + phishing
        labels = [0] * len(legitimate) + [1] * len(phishing)

        # Duplicate for more samples
        texts = texts * 50
        labels = labels * 50

        df = pd.DataFrame({'text': texts, 'label': labels})

        save_path = self.processed_dir / "synthetic_training_data.csv"
        df.to_csv(save_path, index=False)

        logger.info(f"✓ Synthetic dataset created: {len(df)} samples")
        return save_path


def main():
    """Main function to run dataset download"""
    downloader = DatasetDownloader()

    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description="Download datasets for Email Security Gateway")
    parser.add_argument("--dataset", help="Specific dataset to download", choices=list(downloader.DATASETS.keys()))
    parser.add_argument("--all", action="store_true", help="Download all datasets")
    parser.add_argument("--preview", help="Preview a dataset", choices=list(downloader.DATASETS.keys()))
    parser.add_argument("--train", action="store_true", help="Create training data")
    parser.add_argument("--sample", type=float, default=1.0, help="Sample fraction for training data")

    args = parser.parse_args()

    if args.dataset:
        downloader.download_dataset(args.dataset)
        if args.preview == args.dataset:
            downloader.load_and_preview(args.dataset)

    elif args.all:
        downloader.download_all()

    elif args.preview:
        downloader.load_and_preview(args.preview)

    elif args.train:
        downloader.create_training_data(args.sample)

    else:
        # Show help
        parser.print_help()
        print("\nExamples:")
        print("  python scripts/download_datasets.py --all")
        print("  python scripts/download_datasets.py --dataset combined_fraud")
        print("  python scripts/download_datasets.py --preview combined_fraud")
        print("  python scripts/download_datasets.py --train --sample 0.2")


if __name__ == "__main__":
    main()