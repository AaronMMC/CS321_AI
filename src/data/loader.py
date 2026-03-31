"""
Data loading utilities for training and inference.
"""

import pandas as pd
import numpy as np
import torch
from pathlib import Path
from typing import Tuple, Dict, Optional, List
from sklearn.model_selection import train_test_split
from torch.utils.data import Dataset, DataLoader as TorchDataLoader
from transformers import AutoTokenizer
from loguru import logger


class EmailDataset(Dataset):
    """PyTorch dataset for email classification."""

    def __init__(self, texts: List[str], labels: List[int], tokenizer, max_length: int = 512):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx):
        text = str(self.texts[idx])
        label = self.labels[idx]

        encoding = self.tokenizer(
            text,
            truncation=True,
            padding="max_length",
            max_length=self.max_length,
            return_tensors="pt",
        )

        return {
            "input_ids": encoding["input_ids"].flatten(),
            "attention_mask": encoding["attention_mask"].flatten(),
            "labels": torch.tensor(label, dtype=torch.long),
        }


class EmailDataLoader:
    """Load and prepare data for training."""

    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.processed_dir = self.data_dir / "processed"
        self.raw_dir = self.data_dir / "raw"

    def load_training_data(self, file_path: Optional[Path] = None) -> pd.DataFrame:
        """Load training data from CSV."""
        if file_path is None:
            processed_files = list(self.processed_dir.glob("*training*.csv"))
            if processed_files:
                file_path = processed_files[0]
            else:
                raw_files = list(self.raw_dir.glob("*.csv"))
                if raw_files:
                    file_path = raw_files[0]
                else:
                    raise FileNotFoundError("No training data found. Run scripts/download_datasets.py first.")

        logger.info(f"Loading data from {file_path}")
        df = pd.read_csv(file_path)
        df = df.dropna(subset=["text", "label"])

        logger.info(f"Loaded {len(df)} samples")
        logger.info(f"Label distribution:\n{df['label'].value_counts()}")
        return df

    def prepare_datasets(
        self,
        df: pd.DataFrame,
        text_column: str = "text",
        label_column: str = "label",
        test_size: float = 0.2,
        val_size: float = 0.1,
        random_state: int = 42,
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """Split data into train / validation / test sets."""
        train_val, test = train_test_split(
            df,
            test_size=test_size,
            random_state=random_state,
            stratify=df[label_column],
        )

        val_ratio = val_size / (1 - test_size)
        train, val = train_test_split(
            train_val,
            test_size=val_ratio,
            random_state=random_state,
            stratify=train_val[label_column],
        )

        logger.info(f"Train: {len(train)} | Val: {len(val)} | Test: {len(test)}")
        return train, val, test

    def create_torch_datasets(
        self,
        train_df: pd.DataFrame,
        val_df: pd.DataFrame,
        test_df: pd.DataFrame,
        tokenizer,
        max_length: int = 512,
        text_column: str = "text",
        label_column: str = "label",
    ) -> Tuple[EmailDataset, EmailDataset, EmailDataset]:
        """Create PyTorch datasets from DataFrame splits."""

        def _make(df: pd.DataFrame) -> EmailDataset:
            return EmailDataset(
                texts=df[text_column].tolist(),
                labels=df[label_column].tolist(),
                tokenizer=tokenizer,
                max_length=max_length,
            )

        return _make(train_df), _make(val_df), _make(test_df)

    def create_dataloaders(
        self,
        train_dataset: EmailDataset,
        val_dataset: EmailDataset,
        test_dataset: EmailDataset,
        batch_size: int = 16,
        num_workers: int = 0,
    ) -> Tuple[TorchDataLoader, TorchDataLoader, TorchDataLoader]:
        """Wrap datasets in DataLoaders."""
        train_loader = TorchDataLoader(
            train_dataset, batch_size=batch_size, shuffle=True, num_workers=num_workers
        )
        val_loader = TorchDataLoader(
            val_dataset, batch_size=batch_size, shuffle=False, num_workers=num_workers
        )
        test_loader = TorchDataLoader(
            test_dataset, batch_size=batch_size, shuffle=False, num_workers=num_workers
        )
        return train_loader, val_loader, test_loader