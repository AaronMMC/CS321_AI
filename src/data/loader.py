"""
Data loading utilities for training and inference.
"""

import pandas as pd
import numpy as np
from pathlib import Path
from typing import Tuple, Dict, Optional, List
from sklearn.model_selection import train_test_split
from torch.utils.data import Dataset, DataLoader
from transformers import AutoTokenizer
from loguru import logger


class EmailDataset(Dataset):
    """PyTorch dataset for email classification"""

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

        # Tokenize
        encoding = self.tokenizer(
            text,
            truncation=True,
            padding='max_length',
            max_length=self.max_length,
            return_tensors='pt'
        )

        return {
            'input_ids': encoding['input_ids'].flatten(),
            'attention_mask': encoding['attention_mask'].flatten(),
            'labels': torch.tensor(label, dtype=torch.long)
        }


class DataLoader:
    """Load and prepare data for training"""

    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.processed_dir = self.data_dir / "processed"
        self.raw_dir = self.data_dir / "raw"

    def load_training_data(self, file_path: Optional[Path] = None) -> pd.DataFrame:
        """Load training data from CSV"""

        if file_path is None:
            # Try to find processed data
            processed_files = list(self.processed_dir.glob("*training*.csv"))
            if processed_files:
                file_path = processed_files[0]
            else:
                # Fall back to raw data
                raw_files = list(self.raw_dir.glob("*.csv"))
                if raw_files:
                    file_path = raw_files[0]
                else:
                    raise FileNotFoundError("No training data found")

        logger.info(f"Loading data from {file_path}")
        df = pd.read_csv(file_path)

        # Basic cleaning
        df = df.dropna(subset=['text', 'label'])

        logger.info(f"Loaded {len(df)} samples")
        logger.info(f"Label distribution:\n{df['label'].value_counts()}")

        return df

    def prepare_datasets(
            self,
            df: pd.DataFrame,
            text_column: str = 'text',
            label_column: str = 'label',
            test_size: float = 0.2,
            val_size: float = 0.1,
            random_state: int = 42
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """
        Split data into train/validation/test sets
        """
        # First split: train+val vs test
        train_val, test = train_test_split(
            df,
            test_size=test_size,
            random_state=random_state,
            stratify=df[label_column]
        )

        # Second split: train vs val
        val_ratio = val_size / (1 - test_size)  # Adjust ratio
        train, val = train_test_split(
            train_val,
            test_size=val_ratio,
            random_state=random_state,
            stratify=train_val[label_column]
        )

        logger.info(f"Train: {len(train)} samples")
        logger.info(f"Validation: {len(val)} samples")
        logger.info(f"Test: {len(test)} samples")

        return train, val, test

    def create_torch_datasets(
            self,
            train_df: pd.DataFrame,
            val_df: pd.DataFrame,
            test_df: pd.DataFrame,
            tokenizer,
            max_length: int = 512,
            text_column: str = 'text',
            label_column: str = 'label'
    ) -> Tuple[EmailDataset, EmailDataset, EmailDataset]:
        """Create PyTorch datasets"""

        train_dataset = EmailDataset(
            texts=train_df[text_column].tolist(),
            labels=train_df[label_column].tolist(),
            tokenizer=tokenizer,
            max_length=max_length
        )

        val_dataset = EmailDataset(
            texts=val_df[text_column].tolist(),
            labels=val_df[label_column].tolist(),
            tokenizer=tokenizer,
            max_length=max_length
        )

        test_dataset = EmailDataset(
            texts=test_df[text_column].tolist(),
            labels=test_df[label_column].tolist(),
            tokenizer=tokenizer,
            max_length=max_length
        )

        return train_dataset, val_dataset, test_dataset


# Import torch at the end to avoid circular imports
import torch