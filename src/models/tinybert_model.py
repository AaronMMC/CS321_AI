"""
TinyBERT implementation optimized for quick training and inference.
This is our lightweight model for rapid prototyping.
"""

import torch
import torch.nn as nn
from transformers import (
    BertConfig,
    BertForSequenceClassification,
    BertTokenizer,
    get_linear_schedule_with_warmup
)
# CORRECTED IMPORT: AdamW is in torch.optim, not directly from transformers
from torch.optim import AdamW
from pathlib import Path
from typing import Optional, Dict, List, Union
from loguru import logger
import pandas as pd
import numpy as np
from torch.utils.data import DataLoader, Dataset


class TinyBERTForEmailSecurity:
    """
    TinyBERT model specifically optimized for email security.
    Can be trained quickly on small datasets.
    """

    def __init__(
        self,
        model_name: str = "huawei-noah/TinyBERT_4L_312D",
        num_labels: int = 2,
        max_length: int = 256,
        use_gpu: bool = True
    ):
        self.model_name = model_name
        self.num_labels = num_labels
        self.max_length = max_length

        # Set device
        self.device = torch.device("cuda" if torch.cuda.is_available() and use_gpu else "cpu")

        # Load tokenizer
        self.tokenizer = BertTokenizer.from_pretrained(model_name)

        # Load model
        self.model = BertForSequenceClassification.from_pretrained(
            model_name,
            num_labels=num_labels
        ).to(self.device)

        logger.info(f"Initialized TinyBERT on {self.device}")
        logger.info(f"Model parameters: {sum(p.numel() for p in self.model.parameters()):,}")

    def tokenize(self, texts: List[str]) -> Dict[str, torch.Tensor]:
        """Tokenize texts for model input"""
        return self.tokenizer(
            texts,
            truncation=True,
            padding=True,
            max_length=self.max_length,
            return_tensors="pt"
        )

    def predict(self, text: Union[str, List[str]]) -> List[Dict]:
        """
        Predict threat scores for one or more texts.

        Args:
            text: Single email text or list of texts

        Returns:
            List of predictions with scores and labels
        """
        self.model.eval()

        # Handle single input
        if isinstance(text, str):
            texts = [text]
        else:
            texts = text

        # Tokenize
        inputs = self.tokenize(texts)
        inputs = {k: v.to(self.device) for k, v in inputs.items()}

        # Predict
        with torch.no_grad():
            outputs = self.model(**inputs)
            probabilities = torch.softmax(outputs.logits, dim=-1)

        # Format results
        results = []
        for probs in probabilities.cpu().numpy():
            threat_score = float(probs[1])  # Assuming class 1 is phishing

            # Determine label
            if threat_score >= 0.7:
                label = "PHISHING"
            elif threat_score >= 0.4:
                label = "SUSPICIOUS"
            else:
                label = "LEGITIMATE"

            results.append({
                'threat_score': threat_score,
                'label': label,
                'confidence': float(max(probs))
            })

        return results if len(results) > 1 else results[0]

    def train_quick(
        self,
        train_texts: List[str],
        train_labels: List[int],
        val_texts: Optional[List[str]] = None,
        val_labels: Optional[List[int]] = None,
        epochs: int = 3,
        batch_size: int = 16,
        learning_rate: float = 2e-5
    ) -> Dict:
        """
        Quick training for prototyping (2-3 hours on Colab GPU).

        Args:
            train_texts: List of email texts
            train_labels: List of labels (0=legit, 1=phishing)
            val_texts: Optional validation texts
            val_labels: Optional validation labels
            epochs: Number of training epochs
            batch_size: Batch size
            learning_rate: Learning rate

        Returns:
            Training history
        """
        logger.info(f"Starting quick training for {epochs} epochs")

        # Tokenize training data
        train_encodings = self.tokenizer(
            train_texts,
            truncation=True,
            padding=True,
            max_length=self.max_length,
            return_tensors="pt"
        )

        # Create dataset
        class EmailDataset(Dataset):
            def __init__(self, encodings, labels):
                self.encodings = encodings
                self.labels = labels

            def __getitem__(self, idx):
                item = {key: val[idx] for key, val in self.encodings.items()}
                item['labels'] = torch.tensor(self.labels[idx])
                return item

            def __len__(self):
                return len(self.labels)

        train_dataset = EmailDataset(train_encodings, train_labels)
        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)

        # Prepare validation if provided
        val_loader = None
        if val_texts and val_labels:
            val_encodings = self.tokenizer(
                val_texts,
                truncation=True,
                padding=True,
                max_length=self.max_length,
                return_tensors="pt"
            )
            val_dataset = EmailDataset(val_encodings, val_labels)
            val_loader = DataLoader(val_dataset, batch_size=batch_size)

        # CORRECTED: AdamW from torch.optim
        optimizer = AdamW(self.model.parameters(), lr=learning_rate)
        total_steps = len(train_loader) * epochs
        scheduler = get_linear_schedule_with_warmup(
            optimizer,
            num_warmup_steps=int(0.1 * total_steps),
            num_training_steps=total_steps
        )

        # Training loop
        history = {'train_loss': [], 'val_accuracy': []}

        for epoch in range(epochs):
            self.model.train()
            total_loss = 0

            for batch in train_loader:
                # Move batch to device
                batch = {k: v.to(self.device) for k, v in batch.items()}

                # Forward pass
                outputs = self.model(**batch)
                loss = outputs.loss

                # Backward pass
                loss.backward()
                optimizer.step()
                scheduler.step()
                optimizer.zero_grad()

                total_loss += loss.item()

            avg_loss = total_loss / len(train_loader)
            history['train_loss'].append(avg_loss)

            # Validation
            if val_loader:
                val_accuracy = self._evaluate(val_loader)
                history['val_accuracy'].append(val_accuracy)
                logger.info(f"Epoch {epoch+1}/{epochs} - Loss: {avg_loss:.4f} - Val Acc: {val_accuracy:.4f}")
            else:
                logger.info(f"Epoch {epoch+1}/{epochs} - Loss: {avg_loss:.4f}")

        logger.success("Training complete!")
        return history

    def _evaluate(self, val_loader: DataLoader) -> float:
        """Evaluate model on validation set"""
        self.model.eval()
        correct = 0
        total = 0

        with torch.no_grad():
            for batch in val_loader:
                batch = {k: v.to(self.device) for k, v in batch.items()}
                outputs = self.model(**batch)
                predictions = torch.argmax(outputs.logits, dim=-1)
                correct += (predictions == batch['labels']).sum().item()
                total += len(batch['labels'])

        return correct / total

    def save_model(self, path: str):
        """Save model and tokenizer"""
        save_path = Path(path)
        save_path.mkdir(parents=True, exist_ok=True)

        self.model.save_pretrained(save_path)
        self.tokenizer.save_pretrained(save_path)
        logger.info(f"Model saved to {save_path}")

    @classmethod
    def load_model(cls, path: str):
        """Load saved model"""
        instance = cls(model_name=path)
        logger.info(f"Model loaded from {path}")
        return instance


def create_mini_dataset_for_quick_training() -> tuple:
    """
    Create a small dataset for quick testing.
    This mimics real phishing patterns.
    """

    # Legitimate emails
    legitimate = [
        "Meeting agenda for tomorrow's project review",
        "Please find attached the quarterly financial report",
        "Your leave request has been approved for next week",
        "Reminder: Team building event this Friday",
        "Project update: All milestones achieved on time",
        "Invoice #12345 for services rendered",
        "Welcome to the team! Here's your onboarding schedule",
        "System maintenance scheduled for Sunday 2 AM",
        "Your password reset request has been processed",
        "Thank you for your application. We'll be in touch",
    ]

    # Phishing emails
    phishing = [
        "URGENT: Your account will be suspended in 24 hours. Click here to verify",
        "You have won $1,000,000! Claim your prize now by providing bank details",
        "GCash: Your account has been limited. Verify immediately",
        "Security Alert: Unusual login detected. Confirm your identity",
        "Your Netflix subscription is expiring. Update payment method",
        "DICT: Your email requires immediate verification. Click link",
        "PayPal: Transaction disputed. Sign in to review",
        "Apple ID: Your account has been locked. Unlock now",
        "Tax refund available. Submit form to receive payment",
        "HR Department: Update your payroll information immediately",
    ]

    # Create dataset with variations
    texts = []
    labels = []

    # Add legitimate emails with variations
    for i, email in enumerate(legitimate):
        texts.append(email)
        labels.append(0)
        # Add variation
        texts.append(email.replace("Meeting", "Conference"))
        labels.append(0)
        texts.append(email.upper())
        labels.append(0)

    # Add phishing emails with variations
    for i, email in enumerate(phishing):
        texts.append(email)
        labels.append(1)
        # Add variation
        texts.append(email.replace("URGENT", "IMPORTANT"))
        labels.append(1)
        texts.append(email.lower())
        labels.append(1)

    # Add mixed examples
    texts.append("Your package is delayed. Track here: http://bit.ly/track-package")
    labels.append(0)  # Could be legitimate tracking

    texts.append("Your package is delayed. Verify account: http://bit.ly/verify-account")
    labels.append(1)  # Phishing variant

    logger.info(f"Created mini dataset with {len(texts)} samples")
    return texts, labels