"""
Training pipeline for the phishing detection model.
Handles training loop, evaluation, and model saving.
"""

import torch
from torch.utils.data import DataLoader
# CORRECTED: AdamW from torch.optim, not transformers
from torch.optim import AdamW
from transformers import get_linear_schedule_with_warmup
from pathlib import Path
from typing import Optional, Dict, List, Tuple
from loguru import logger
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import json
from datetime import datetime


class ModelTrainer:
    """Handles model training and evaluation"""

    def __init__(
        self,
        model,
        tokenizer,
        device: Optional[torch.device] = None,
        output_dir: str = "models_saved"
    ):
        self.model = model
        self.tokenizer = tokenizer
        self.device = device or torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Move model to device
        self.model.to(self.device)

        logger.info(f"Trainer initialized on device: {self.device}")

    def train(
        self,
        train_dataloader: DataLoader,
        val_dataloader: Optional[DataLoader] = None,
        epochs: int = 3,
        learning_rate: float = 2e-5,
        warmup_steps: int = 0,
        gradient_accumulation_steps: int = 1,
        max_grad_norm: float = 1.0,
        save_best_model: bool = True,
        early_stopping_patience: Optional[int] = None
    ) -> Dict:
        """
        Train the model.

        Returns:
            Training history dictionary
        """
        # CORRECTED: AdamW from torch.optim
        optimizer = AdamW(self.model.parameters(), lr=learning_rate)

        total_steps = len(train_dataloader) * epochs
        scheduler = get_linear_schedule_with_warmup(
            optimizer,
            num_warmup_steps=warmup_steps,
            num_training_steps=total_steps
        )

        # Training tracking
        history = {
            'train_loss': [],
            'val_loss': [],
            'val_accuracy': [],
            'val_f1': [],
            'epochs': []
        }

        best_val_f1 = 0
        patience_counter = 0

        logger.info(f"Starting training for {epochs} epochs")

        for epoch in range(epochs):
            # Training phase
            self.model.train()
            total_train_loss = 0

            for step, batch in enumerate(train_dataloader):
                # Move batch to device
                batch = {k: v.to(self.device) for k, v in batch.items()}

                # Forward pass
                outputs = self.model(**batch)
                loss = outputs['loss']

                # Scale loss for gradient accumulation
                if gradient_accumulation_steps > 1:
                    loss = loss / gradient_accumulation_steps

                # Backward pass
                loss.backward()

                # Gradient clipping
                if max_grad_norm > 0:
                    torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_grad_norm)

                # Update weights (with gradient accumulation)
                if (step + 1) % gradient_accumulation_steps == 0:
                    optimizer.step()
                    scheduler.step()
                    optimizer.zero_grad()

                total_train_loss += loss.item() * (gradient_accumulation_steps if gradient_accumulation_steps > 1 else 1)

                # Log progress
                if step % 50 == 0:
                    logger.debug(f"Epoch {epoch+1}/{epochs} - Step {step}/{len(train_dataloader)} - Loss: {loss.item():.4f}")

            avg_train_loss = total_train_loss / len(train_dataloader)
            history['train_loss'].append(avg_train_loss)
            history['epochs'].append(epoch + 1)

            # Validation phase
            if val_dataloader:
                val_metrics = self.evaluate(val_dataloader)

                history['val_loss'].append(val_metrics['loss'])
                history['val_accuracy'].append(val_metrics['accuracy'])
                history['val_f1'].append(val_metrics['f1'])

                logger.info(
                    f"Epoch {epoch+1}/{epochs} - "
                    f"Train Loss: {avg_train_loss:.4f} - "
                    f"Val Loss: {val_metrics['loss']:.4f} - "
                    f"Val Acc: {val_metrics['accuracy']:.4f} - "
                    f"Val F1: {val_metrics['f1']:.4f}"
                )

                # Save best model
                if save_best_model and val_metrics['f1'] > best_val_f1:
                    best_val_f1 = val_metrics['f1']
                    self.save_model("best_model")
                    patience_counter = 0
                elif early_stopping_patience:
                    patience_counter += 1
                    if patience_counter >= early_stopping_patience:
                        logger.info(f"Early stopping triggered after {epoch+1} epochs")
                        break
            else:
                logger.info(f"Epoch {epoch+1}/{epochs} - Train Loss: {avg_train_loss:.4f}")

        # Save final model
        self.save_model("final_model")

        logger.success("Training completed!")
        return history

    def evaluate(self, dataloader: DataLoader) -> Dict:
        """
        Evaluate model on validation/test data.

        Returns:
            Dictionary of evaluation metrics
        """
        self.model.eval()

        total_loss = 0
        all_predictions = []
        all_labels = []

        with torch.no_grad():
            for batch in dataloader:
                # Move batch to device
                batch = {k: v.to(self.device) for k, v in batch.items()}

                # Forward pass
                outputs = self.model(**batch)

                # Get loss
                if 'loss' in outputs:
                    total_loss += outputs['loss'].item()

                # Get predictions
                predictions = torch.argmax(outputs['logits'], dim=-1)

                all_predictions.extend(predictions.cpu().numpy())
                all_labels.extend(batch['labels'].cpu().numpy())

        # Calculate metrics
        accuracy = accuracy_score(all_labels, all_predictions)
        precision = precision_score(all_labels, all_predictions, average='binary', zero_division=0)
        recall = recall_score(all_labels, all_predictions, average='binary', zero_division=0)
        f1 = f1_score(all_labels, all_predictions, average='binary', zero_division=0)
        conf_matrix = confusion_matrix(all_labels, all_predictions)

        avg_loss = total_loss / len(dataloader) if dataloader else 0

        return {
            'loss': avg_loss,
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'confusion_matrix': conf_matrix.tolist(),
            'predictions': all_predictions,
            'true_labels': all_labels
        }

    def save_model(self, model_name: str):
        """Save model, tokenizer, and metadata"""
        save_path = self.output_dir / model_name
        save_path.mkdir(parents=True, exist_ok=True)

        # Save model
        self.model.save_pretrained(save_path)

        # Save tokenizer
        self.tokenizer.save_pretrained(save_path)

        # Save metadata
        metadata = {
            'saved_at': datetime.now().isoformat(),
            'model_type': type(self.model).__name__,
            'device': str(self.device)
        }

        with open(save_path / "metadata.json", 'w') as f:
            json.dump(metadata, f, indent=2)

        logger.info(f"Model saved to {save_path}")

    def load_model(self, model_name: str):
        """Load saved model"""
        load_path = self.output_dir / model_name

        if not load_path.exists():
            logger.error(f"Model not found: {load_path}")
            return False

        # Load model
        self.model = self.model.from_pretrained(load_path)
        self.model.to(self.device)

        # Load tokenizer
        self.tokenizer = self.tokenizer.from_pretrained(load_path)

        logger.info(f"Model loaded from {load_path}")
        return True


class QuickTrainer:
    """
    Simplified trainer for rapid prototyping.
    Trains on small datasets in minutes/hours.
    """

    def __init__(self, model_name: str = "huawei-noah/TinyBERT_4L_312D"):
        from src.models.tinybert_model import TinyBERTForEmailSecurity

        self.model = TinyBERTForEmailSecurity(model_name=model_name)
        self.history = []

    def train_on_sample(
        self,
        texts: List[str],
        labels: List[int],
        val_split: float = 0.2,
        epochs: int = 3
    ) -> Dict:
        """
        Quick training on a small sample.
        Perfect for demonstrating the concept with limited time.
        """
        from sklearn.model_selection import train_test_split

        # Split data
        train_texts, val_texts, train_labels, val_labels = train_test_split(
            texts, labels, test_size=val_split, random_state=42, stratify=labels
        )

        logger.info(f"Quick training on {len(train_texts)} samples")

        # Train
        history = self.model.train_quick(
            train_texts=train_texts,
            train_labels=train_labels,
            val_texts=val_texts,
            val_labels=val_labels,
            epochs=epochs
        )

        self.history.append(history)

        return history

    def demo_prediction(self, test_emails: List[str]) -> List[Dict]:
        """Make predictions and display results for demo"""
        results = []

        for email in test_emails:
            pred = self.model.predict(email)
            results.append({
                'email': email[:50] + "..." if len(email) > 50 else email,
                'threat_score': pred['threat_score'],
                'label': pred['label'],
                'confidence': pred['confidence']
            })

        # Print demo table
        logger.info("Demo Predictions:")
        for r in results:
            indicator = "bad" if r['threat_score'] > 0.7 else "ok" if r['threat_score'] > 0.4 else "good"
            logger.info(f"{indicator} [{r['label']:10}] {r['threat_score']:.2%} - {r['email']}")

        return results