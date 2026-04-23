"""
trainer.py — Full training loop for scratch Transformer models.

BUG FIX: Replaced `get_linear_schedule_with_warmup` from the `transformers`
package with `OneCycleLR` from pure PyTorch (`torch.optim.lr_scheduler`).
The transformers import was fragile (the package is listed in requirements
only for its scheduler utility) and unnecessary since PyTorch ships an
equivalent scheduler natively.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import torch
import torch.nn as nn
from torch.optim import AdamW
from torch.optim.lr_scheduler import OneCycleLR          # pure PyTorch – no transformers needed
from torch.utils.data import DataLoader
from loguru import logger
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix,
)

from src.models.scratch_transformer import SimpleTokenizer


class ModelTrainer:
    """
    Generic trainer that works with any model whose forward() returns
    a dict containing at least 'loss' and 'logits'.

    Designed for ScratchTransformerClassifier / ScratchBERTClassifier.
    """

    def __init__(
        self,
        model:       nn.Module,
        tokenizer:   SimpleTokenizer,
        device:      Optional[torch.device] = None,
        output_dir:  str = "models_saved",
    ):
        self.model     = model
        self.tokenizer = tokenizer
        self.device    = device or torch.device(
            "cuda" if torch.cuda.is_available() else "cpu"
        )
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.model.to(self.device)
        logger.info(f"Trainer initialised on {self.device}")

    def train(
        self,
        train_dataloader:            DataLoader,
        val_dataloader:              Optional[DataLoader] = None,
        epochs:                      int   = 5,
        learning_rate:               float = 3e-4,
        warmup_ratio:                float = 0.1,          # fraction of total steps for warmup
        gradient_accumulation_steps: int   = 1,
        max_grad_norm:               float = 1.0,
        save_best_model:             bool  = True,
        early_stopping_patience:     Optional[int] = 3,
    ) -> Dict:

        total_steps  = len(train_dataloader) * epochs
        optimizer    = AdamW(self.model.parameters(), lr=learning_rate, weight_decay=1e-2)

        # BUG FIX: was `get_linear_schedule_with_warmup` from transformers.
        # OneCycleLR from PyTorch provides warm-up + cosine annealing with zero
        # external dependencies.
        scheduler = OneCycleLR(
            optimizer,
            max_lr=learning_rate,
            total_steps=total_steps,
            pct_start=warmup_ratio,      # fraction used for warm-up phase
            anneal_strategy="cos",
        )

        history = {
            "train_loss": [], "val_loss": [],
            "val_accuracy": [], "val_f1": [], "epochs": [],
        }

        best_val_f1      = 0.0
        patience_counter = 0

        logger.info(f"Training for {epochs} epochs — all weights random, training from scratch")

        for epoch in range(epochs):
            self.model.train()
            total_loss = 0.0

            for step, batch in enumerate(train_dataloader):
                batch = {k: v.to(self.device) for k, v in batch.items()}
                out   = self.model(**batch)
                loss  = out["loss"]

                if gradient_accumulation_steps > 1:
                    loss = loss / gradient_accumulation_steps

                loss.backward()
                nn.utils.clip_grad_norm_(self.model.parameters(), max_grad_norm)

                if (step + 1) % gradient_accumulation_steps == 0:
                    optimizer.step()
                    scheduler.step()
                    optimizer.zero_grad()

                total_loss += loss.item() * gradient_accumulation_steps

                if step % 50 == 0:
                    logger.debug(
                        f"Epoch {epoch+1}/{epochs}  step {step}/{len(train_dataloader)}  "
                        f"loss={loss.item():.4f}"
                    )

            avg_loss = total_loss / len(train_dataloader)
            history["train_loss"].append(avg_loss)
            history["epochs"].append(epoch + 1)

            if val_dataloader:
                metrics = self.evaluate(val_dataloader)
                history["val_loss"].append(metrics["loss"])
                history["val_accuracy"].append(metrics["accuracy"])
                history["val_f1"].append(metrics["f1"])

                logger.info(
                    f"Epoch {epoch+1}/{epochs}  "
                    f"train_loss={avg_loss:.4f}  "
                    f"val_loss={metrics['loss']:.4f}  "
                    f"val_acc={metrics['accuracy']:.4f}  "
                    f"val_f1={metrics['f1']:.4f}"
                )

                if save_best_model and metrics["f1"] > best_val_f1:
                    best_val_f1 = metrics["f1"]
                    self._save_checkpoint("best_model")
                    patience_counter = 0
                elif early_stopping_patience:
                    patience_counter += 1
                    if patience_counter >= early_stopping_patience:
                        logger.info(f"Early stopping at epoch {epoch+1}")
                        break
            else:
                logger.info(f"Epoch {epoch+1}/{epochs}  train_loss={avg_loss:.4f}")

        self._save_checkpoint("final_model")
        logger.success("Training complete.")
        return history

    def evaluate(self, dataloader: DataLoader) -> Dict:
        self.model.eval()
        total_loss = 0.0
        all_preds  = []
        all_labels = []

        with torch.no_grad():
            for batch in dataloader:
                batch = {k: v.to(self.device) for k, v in batch.items()}
                out   = self.model(**batch)
                if "loss" in out:
                    total_loss += out["loss"].item()
                preds = out["logits"].argmax(dim=-1).cpu().numpy()
                all_preds.extend(preds)
                all_labels.extend(batch["labels"].cpu().numpy())

        return {
            "loss":             total_loss / max(len(dataloader), 1),
            "accuracy":         accuracy_score(all_labels, all_preds),
            "precision":        precision_score(all_labels, all_preds, average="binary", zero_division=0),
            "recall":           recall_score(all_labels, all_preds, average="binary", zero_division=0),
            "f1":               f1_score(all_labels, all_preds, average="binary", zero_division=0),
            "confusion_matrix": confusion_matrix(all_labels, all_preds).tolist(),
            "predictions":      all_preds,
            "true_labels":      all_labels,
        }

    def _save_checkpoint(self, name: str):
        save_path = self.output_dir / name
        save_path.mkdir(parents=True, exist_ok=True)

        torch.save(self.model.state_dict(), save_path / "model_weights.pt")
        self.tokenizer.save(str(save_path / "tokenizer.json"))

        meta = {
            "saved_at":   datetime.now().isoformat(),
            "model_type": type(self.model).__name__,
            "device":     str(self.device),
            "pretrained": False,
        }
        with open(save_path / "metadata.json", "w") as f:
            json.dump(meta, f, indent=2)

        logger.info(f"Checkpoint saved → {save_path}")


class QuickTrainer:
    """
    Convenience wrapper — one-call training for rapid prototyping.
    """

    def __init__(self):
        from src.models.scratch_transformer import ScratchModelForEmailSecurity
        self.model = ScratchModelForEmailSecurity()

    def train_on_sample(
        self,
        texts:      List[str],
        labels:     List[int],
        val_split:  float = 0.2,
        epochs:     int   = 5,
    ) -> Dict:
        from sklearn.model_selection import train_test_split

        train_texts, val_texts, train_labels, val_labels = train_test_split(
            texts, labels, test_size=val_split, random_state=42, stratify=labels
        )

        self.model.build_tokenizer(train_texts)

        return self.model.train_quick(
            train_texts, train_labels,
            val_texts,   val_labels,
            epochs=epochs,
        )

    def demo_prediction(self, test_emails: List[str]) -> List[Dict]:
        results = []
        for email in test_emails:
            pred = self.model.predict(email)
            results.append({
                "email":        email[:50] + ("..." if len(email) > 50 else ""),
                "threat_score": pred["threat_score"],
                "label":        pred["label"],
                "confidence":   pred["confidence"],
            })
            indicator = (
                "PHISHING"  if pred["threat_score"] > 0.7 else
                "SUSPICIOUS" if pred["threat_score"] > 0.4 else
                "LEGIT"
            )
            logger.info(
                f"[{indicator}] {pred['threat_score']:.2%}  {results[-1]['email']}"
            )
        return results