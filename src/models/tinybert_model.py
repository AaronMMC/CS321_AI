"""
Email Security Model with dual backends.

Default behavior remains a lightweight heuristic detector for fast startup and
reliable offline operation. When provided a valid transformer artifact path,
the same API can load and use a real trainable transformer backend.
"""

import os
import re
import json
from pathlib import Path
from typing import Dict, List, Union, Optional, Any
from loguru import logger

try:
    import torch
except ImportError:  # pragma: no cover - fallback for minimal environments
    torch = None


DEFAULT_HEURISTIC_MODEL_NAME = "heuristic-email-security"
DEFAULT_TRAINING_BASE_MODEL = "distilbert-base-uncased"


class _SimpleTokenizer:
    """Minimal tokenizer compatible with current tests and data loaders."""

    def __init__(self, max_length: int = 256, vocab_size: int = 30000):
        self.max_length = max_length
        self.vocab_size = vocab_size

    def _token_to_id(self, token: str) -> int:
        # Keep 0 for padding and map all tokens to a stable pseudo-vocab id.
        return (abs(hash(token)) % (self.vocab_size - 1)) + 1

    def encode(self, text: str, max_length: Optional[int] = None) -> List[int]:
        length = max_length or self.max_length
        tokens = re.findall(r"\w+", text.lower())
        token_ids = [self._token_to_id(t) for t in tokens[:length]]

        if len(token_ids) < length:
            token_ids.extend([0] * (length - len(token_ids)))

        return token_ids

    def __call__(
        self,
        texts: Union[str, List[str]],
        truncation: bool = True,
        padding: str = 'max_length',
        max_length: Optional[int] = None,
        return_tensors: str = 'pt',
    ) -> Dict[str, Union['torch.Tensor', List[List[int]]]]:
        if isinstance(texts, str):
            texts = [texts]

        length = max_length or self.max_length
        input_ids = [self.encode(t, max_length=length) for t in texts]
        attention_mask = [[1 if token_id != 0 else 0 for token_id in row] for row in input_ids]

        if return_tensors == 'pt' and torch is not None:
            return {
                'input_ids': torch.tensor(input_ids, dtype=torch.long),
                'attention_mask': torch.tensor(attention_mask, dtype=torch.long),
            }

        return {
            'input_ids': input_ids,
            'attention_mask': attention_mask,
        }


class _HeuristicModelStub:
    """Placeholder model object for compatibility with legacy callers/tests."""

    def __init__(self, name: str):
        self.name = name


class TinyBERTForEmailSecurity:
    """
        Email threat detection model with heuristic and transformer backends.

        Backend selection:
        - Heuristic backend (default): no downloads, deterministic fast scoring.
        - Transformer backend: loaded from local artifact path when available,
            or explicitly requested for training.
    """
    
    def __init__(
        self,
        model_name: str = DEFAULT_HEURISTIC_MODEL_NAME,
        max_length: int = 256,
        vocab_size: int = 30000,
        use_gpu: bool = False,
        model_path: Optional[Union[str, Path]] = None,
        force_transformer: bool = False,
        **_: Dict,
    ):
        """Initialize the threat detection model."""
        self.model_name = model_name
        self.max_length = max_length
        self.vocab_size = vocab_size
        self.device = "cpu"
        self.model_loaded = True
        self.backend = "heuristic"
        self.tokenizer = _SimpleTokenizer(max_length=max_length, vocab_size=vocab_size)
        self.model = _HeuristicModelStub(model_name)

        resolved_path = self._resolve_local_model_path(model_path)
        if resolved_path and (resolved_path / "config.json").exists():
            if self._try_load_transformer(str(resolved_path), use_gpu=use_gpu):
                return

        if force_transformer:
            source = model_name if model_name != DEFAULT_HEURISTIC_MODEL_NAME else DEFAULT_TRAINING_BASE_MODEL
            if self._try_load_transformer(source, use_gpu=use_gpu):
                return
            logger.warning("Requested transformer backend but initialization failed; using heuristic backend")

        self._initialize_heuristic_backend(model_name)

    def _initialize_heuristic_backend(self, model_name: str):
        """Initialize the lightweight heuristic backend."""
        self.model_name = model_name
        self.backend = "heuristic"
        self.device = "cpu"
        self.tokenizer = _SimpleTokenizer(max_length=self.max_length, vocab_size=self.vocab_size)
        self.model = _HeuristicModelStub(model_name)
        logger.info("Initialized heuristic-based threat detection model")

    def _resolve_local_model_path(self, model_path: Optional[Union[str, Path]]) -> Optional[Path]:
        """Resolve a local model directory candidate from args or environment."""
        candidates: List[Path] = []

        if model_path:
            candidates.append(Path(model_path))

        env_path = os.getenv("TINYBERT_MODEL_PATH", "").strip()
        if env_path:
            candidates.append(Path(env_path))

        model_name_path = Path(self.model_name)
        if model_name_path.exists():
            candidates.append(model_name_path)

        for candidate in candidates:
            if candidate.exists() and candidate.is_dir():
                return candidate

        return None

    def _try_load_transformer(self, model_ref: str, use_gpu: bool) -> bool:
        """Attempt to load a transformer model/tokenizer for real training/inference."""
        if torch is None:
            logger.warning("PyTorch unavailable; cannot initialize transformer backend")
            return False

        try:
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except Exception as e:
            logger.warning(f"Transformers unavailable; cannot initialize transformer backend: {e}")
            return False

        is_local_ref = Path(model_ref).exists()

        try:
            tokenizer = AutoTokenizer.from_pretrained(
                model_ref,
                local_files_only=is_local_ref,
                use_fast=False,
            )
            model = AutoModelForSequenceClassification.from_pretrained(
                model_ref,
                local_files_only=is_local_ref,
            )

            device = "cuda" if use_gpu and torch.cuda.is_available() else "cpu"
            model.to(device)
            model.eval()

            self.backend = "transformer"
            self.model_name = str(model_ref)
            self.device = device
            self.tokenizer = tokenizer
            self.model = model
            self.model_loaded = True
            logger.info(f"Initialized transformer model backend from {model_ref} on {device}")
            return True
        except Exception as e:
            logger.warning(f"Failed to initialize transformer backend from {model_ref}: {e}")
            return False

    def to(self, device):
        """Compatibility shim for trainer-style APIs."""
        self.device = str(device)
        if self.backend == "transformer" and hasattr(self.model, "to"):
            self.model.to(self.device)
        return self

    def tokenize(self, texts: Union[str, List[str]], max_length: Optional[int] = None):
        """Compatibility wrapper for tests expecting tokenize()."""
        if self.backend == "transformer":
            return self.tokenizer(
                texts,
                truncation=True,
                padding='max_length',
                max_length=max_length or self.max_length,
                return_tensors='pt',
            )

        return self.tokenizer(
            texts,
            truncation=True,
            padding='max_length',
            max_length=max_length or self.max_length,
            return_tensors='pt',
        )

    def predict(self, text: Union[str, List[str]]) -> Union[Dict, List[Dict]]:
        """
        Predict threat scores for one or more texts.
        
        Args:
            text: Single email text or list of texts
            
        Returns:
            Dictionary or list of dictionaries with predictions
        """
        is_single = isinstance(text, str)
        texts = [text] if is_single else text

        if self.backend == "transformer":
            predictions = self._transformer_predict(texts)
            return predictions[0] if is_single else predictions

        predictions = [self._heuristic_predict(t) for t in texts]
        return predictions[0] if is_single else predictions

    def _transformer_predict(self, texts: List[str]) -> List[Dict]:
        """Predict with transformer backend and map to gateway-compatible response."""
        if torch is None:
            return [self._heuristic_predict(t) for t in texts]

        encoded = self.tokenizer(
            texts,
            truncation=True,
            padding=True,
            max_length=self.max_length,
            return_tensors='pt',
        )

        encoded = {k: v.to(self.device) for k, v in encoded.items()}

        with torch.no_grad():
            outputs = self.model(**encoded)
            logits = outputs.logits

            if logits.shape[-1] == 1:
                scores = torch.sigmoid(logits.squeeze(-1))
            else:
                probs = torch.softmax(logits, dim=-1)
                positive_index = 1 if probs.shape[-1] > 1 else 0
                scores = probs[:, positive_index]

        return [self._format_prediction(float(score)) for score in scores.detach().cpu().tolist()]

    def _format_prediction(self, threat_score: float) -> Dict[str, Any]:
        """Map a threat score to consistent labels and confidence metadata."""
        threat_score = max(0.0, min(1.0, float(threat_score)))

        if threat_score >= 0.7:
            label = "PHISHING"
        elif threat_score >= 0.4:
            label = "SUSPICIOUS"
        else:
            label = "LEGITIMATE"

        confidence = 0.5 + abs(threat_score - 0.5)

        return {
            'threat_score': threat_score,
            'label': label,
            'confidence': float(min(1.0, max(0.0, confidence))),
        }

    def _heuristic_predict(self, text: str) -> Dict:
        """
        Heuristic-based prediction for email threat detection.
        
        Analyzes text for common phishing patterns and assigns a threat score.
        """
        text_lower = text.lower()
        threat_score = 0.0
        
        # High-risk phishing keywords (strong indicators)
        high_risk_keywords = [
            'urgent', 'immediately', 'suspended', 'account limited', 
            'verify now', 'click here', 'confirm identity', 'unauthorized',
            'locked', 'compromised', 'breach', 'terminate', 'closed'
        ]
        
        # Medium-risk keywords
        medium_risk_keywords = [
            'verify', 'update', 'confirm', 'suspended', 'limited',
            'winner', 'prize', 'claim', 'gift', 'free', 'bonus',
            'discount', 'offer', 'expire', 'deadline', 'action required'
        ]
        
        # Check for high-risk keywords
        for keyword in high_risk_keywords:
            if keyword in text_lower:
                threat_score += 0.20
        
        # Check for medium-risk keywords
        for keyword in medium_risk_keywords:
            if keyword in text_lower:
                threat_score += 0.10
        
        # Check for suspicious URLs/domains
        suspicious_domains = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'is.gd']
        for domain in suspicious_domains:
            if domain in text_lower:
                threat_score += 0.15
        
        # Check for suspicious TLDs often used in phishing
        if re.search(r'https?://[^\s]+\.(xyz|tk|ml|ga|cf|gq|top|work|click)', text_lower):
            threat_score += 0.25
        
        # Check for financial keywords
        financial_keywords = ['bank', 'gcash', 'paypal', 'netflix', 'credit card', 
                           'banking', 'wallet', 'invoice', 'payment', 'billing',
                           'payroll', 'salary', 'refund', 'tax']
        for keyword in financial_keywords:
            if keyword in text_lower:
                threat_score += 0.08
        
        # Check for threat/urgency patterns
        urgency_patterns = [
            r'24\s*hours?',
            r'48\s*hours?',
            r'immediate',
            r'within\s*\d+\s*hours?',
            r'last\s*chance',
            r'don\'t\s*miss',
            r'only\s*\d+\s*left'
        ]
        
        for pattern in urgency_patterns:
            if re.search(pattern, text_lower):
                threat_score += 0.12
        
        # Cap the threat score at 1.0
        threat_score = min(1.0, threat_score)
        
        return self._format_prediction(threat_score)

    def _train_heuristic_quick(
        self,
        train_texts: Optional[List[str]] = None,
        train_labels: Optional[List[int]] = None,
        val_texts: Optional[List[str]] = None,
        val_labels: Optional[List[int]] = None,
        epochs: int = 3,
    ) -> Dict[str, List[float]]:
        """Compatibility pseudo-training for heuristic backend."""
        train_texts = train_texts or []
        train_labels = train_labels or []
        val_texts = val_texts or []
        val_labels = val_labels or []

        history = {
            'train_loss': [],
            'val_accuracy': [],
        }

        if not train_texts or not train_labels:
            logger.warning("No training data provided to train_quick; returning empty-like history")
            history['train_loss'] = [0.0 for _ in range(max(1, epochs))]
            history['val_accuracy'] = [0.0 for _ in range(max(1, epochs))]
            return history

        for _epoch in range(max(1, epochs)):
            losses = []
            for text, label in zip(train_texts, train_labels):
                pred = self._heuristic_predict(text)['threat_score']
                target = 1.0 if int(label) == 1 else 0.0
                losses.append((pred - target) ** 2)

            avg_loss = float(sum(losses) / len(losses)) if losses else 0.0
            history['train_loss'].append(round(avg_loss, 4))

            eval_texts = val_texts if val_texts else train_texts
            eval_labels = val_labels if val_labels else train_labels
            correct = 0
            for text, label in zip(eval_texts, eval_labels):
                score = self._heuristic_predict(text)['threat_score']
                pred_label = 1 if score >= 0.5 else 0
                if pred_label == int(label):
                    correct += 1

            accuracy = float(correct / len(eval_labels)) if eval_labels else 0.0
            history['val_accuracy'].append(round(accuracy, 4))

        logger.info("Heuristic train_quick completed")
        return history

    def _evaluate_accuracy(self, texts: List[str], labels: List[int]) -> float:
        """Compute accuracy for the current backend using threshold 0.5."""
        if not texts or not labels:
            return 0.0

        predictions = self.predict(texts)
        if isinstance(predictions, dict):
            predictions = [predictions]

        pred_labels = [1 if p.get('threat_score', 0.0) >= 0.5 else 0 for p in predictions]
        labels_int = [int(v) for v in labels[:len(pred_labels)]]

        if not labels_int:
            return 0.0

        correct = sum(int(p == y) for p, y in zip(pred_labels, labels_int))
        return float(correct / len(labels_int))

    def _train_transformer_quick(
        self,
        train_texts: Optional[List[str]] = None,
        train_labels: Optional[List[int]] = None,
        val_texts: Optional[List[str]] = None,
        val_labels: Optional[List[int]] = None,
        epochs: int = 3,
        batch_size: int = 16,
        learning_rate: float = 3e-5,
        save_path: Optional[Union[str, Path]] = None,
    ) -> Dict[str, List[float]]:
        """Real quick fine-tuning loop for transformer backend."""
        train_texts = train_texts or []
        train_labels = train_labels or []
        val_texts = val_texts or []
        val_labels = val_labels or []

        if not train_texts or not train_labels:
            logger.warning("No training data provided for transformer training")
            return {
                'train_loss': [0.0 for _ in range(max(1, epochs))],
                'val_accuracy': [0.0 for _ in range(max(1, epochs))],
            }

        if torch is None:
            logger.warning("PyTorch unavailable; using heuristic compatibility training")
            return self._train_heuristic_quick(
                train_texts=train_texts,
                train_labels=train_labels,
                val_texts=val_texts,
                val_labels=val_labels,
                epochs=epochs,
            )

        if self.backend != "transformer":
            source = self.model_name if self.model_name != DEFAULT_HEURISTIC_MODEL_NAME else DEFAULT_TRAINING_BASE_MODEL
            if not self._try_load_transformer(source, use_gpu=False):
                logger.warning("Transformer backend unavailable; using heuristic compatibility training")
                return self._train_heuristic_quick(
                    train_texts=train_texts,
                    train_labels=train_labels,
                    val_texts=val_texts,
                    val_labels=val_labels,
                    epochs=epochs,
                )

        from torch.optim import AdamW
        from torch.utils.data import DataLoader, TensorDataset

        encoded_train = self.tokenizer(
            train_texts,
            truncation=True,
            padding='max_length',
            max_length=self.max_length,
            return_tensors='pt',
        )

        labels_tensor = torch.tensor([int(v) for v in train_labels], dtype=torch.long)
        train_dataset = TensorDataset(
            encoded_train['input_ids'],
            encoded_train['attention_mask'],
            labels_tensor,
        )
        train_loader = DataLoader(train_dataset, batch_size=max(1, batch_size), shuffle=True)

        optimizer = AdamW(self.model.parameters(), lr=learning_rate)

        history = {
            'train_loss': [],
            'val_accuracy': [],
        }

        self.model.train()
        for _epoch in range(max(1, epochs)):
            total_loss = 0.0

            for batch in train_loader:
                input_ids, attention_mask, labels = [t.to(self.device) for t in batch]

                optimizer.zero_grad()
                outputs = self.model(
                    input_ids=input_ids,
                    attention_mask=attention_mask,
                    labels=labels,
                )
                loss = outputs.loss
                loss.backward()
                optimizer.step()

                total_loss += float(loss.item())

            avg_loss = total_loss / max(1, len(train_loader))
            history['train_loss'].append(round(avg_loss, 4))

            eval_texts = val_texts if val_texts else train_texts
            eval_labels = val_labels if val_labels else train_labels
            accuracy = self._evaluate_accuracy(eval_texts, eval_labels)
            history['val_accuracy'].append(round(accuracy, 4))

        self.model.eval()

        if save_path:
            self.save_pretrained(save_path)

        logger.info("Transformer train_quick completed")
        return history

    def train_quick(
        self,
        train_texts: Optional[List[str]] = None,
        train_labels: Optional[List[int]] = None,
        val_texts: Optional[List[str]] = None,
        val_labels: Optional[List[int]] = None,
        epochs: int = 3,
        batch_size: int = 16,
        learning_rate: float = 3e-4,
        real_training: bool = False,
        save_path: Optional[Union[str, Path]] = None,
        **kwargs,
    ):
        """
        Quick training API.

        - Default: heuristic compatibility training (fast, no downloads)
        - real_training=True: try real transformer fine-tuning
        """
        if real_training or self.backend == "transformer":
            return self._train_transformer_quick(
                train_texts=train_texts,
                train_labels=train_labels,
                val_texts=val_texts,
                val_labels=val_labels,
                epochs=epochs,
                batch_size=batch_size,
                learning_rate=learning_rate,
                save_path=save_path,
            )

        return self._train_heuristic_quick(
            train_texts=train_texts,
            train_labels=train_labels,
            val_texts=val_texts,
            val_labels=val_labels,
            epochs=epochs,
        )
    
    def save_model(self, path: str):
        """Persist model artifacts/metadata for compatibility."""
        save_dir = Path(path)
        save_dir.mkdir(parents=True, exist_ok=True)

        metadata = {
            'model_type': self.backend,
            'model_name': self.model_name,
            'max_length': self.max_length,
            'vocab_size': self.vocab_size,
            'device': self.device,
        }

        if self.backend == "transformer" and hasattr(self.model, "save_pretrained"):
            self.model.save_pretrained(save_dir)
            if hasattr(self.tokenizer, "save_pretrained"):
                self.tokenizer.save_pretrained(save_dir)
            logger.info(f"Transformer model artifacts saved to {save_dir}")
        else:
            with open(save_dir / 'heuristic_model.json', 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2)
            logger.info(f"Heuristic model metadata saved to {save_dir}")

        with open(save_dir / 'model_metadata.json', 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2)

    def save_pretrained(self, path: Union[str, Path]):
        """HuggingFace-like compatibility API."""
        self.save_model(str(path))

    @classmethod
    def load_model(cls, path: str):
        """Load model artifacts from a path when available."""
        model_path = Path(path)
        if (model_path / 'config.json').exists():
            return cls(model_path=model_path, use_gpu=False)

        metadata_file = model_path / 'heuristic_model.json'

        if metadata_file.exists():
            try:
                with open(metadata_file, 'r', encoding='utf-8') as f:
                    metadata = json.load(f)
                return cls(
                    model_name=metadata.get('model_name', DEFAULT_HEURISTIC_MODEL_NAME),
                    max_length=metadata.get('max_length', 256),
                    vocab_size=metadata.get('vocab_size', 30000),
                    use_gpu=False,
                )
            except Exception as e:
                logger.warning(f"Failed to load heuristic metadata from {metadata_file}: {e}")

        return cls()

    @classmethod
    def from_pretrained(cls, path: Union[str, Path]):
        """HuggingFace-like compatibility API."""
        return cls.load_model(str(path))


def create_mini_dataset_for_quick_training():
    """
    Create a small dataset for testing.
    Returns (texts, labels) where 0=legit, 1=phishing
    """
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
    
    phishing = [
        "URGENT: Your account will be suspended in 24 hours. Click here to verify",
        "You have won $1,000,000! Claim your prize now by providing bank details",
        "GCash: Your account has been limited. Verify immediately",
        "Security Alert: Unusual login detected. Confirm your identity",
        "Your Netflix subscription is expiring. Update payment method",
        "DICT: Your email requires immediate verification. Click link",
        "Paypal: Transaction disputed. Sign in to review",
        "Apple ID: Your account has been locked. Unlock now",
        "Tax refund available. Submit form to receive payment",
        "HR Department: Update your payroll information immediately",
    ]
    
    texts = []
    labels = []
    
    for email in legitimate:
        texts.append(email)
        labels.append(0)
    
    for email in phishing:
        texts.append(email)
        labels.append(1)
    
    return texts, labels
