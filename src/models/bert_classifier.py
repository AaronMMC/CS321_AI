"""
BERT-based classifier for phishing email detection.
This is the main model that combines NLP with external intelligence.
"""
from pathlib import Path

import torch
import torch.nn as nn
from transformers import AutoModel, AutoTokenizer, AutoConfig
from typing import Dict, Optional, Tuple, List
from dataclasses import dataclass
from loguru import logger
import numpy as np


@dataclass
class ModelOutput:
    """Structured output from the model"""
    threat_score: float
    risk_level: str
    confidence: float
    explanations: List[str]
    features_used: Dict[str, float]


class BERTPhishingClassifier(nn.Module):
    """
    BERT-based model with custom classification head for phishing detection.
    Combines text analysis with external feature scores.
    """

    def __init__(
            self,
            model_name: str = "bert-base-uncased",
            num_labels: int = 2,
            dropout: float = 0.3,
            use_external_features: bool = True
    ):
        super().__init__()

        self.model_name = model_name
        self.num_labels = num_labels
        self.use_external_features = use_external_features

        # Load BERT configuration
        self.config = AutoConfig.from_pretrained(
            model_name,
            num_labels=num_labels,
            hidden_dropout_prob=dropout,
            attention_probs_dropout_prob=dropout
        )

        # Load BERT model
        self.bert = AutoModel.from_pretrained(model_name, config=self.config)

        # Custom classification head
        hidden_size = self.config.hidden_size

        if use_external_features:
            # If using external features, we need to combine them
            # External features: URL reputation, domain age, etc. (4 features)
            self.feature_projection = nn.Linear(4, hidden_size // 4)
            combined_size = hidden_size + (hidden_size // 4)

            self.classifier = nn.Sequential(
                nn.Linear(combined_size, hidden_size // 2),
                nn.ReLU(),
                nn.Dropout(dropout),
                nn.Linear(hidden_size // 2, hidden_size // 4),
                nn.ReLU(),
                nn.Dropout(dropout),
                nn.Linear(hidden_size // 4, num_labels)
            )
        else:
            # Simpler head without external features
            self.classifier = nn.Sequential(
                nn.Linear(hidden_size, hidden_size // 2),
                nn.ReLU(),
                nn.Dropout(dropout),
                nn.Linear(hidden_size // 2, hidden_size // 4),
                nn.ReLU(),
                nn.Dropout(dropout),
                nn.Linear(hidden_size // 4, num_labels)
            )

        # Loss function
        self.loss_fn = nn.CrossEntropyLoss()

        # Move to GPU if available
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.to(self.device)

        logger.info(f"Initialized BERTPhishingClassifier on {self.device}")
        logger.info(f"Model: {model_name}")
        logger.info(f"External features: {use_external_features}")

    def forward(
            self,
            input_ids: torch.Tensor,
            attention_mask: torch.Tensor,
            external_features: Optional[torch.Tensor] = None,
            labels: Optional[torch.Tensor] = None
    ) -> Dict[str, torch.Tensor]:
        """
        Forward pass through the model.

        Args:
            input_ids: Tokenized input IDs
            attention_mask: Attention mask
            external_features: Optional tensor of external features
            labels: Optional ground truth labels for training

        Returns:
            Dictionary containing logits, loss (if labels provided), and probabilities
        """
        # Get BERT embeddings
        outputs = self.bert(
            input_ids=input_ids,
            attention_mask=attention_mask
        )

        # Use [CLS] token representation
        pooled_output = outputs.last_hidden_state[:, 0, :]  # Shape: (batch_size, hidden_size)

        # Combine with external features if available
        if self.use_external_features and external_features is not None:
            # Project external features
            projected_features = self.feature_projection(external_features)

            # Concatenate with BERT output
            combined = torch.cat([pooled_output, projected_features], dim=1)
        else:
            combined = pooled_output

        # Classify
        logits = self.classifier(combined)

        # Calculate probabilities
        probabilities = torch.softmax(logits, dim=-1)

        output = {
            'logits': logits,
            'probabilities': probabilities,
        }

        # Calculate loss if labels provided
        if labels is not None:
            loss = self.loss_fn(logits, labels)
            output['loss'] = loss

        return output

    def predict(
            self,
            text: str,
            tokenizer,
            external_features: Optional[np.ndarray] = None,
            threshold: float = 0.5
    ) -> ModelOutput:
        """
        Predict threat score for a single email.

        Args:
            text: Email content
            tokenizer: Tokenizer for the model
            external_features: Optional external intelligence scores
            threshold: Classification threshold

        Returns:
            ModelOutput with predictions and explanations
        """
        self.eval()

        # Tokenize
        encoding = tokenizer(
            text,
            truncation=True,
            padding='max_length',
            max_length=512,
            return_tensors='pt'
        )

        # Move to device
        input_ids = encoding['input_ids'].to(self.device)
        attention_mask = encoding['attention_mask'].to(self.device)

        # Process external features
        if external_features is not None and self.use_external_features:
            ext_features = torch.tensor(external_features, dtype=torch.float32).unsqueeze(0).to(self.device)
        else:
            ext_features = None

        # Forward pass
        with torch.no_grad():
            outputs = self.forward(
                input_ids=input_ids,
                attention_mask=attention_mask,
                external_features=ext_features
            )

        # Get probabilities
        probs = outputs['probabilities'].cpu().numpy()[0]
        threat_prob = probs[1]  # Assuming class 1 is phishing

        # Generate explanations
        explanations = self._generate_explanations(text, threat_prob, external_features)

        # Determine risk level
        if threat_prob >= 0.8:
            risk_level = "CRITICAL"
        elif threat_prob >= 0.6:
            risk_level = "HIGH"
        elif threat_prob >= 0.4:
            risk_level = "MEDIUM"
        elif threat_prob >= 0.2:
            risk_level = "LOW"
        else:
            risk_level = "SAFE"

        # Feature importance (simplified)
        features_used = {
            'text_analysis': float(threat_prob),
            'url_reputation': float(external_features[0]) if external_features is not None else 0.0,
            'domain_age': float(external_features[1]) if external_features is not None else 0.0,
            'external_db_hits': float(external_features[2]) if external_features is not None else 0.0,
            'pattern_match': float(external_features[3]) if external_features is not None else 0.0
        }

        return ModelOutput(
            threat_score=float(threat_prob),
            risk_level=risk_level,
            confidence=float(max(probs)),
            explanations=explanations,
            features_used=features_used
        )

    def _generate_explanations(
            self,
            text: str,
            threat_prob: float,
            external_features: Optional[np.ndarray]
    ) -> List[str]:
        """Generate human-readable explanations for the prediction"""
        explanations = []

        # Text-based explanations
        if threat_prob > 0.7:
            urgent_words = ['urgent', 'immediately', 'verify', 'suspended', 'limited']
            found_words = [word for word in urgent_words if word in text.lower()]
            if found_words:
                explanations.append(f"Contains urgency words: {', '.join(found_words)}")

        # External feature explanations
        if external_features is not None:
            if external_features[0] > 0.7:
                explanations.append("Links have poor reputation (flagged by security vendors)")

            if external_features[1] > 0.7:
                explanations.append("Sender domain is newly registered")

            if external_features[2] > 0.7:
                explanations.append("Domain appears in threat intelligence databases")

            if external_features[3] > 0.7:
                explanations.append("Similar to previously detected phishing campaigns")

        if not explanations:
            if threat_prob > 0.5:
                explanations.append("Suspicious language patterns detected")
            else:
                explanations.append("No obvious phishing indicators found")

        return explanations


class TinyBERTPhishingDetector:
    """
    Lightweight version using pre-trained TinyBERT for faster inference.
    Good for resource-constrained environments.
    """

    def __init__(self, model_path: Optional[str] = None):
        from transformers import pipeline

        if model_path and Path(model_path).exists():
            # Load fine-tuned model
            self.classifier = pipeline(
                "text-classification",
                model=model_path,
                truncation=True
            )
            logger.info(f"Loaded TinyBERT model from {model_path}")
        else:
            # Use pre-trained from HuggingFace
            self.classifier = pipeline(
                "text-classification",
                model="prancyFox/tiny-bert-enron-spam",
                truncation=True
            )
            logger.info("Loaded pre-trained TinyBERT from HuggingFace")

    def predict(self, text: str) -> Dict:
        """Predict using TinyBERT"""
        result = self.classifier(text)[0]

        # Convert to our format
        is_phishing = result['label'].lower() == 'spam' or result['label'].lower() == 'phishing'
        score = result['score'] if is_phishing else 1 - result['score']

        return {
            'threat_score': score,
            'label': result['label'],
            'confidence': result['score']
        }