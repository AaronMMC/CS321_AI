"""
bert_classifier.py  —  UPDATED

Previously used AutoModel / AutoTokenizer from HuggingFace, which loaded
pre-trained BERT weights. This version builds the same BERT-style encoder
architecture from scratch using only torch.nn — zero pre-trained weights.

The ScratchBERTClassifier here is the "full-size" counterpart to the
lightweight ScratchTransformerClassifier in scratch_transformer.py.
Use this when you want a larger, more accurate model and have the compute.
"""

import math
import torch
import torch.nn as nn
from typing import Dict, List, Optional
from dataclasses import dataclass
from loguru import logger
import numpy as np

from src.models.scratch_transformer import (
    SimpleTokenizer,
    PositionalEncoding,
    ScratchModelForEmailSecurity,
)


@dataclass
class ModelOutput:
    """Structured output from the model — interface unchanged."""
    threat_score:  float
    risk_level:    str
    confidence:    float
    explanations:  List[str]
    features_used: Dict[str, float]


class ScratchBERTClassifier(nn.Module):
    """
    Full-sized scratch Transformer classifier.
    Larger than ScratchTransformerClassifier but still fully randomly
    initialised — no pre-trained weights whatsoever.

    Default config mirrors BERT-base dimensions scaled to be trainable
    in a reasonable time on a single mid-range GPU:
        embed_dim  = 512   (BERT-base uses 768)
        num_heads  = 8
        num_layers = 6     (BERT-base uses 12)
        ffn_dim    = 2048  (BERT-base uses 3072)
    """

    def __init__(
        self,
        vocab_size:          int   = 30_000,
        embed_dim:           int   = 512,
        num_heads:           int   = 8,
        num_layers:          int   = 6,
        ffn_dim:             int   = 2048,
        max_length:          int   = 256,
        num_labels:          int   = 2,
        dropout:             float = 0.1,
        use_external_features: bool = True,
        pad_idx:             int   = 0,
    ):
        super().__init__()

        self.embed_dim            = embed_dim
        self.max_length           = max_length
        self.use_external_features = use_external_features
        self.num_labels           = num_labels

        # ── Embedding stack ───────────────────────────────────────────────
        self.embedding    = nn.Embedding(vocab_size, embed_dim, padding_idx=pad_idx)
        self.pos_encoding = PositionalEncoding(embed_dim, max_len=max_length, dropout=dropout)
        nn.init.normal_(self.embedding.weight, std=0.02)
        with torch.no_grad():
            self.embedding.weight[pad_idx].fill_(0)

        # ── Transformer encoder ───────────────────────────────────────────
        enc_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim, nhead=num_heads,
            dim_feedforward=ffn_dim, dropout=dropout,
            activation="gelu", batch_first=True, norm_first=True,
        )
        self.encoder = nn.TransformerEncoder(
            enc_layer, num_layers=num_layers, enable_nested_tensor=False
        )

        # ── External feature fusion (4-dim threat intelligence vector) ────
        if use_external_features:
            self.feature_projection = nn.Sequential(
                nn.Linear(4, embed_dim // 4),
                nn.GELU(),
            )
            clf_input_dim = embed_dim + embed_dim // 4
        else:
            clf_input_dim = embed_dim

        # ── Classification head ───────────────────────────────────────────
        self.classifier = nn.Sequential(
            nn.LayerNorm(clf_input_dim),
            nn.Linear(clf_input_dim, clf_input_dim // 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(clf_input_dim // 2, clf_input_dim // 4),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(clf_input_dim // 4, num_labels),
        )

        self.loss_fn = nn.CrossEntropyLoss()
        self._init_weights()

        total = sum(p.numel() for p in self.parameters())
        logger.info(
            f"ScratchBERTClassifier ready — {total:,} params — "
            f"ALL WEIGHTS RANDOMLY INITIALISED"
        )

    def _init_weights(self):
        for m in self.modules():
            if isinstance(m, nn.Linear):
                nn.init.xavier_uniform_(m.weight)
                if m.bias is not None:
                    nn.init.zeros_(m.bias)
            elif isinstance(m, nn.LayerNorm):
                nn.init.ones_(m.weight)
                nn.init.zeros_(m.bias)

    def forward(
        self,
        input_ids:         torch.Tensor,
        attention_mask:    torch.Tensor,
        external_features: Optional[torch.Tensor] = None,
        labels:            Optional[torch.Tensor] = None,
    ) -> Dict[str, torch.Tensor]:

        x = self.embedding(input_ids) * math.sqrt(self.embed_dim)
        x = self.pos_encoding(x)

        pad_mask = (attention_mask == 0)
        x = self.encoder(x, src_key_padding_mask=pad_mask)

        # Mean pooling over real tokens
        mask_f = attention_mask.unsqueeze(-1).float()
        pooled = (x * mask_f).sum(1) / mask_f.sum(1).clamp(min=1e-9)

        if self.use_external_features and external_features is not None:
            proj = self.feature_projection(external_features)
            pooled = torch.cat([pooled, proj], dim=1)

        logits = self.classifier(pooled)
        probs  = torch.softmax(logits, dim=-1)

        out: Dict[str, torch.Tensor] = {"logits": logits, "probabilities": probs}
        if labels is not None:
            out["loss"] = self.loss_fn(logits, labels)
        return out

    def predict(
        self,
        text:               str,
        tokenizer:          SimpleTokenizer,
        external_features:  Optional[np.ndarray] = None,
        threshold:          float = 0.5,
    ) -> ModelOutput:
        self.eval()
        device = next(self.parameters()).device

        ids, mask = tokenizer.encode(text, max_length=self.max_length)
        input_ids      = torch.tensor([ids],  dtype=torch.long).to(device)
        attention_mask = torch.tensor([mask], dtype=torch.long).to(device)

        ext = None
        if external_features is not None and self.use_external_features:
            ext = torch.tensor(external_features, dtype=torch.float32
                               ).unsqueeze(0).to(device)

        with torch.no_grad():
            out = self.forward(input_ids, attention_mask, ext)

        probs       = out["probabilities"].cpu().numpy()[0]
        threat_prob = float(probs[1])

        if threat_prob >= 0.8:   risk_level = "CRITICAL"
        elif threat_prob >= 0.6: risk_level = "HIGH"
        elif threat_prob >= 0.4: risk_level = "MEDIUM"
        elif threat_prob >= 0.2: risk_level = "LOW"
        else:                    risk_level = "SAFE"

        explanations = self._generate_explanations(text, threat_prob, external_features)

        features_used = {
            "text_analysis":   threat_prob,
            "url_reputation":  float(external_features[0]) if external_features is not None else 0.0,
            "domain_age":      float(external_features[1]) if external_features is not None else 0.0,
            "external_db_hits":float(external_features[2]) if external_features is not None else 0.0,
            "pattern_match":   float(external_features[3]) if external_features is not None else 0.0,
        }

        return ModelOutput(
            threat_score=threat_prob,
            risk_level=risk_level,
            confidence=float(max(probs)),
            explanations=explanations,
            features_used=features_used,
        )

    def _generate_explanations(
        self,
        text:              str,
        threat_prob:       float,
        external_features: Optional[np.ndarray],
    ) -> List[str]:
        explanations = []
        if threat_prob > 0.7:
            urgent_words = ["urgent", "immediately", "verify", "suspended", "limited"]
            found = [w for w in urgent_words if w in text.lower()]
            if found:
                explanations.append(f"Contains urgency words: {', '.join(found)}")
        if external_features is not None:
            if external_features[0] > 0.7:
                explanations.append("Links flagged by security vendors (URL reputation)")
            if external_features[1] > 0.7:
                explanations.append("Sender domain is newly registered")
            if external_features[2] > 0.7:
                explanations.append("Domain appears in threat intelligence databases")
            if external_features[3] > 0.7:
                explanations.append("Similar to previously detected phishing campaigns")
        if not explanations:
            explanations.append(
                "Suspicious language patterns detected" if threat_prob > 0.5
                else "No obvious phishing indicators found"
            )
        return explanations


# ── Backwards-compatible alias ────────────────────────────────────────────────
# Old code that imported BERTPhishingClassifier still works.
BERTPhishingClassifier = ScratchBERTClassifier