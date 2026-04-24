"""
A compact Transformer-based text classifier built entirely from scratch
using PyTorch primitives. NO pre-trained weights are loaded at any point.

Architecture overview:
  Token Embedding  (vocab_size → embed_dim)
  + Positional Encoding
  → N × TransformerEncoderLayer  (multi-head self-attention + FFN)
  → mean-pool over sequence
  → Classification head  (embed_dim → num_classes)

"""

import math
import json
import re
import string
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, Dataset
from torch.optim import AdamW
from torch.optim.lr_scheduler import OneCycleLR
from loguru import logger


# ─────────────────────────────────────────────────────────────────────────────
#  1.  TOKENIZER  (simple word-level, built from training data)
# ─────────────────────────────────────────────────────────────────────────────

class SimpleTokenizer:
    """
    Lightweight word-level tokenizer.
    Built entirely from the training corpus — no external libraries.

    Special tokens:
        <PAD>  = 0   padding
        <UNK>  = 1   out-of-vocabulary
        <CLS>  = 2   sentence start (classification token)
        <SEP>  = 3   sentence end
    """

    PAD, UNK, CLS, SEP = 0, 1, 2, 3
    SPECIAL = {"<PAD>": 0, "<UNK>": 1, "<CLS>": 2, "<SEP>": 3}

    def __init__(self, max_vocab: int = 30_000):
        self.max_vocab = max_vocab
        self.word2idx: Dict[str, int] = dict(self.SPECIAL)
        self.idx2word: Dict[int, str] = {v: k for k, v in self.SPECIAL.items()}
        self._built = False

    # ── text cleaning ──────────────────────────────────────────────────────
    @staticmethod
    def _clean(text: str) -> List[str]:
        text = text.lower()
        # replace URLs with a placeholder token
        text = re.sub(r'https?://\S+', ' <URL> ', text)
        # replace email addresses
        text = re.sub(r'\S+@\S+', ' <EMAIL> ', text)
        # keep alphanumeric + basic punctuation
        text = re.sub(r"[^a-z0-9\s<>_]", " ", text)
        return text.split()

    # ── vocabulary building ────────────────────────────────────────────────
    def build_vocab(self, texts: List[str], min_freq: int = 2) -> "SimpleTokenizer":
        """Build vocabulary from a list of raw text strings."""
        counter: Counter = Counter()
        for text in texts:
            counter.update(self._clean(text))

        # keep the top (max_vocab - 4) most frequent words
        most_common = counter.most_common(self.max_vocab - 4)
        for rank, (word, freq) in enumerate(most_common):
            if freq < min_freq:
                break
            idx = rank + 4          # 0-3 are reserved for special tokens
            self.word2idx[word] = idx
            self.idx2word[idx] = word

        self._built = True
        logger.info(
            f"Vocabulary built: {len(self.word2idx):,} tokens "
            f"(min_freq={min_freq}, max_vocab={self.max_vocab})"
        )
        return self

    # ── encoding ──────────────────────────────────────────────────────────
    def encode(
        self,
        text: str,
        max_length: int = 256,
        pad: bool = True,
    ) -> Tuple[List[int], List[int]]:
        """
        Returns (input_ids, attention_mask).
        Sequence format: [CLS] w1 w2 ... [SEP] [PAD...PAD]
        """
        tokens = self._clean(text)[: max_length - 2]   # reserve 2 for CLS/SEP
        ids = (
            [self.CLS]
            + [self.word2idx.get(t, self.UNK) for t in tokens]
            + [self.SEP]
        )
        mask = [1] * len(ids)

        if pad:
            pad_len = max_length - len(ids)
            ids  += [self.PAD] * pad_len
            mask += [0] * pad_len

        return ids[:max_length], mask[:max_length]

    def batch_encode(
        self,
        texts: List[str],
        max_length: int = 256,
    ) -> Dict[str, torch.Tensor]:
        all_ids, all_masks = [], []
        for text in texts:
            ids, mask = self.encode(text, max_length=max_length)
            all_ids.append(ids)
            all_masks.append(mask)
        return {
            "input_ids":      torch.tensor(all_ids,   dtype=torch.long),
            "attention_mask": torch.tensor(all_masks, dtype=torch.long),
        }

    # ── persistence ───────────────────────────────────────────────────────
    def save(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"word2idx": self.word2idx, "max_vocab": self.max_vocab}, f)
        logger.info(f"Tokenizer saved → {path}")

    @classmethod
    def load(cls, path: str) -> "SimpleTokenizer":
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        tok = cls(max_vocab=data["max_vocab"])
        tok.word2idx = {k: int(v) for k, v in data["word2idx"].items()}
        tok.idx2word = {int(v): k for k, v in tok.word2idx.items()}
        tok._built = True
        logger.info(f"Tokenizer loaded ← {path} ({len(tok.word2idx):,} tokens)")
        return tok

    @property
    def vocab_size(self) -> int:
        return len(self.word2idx)


# ─────────────────────────────────────────────────────────────────────────────
#  2.  POSITIONAL ENCODING  (standard sinusoidal, no learnable params)
# ─────────────────────────────────────────────────────────────────────────────

class PositionalEncoding(nn.Module):
    """
    Fixed sinusoidal positional encoding (Vaswani et al., 2017).
    No learnable parameters — entirely deterministic.
    """

    def __init__(self, embed_dim: int, max_len: int = 512, dropout: float = 0.1):
        super().__init__()
        self.dropout = nn.Dropout(dropout)

        pe = torch.zeros(max_len, embed_dim)
        position = torch.arange(0, max_len).unsqueeze(1).float()
        div_term = torch.exp(
            torch.arange(0, embed_dim, 2).float() * (-math.log(10_000.0) / embed_dim)
        )
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        pe = pe.unsqueeze(0)            # (1, max_len, embed_dim)
        self.register_buffer("pe", pe)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (batch, seq_len, embed_dim)
        x = x + self.pe[:, : x.size(1)]
        return self.dropout(x)


# ─────────────────────────────────────────────────────────────────────────────
#  3.  SCRATCH TRANSFORMER CLASSIFIER
# ─────────────────────────────────────────────────────────────────────────────

class ScratchTransformerClassifier(nn.Module):
    """
    Compact Transformer encoder for binary text classification.
    All weights are randomly initialised — nothing is pre-trained.

    Default hyperparameters are tuned for:
      - ~10k–200k training samples
      - sequences up to 256 tokens
      - binary phishing / legitimate classification
      - training on a single GPU or modern CPU in under 2 hours
    """

    def __init__(
        self,
        vocab_size:   int   = 30_000,
        embed_dim:    int   = 256,       # embedding + model dimension
        num_heads:    int   = 8,         # attention heads  (embed_dim % num_heads == 0)
        num_layers:   int   = 4,         # transformer encoder layers
        ffn_dim:      int   = 512,       # feed-forward inner dimension
        max_length:   int   = 256,       # maximum sequence length
        num_classes:  int   = 2,         # 0 = legitimate, 1 = phishing
        dropout:      float = 0.2,
        pad_idx:      int   = 0,
    ):
        super().__init__()

        assert embed_dim % num_heads == 0, (
            f"embed_dim ({embed_dim}) must be divisible by num_heads ({num_heads})"
        )

        self.embed_dim   = embed_dim
        self.max_length  = max_length
        self.pad_idx     = pad_idx

        # ── Token embedding ───────────────────────────────────────────────
        self.embedding = nn.Embedding(
            vocab_size, embed_dim, padding_idx=pad_idx
        )
        nn.init.normal_(self.embedding.weight, mean=0.0, std=0.02)
        with torch.no_grad():
            self.embedding.weight[pad_idx].fill_(0)

        # ── Positional encoding ───────────────────────────────────────────
        self.pos_encoding = PositionalEncoding(
            embed_dim, max_len=max_length, dropout=dropout
        )

        # ── Transformer encoder ───────────────────────────────────────────
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim,
            nhead=num_heads,
            dim_feedforward=ffn_dim,
            dropout=dropout,
            activation="gelu",
            batch_first=True,       # (batch, seq, dim) convention
            norm_first=True,        # pre-LN: more stable training from scratch
        )
        self.encoder = nn.TransformerEncoder(
            encoder_layer,
            num_layers=num_layers,
            enable_nested_tensor=False,
        )

        # ── Classification head ───────────────────────────────────────────
        self.classifier = nn.Sequential(
            nn.LayerNorm(embed_dim),
            nn.Linear(embed_dim, embed_dim // 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(embed_dim // 2, num_classes),
        )

        # ── Loss ──────────────────────────────────────────────────────────
        self.loss_fn = nn.CrossEntropyLoss()

        # ── Weight init for linear layers ─────────────────────────────────
        self._init_weights()

        total_params = sum(p.numel() for p in self.parameters())
        logger.info(
            f"ScratchTransformerClassifier initialised "
            f"(vocab={vocab_size:,}, embed={embed_dim}, "
            f"layers={num_layers}, heads={num_heads}) "
            f"— {total_params:,} parameters — ALL WEIGHTS RANDOM"
        )

    def _init_weights(self):
        for module in self.modules():
            if isinstance(module, nn.Linear):
                nn.init.xavier_uniform_(module.weight)
                if module.bias is not None:
                    nn.init.zeros_(module.bias)
            elif isinstance(module, nn.LayerNorm):
                nn.init.ones_(module.weight)
                nn.init.zeros_(module.bias)

    # ── padding mask ──────────────────────────────────────────────────────
    def _make_pad_mask(self, attention_mask: torch.Tensor) -> torch.Tensor:
        """
        Convert HuggingFace-style attention_mask (1=real, 0=pad)
        to PyTorch src_key_padding_mask (True=pad, False=real).
        """
        return attention_mask == 0   # (batch, seq_len)

    # ── forward ───────────────────────────────────────────────────────────
    def forward(
        self,
        input_ids:      torch.Tensor,
        attention_mask: torch.Tensor,
        labels:         Optional[torch.Tensor] = None,
    ) -> Dict[str, torch.Tensor]:
        """
        Args:
            input_ids:      (B, L)  long tensor of token indices
            attention_mask: (B, L)  1 for real tokens, 0 for padding
            labels:         (B,)    optional; if provided, loss is computed

        Returns dict with keys: logits, probabilities, [loss]
        """
        # Embed + positional encode
        x = self.embedding(input_ids) * math.sqrt(self.embed_dim)
        x = self.pos_encoding(x)                          # (B, L, D)

        # Transformer encoder
        pad_mask = self._make_pad_mask(attention_mask)    # (B, L)
        x = self.encoder(x, src_key_padding_mask=pad_mask)  # (B, L, D)

        # Mean pool over non-padding positions
        mask_f = attention_mask.unsqueeze(-1).float()     # (B, L, 1)
        pooled = (x * mask_f).sum(dim=1) / mask_f.sum(dim=1).clamp(min=1e-9)  # (B, D)

        logits = self.classifier(pooled)                  # (B, C)
        probs  = torch.softmax(logits, dim=-1)

        out: Dict[str, torch.Tensor] = {"logits": logits, "probabilities": probs}
        if labels is not None:
            out["loss"] = self.loss_fn(logits, labels)
        return out


# ─────────────────────────────────────────────────────────────────────────────
#  4.  DATASET WRAPPER
# ─────────────────────────────────────────────────────────────────────────────

class EmailDataset(Dataset):
    def __init__(
        self,
        texts:      List[str],
        labels:     List[int],
        tokenizer:  SimpleTokenizer,
        max_length: int = 256,
    ):
        self.tokenizer  = tokenizer
        self.max_length = max_length
        self.labels     = labels
        self.encoded    = [tokenizer.encode(t, max_length=max_length) for t in texts]

    def __len__(self) -> int:
        return len(self.labels)

    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        ids, mask = self.encoded[idx]
        return {
            "input_ids":      torch.tensor(ids,  dtype=torch.long),
            "attention_mask": torch.tensor(mask, dtype=torch.long),
            "labels":         torch.tensor(self.labels[idx], dtype=torch.long),
        }


# ─────────────────────────────────────────────────────────────────────────────
#  5.  HIGH-LEVEL WRAPPER  (drop-in replacement for TinyBERTForEmailSecurity)
# ─────────────────────────────────────────────────────────────────────────────

class ScratchModelForEmailSecurity:
    """
    Drop-in replacement for TinyBERTForEmailSecurity.

    Usage — training:
        model = ScratchModelForEmailSecurity()
        model.build_tokenizer(train_texts)
        history = model.train_quick(train_texts, train_labels)
        model.save("models_saved/scratch_v1")

    Usage — inference:
        model = ScratchModelForEmailSecurity.load("models_saved/scratch_v1")
        result = model.predict("URGENT: verify your GCash account now")
        # → {"threat_score": 0.91, "label": "PHISHING", "confidence": 0.91}
    """

    def __init__(
        self,
        vocab_size:  int   = 30_000,
        embed_dim:   int   = 256,
        num_heads:   int   = 8,
        num_layers:  int   = 4,
        ffn_dim:     int   = 512,
        max_length:  int   = 256,
        dropout:     float = 0.2,
        use_gpu:     bool  = True,
    ):
        self.max_length = max_length
        self.device = torch.device(
            "cuda" if torch.cuda.is_available() and use_gpu else "cpu"
        )

        self.tokenizer: Optional[SimpleTokenizer] = None

        # model is created after vocab is known
        self._vocab_size = vocab_size
        self._embed_dim  = embed_dim
        self._num_heads  = num_heads
        self._num_layers = num_layers
        self._ffn_dim    = ffn_dim
        self._dropout    = dropout
        self.model: Optional[ScratchTransformerClassifier] = None

    # ── tokenizer ─────────────────────────────────────────────────────────
    def build_tokenizer(self, texts: List[str], min_freq: int = 2) -> "ScratchModelForEmailSecurity":
        self.tokenizer = SimpleTokenizer(max_vocab=self._vocab_size)
        self.tokenizer.build_vocab(texts, min_freq=min_freq)
        self._init_model()
        return self

    def _init_model(self):
        assert self.tokenizer is not None, "Call build_tokenizer() first."
        self.model = ScratchTransformerClassifier(
            vocab_size  = self.tokenizer.vocab_size,
            embed_dim   = self._embed_dim,
            num_heads   = self._num_heads,
            num_layers  = self._num_layers,
            ffn_dim     = self._ffn_dim,
            max_length  = self.max_length,
            dropout     = self._dropout,
        ).to(self.device)

    # ── prediction ────────────────────────────────────────────────────────
    def predict(self, text: Union[str, List[str]]) -> Union[Dict, List[Dict]]:
        assert self.model is not None and self.tokenizer is not None, \
            "Model not ready. Call build_tokenizer() + train_quick() or load()."

        self.model.eval()
        single = isinstance(text, str)
        texts  = [text] if single else text

        encoded = self.tokenizer.batch_encode(texts, max_length=self.max_length)
        input_ids      = encoded["input_ids"].to(self.device)
        attention_mask = encoded["attention_mask"].to(self.device)

        with torch.no_grad():
            out   = self.model(input_ids, attention_mask)
            probs = out["probabilities"].cpu().numpy()

        results = []
        for p in probs:
            score = float(p[1])
            label = (
                "PHISHING"   if score >= 0.7 else
                "SUSPICIOUS" if score >= 0.4 else
                "LEGITIMATE"
            )
            results.append({
                "threat_score": score,
                "label":        label,
                "confidence":   float(max(p)),
            })

        return results[0] if single else results

    # ── training ──────────────────────────────────────────────────────────
    def train_quick(
        self,
        train_texts:  List[str],
        train_labels: List[int],
        val_texts:    Optional[List[str]]  = None,
        val_labels:   Optional[List[int]]  = None,
        epochs:       int   = 5,
        batch_size:   int   = 32,
        learning_rate: float = 3e-4,
        weight_decay: float = 1e-2,
    ) -> Dict:
        """
        Train the model end-to-end on the provided data.
        Tokenizer must be built first via build_tokenizer().

        Recommended: 5–10 epochs on Colab GPU, 3–5 on a decent desktop GPU.
        """
        assert self.model is not None, "Call build_tokenizer() first."

        train_ds = EmailDataset(train_texts, train_labels, self.tokenizer, self.max_length)
        train_dl = DataLoader(train_ds, batch_size=batch_size, shuffle=True,
                              num_workers=0, pin_memory=(self.device.type == "cuda"))

        val_dl = None
        if val_texts and val_labels:
            val_ds = EmailDataset(val_texts, val_labels, self.tokenizer, self.max_length)
            val_dl = DataLoader(val_ds, batch_size=batch_size, shuffle=False, num_workers=0)

        optimizer = AdamW(
            self.model.parameters(), lr=learning_rate, weight_decay=weight_decay
        )
        total_steps = len(train_dl) * epochs
        scheduler   = OneCycleLR(
            optimizer, max_lr=learning_rate,
            total_steps=total_steps, pct_start=0.1,
        )

        history: Dict[str, list] = {
            "train_loss": [], "val_accuracy": [], "val_f1": []
        }

        logger.info(
            f"Training from scratch — {len(train_texts):,} samples, "
            f"{epochs} epochs, device={self.device}"
        )

        for epoch in range(1, epochs + 1):
            # ── train ──────────────────────────────────────────────────
            self.model.train()
            running_loss, n_batches = 0.0, 0

            for batch in train_dl:
                batch = {k: v.to(self.device) for k, v in batch.items()}
                out   = self.model(**batch)
                loss  = out["loss"]

                optimizer.zero_grad()
                loss.backward()
                nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
                optimizer.step()
                scheduler.step()

                running_loss += loss.item()
                n_batches    += 1

            avg_loss = running_loss / n_batches
            history["train_loss"].append(avg_loss)

            # ── validate ───────────────────────────────────────────────
            if val_dl:
                acc, f1 = self._evaluate(val_dl)
                history["val_accuracy"].append(acc)
                history["val_f1"].append(f1)
                logger.info(
                    f"Epoch {epoch}/{epochs}  loss={avg_loss:.4f}  "
                    f"val_acc={acc:.4f}  val_f1={f1:.4f}"
                )
            else:
                logger.info(f"Epoch {epoch}/{epochs}  loss={avg_loss:.4f}")

        logger.success("Training complete.")
        return history

    def _evaluate(self, dl: DataLoader) -> Tuple[float, float]:
        from sklearn.metrics import accuracy_score, f1_score

        self.model.eval()
        all_preds, all_labels = [], []

        with torch.no_grad():
            for batch in dl:
                batch  = {k: v.to(self.device) for k, v in batch.items()}
                out    = self.model(**batch)
                preds  = out["logits"].argmax(dim=-1).cpu().numpy()
                labels = batch["labels"].cpu().numpy()
                all_preds.extend(preds)
                all_labels.extend(labels)

        acc = accuracy_score(all_labels, all_preds)
        f1  = f1_score(all_labels, all_preds, average="binary", zero_division=0)
        return acc, f1

    # ── persistence ───────────────────────────────────────────────────────
    def save(self, directory: str):
        path = Path(directory)
        path.mkdir(parents=True, exist_ok=True)

        torch.save(self.model.state_dict(), path / "model_weights.pt")
        self.tokenizer.save(str(path / "tokenizer.json"))

        config = {
            "vocab_size":  self._vocab_size,
            "embed_dim":   self._embed_dim,
            "num_heads":   self._num_heads,
            "num_layers":  self._num_layers,
            "ffn_dim":     self._ffn_dim,
            "max_length":  self.max_length,
            "dropout":     self._dropout,
        }
        with open(path / "config.json", "w") as f:
            json.dump(config, f, indent=2)

        logger.info(f"Model saved → {path}")

    @classmethod
    def load(cls, directory: str, use_gpu: bool = True) -> "ScratchModelForEmailSecurity":
        path = Path(directory)

        with open(path / "config.json") as f:
            cfg = json.load(f)

        instance = cls(**cfg, use_gpu=use_gpu)
        instance.tokenizer = SimpleTokenizer.load(str(path / "tokenizer.json"))
        instance._init_model()
        instance.model.load_state_dict(
            torch.load(path / "model_weights.pt", map_location=instance.device)
        )
        instance.model.eval()
        logger.info(f"Model loaded ← {path}")
        return instance


# ─────────────────────────────────────────────────────────────────────────────
#  6.  MINI DATASET HELPER  (keeps same interface as old tinybert_model.py)
# ─────────────────────────────────────────────────────────────────────────────

def create_mini_dataset_for_quick_training() -> Tuple[List[str], List[int]]:
    """
    Returns (texts, labels) for quick smoke-test training.
    Mirrors the function of the same name in the old tinybert_model.py
    so existing call-sites remain unchanged.
    """
    legitimate = [
        "Meeting agenda for tomorrow's project review",
        "Please find attached the quarterly financial report",
        "Your leave request has been approved for next week",
        "Reminder: team building event this Friday at 3pm",
        "Project update: all milestones achieved on time",
        "Invoice 12345 for services rendered this month",
        "Welcome to the team, here is your onboarding schedule",
        "System maintenance scheduled for Sunday 2 AM to 4 AM",
        "Your password reset request has been processed",
        "Thank you for your application, we will be in touch",
        "Please review the attached memorandum before the meeting",
        "Attendance sheet for April training program is now available",
    ]

    phishing = [
        "URGENT your account will be suspended in 24 hours click here to verify",
        "You have won 1000000 pesos claim your prize now by providing bank details",
        "GCash your account has been limited verify immediately at this link",
        "Security alert unusual login detected confirm your identity now",
        "Your Netflix subscription is expiring update payment method",
        "DICT your email requires immediate verification click link below",
        "PayPal transaction disputed sign in to review your account",
        "Apple ID your account has been locked unlock now to avoid data loss",
        "Tax refund available submit form to receive payment from BIR",
        "HR department update your payroll information immediately or salary delayed",
        "Dear user your gcash wallet is on hold please verify here",
        "DepEd email verification required action needed within 48 hours",
    ]

    texts, labels = [], []
    for email in legitimate:
        for variant in [email, email.upper(), email.replace("your", "YOUR")]:
            texts.append(variant)
            labels.append(0)

    for email in phishing:
        for variant in [email, email.replace("URGENT", "IMPORTANT"), email.lower()]:
            texts.append(variant)
            labels.append(1)

    texts.append("your package is delayed track here http://bit.ly/track-package")
    labels.append(0)
    texts.append("your package is delayed verify account at http://bit.ly/verify-account")
    labels.append(1)

    logger.info(f"Mini dataset: {len(texts)} samples ({labels.count(0)} legit, {labels.count(1)} phishing)")
    return texts, labels