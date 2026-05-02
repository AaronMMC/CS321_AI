"""
A compact Transformer-based text classifier built entirely from PyTorch primitives.
No pre-trained weights are loaded at any point. The model trains from scratch
on whatever data you provide from the project's data/ folder.

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
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

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
    Lightweight word-level tokenizer built entirely from the training corpus.
    No external libraries, no pretrained vocabulary.

    Special tokens:
        <PAD>  = 0   padding
        <UNK>  = 1   out-of-vocabulary
        <CLS>  = 2   sentence start
        <SEP>  = 3   sentence end
    """

    PAD, UNK, CLS, SEP = 0, 1, 2, 3
    SPECIAL = {"<PAD>": 0, "<UNK>": 1, "<CLS>": 2, "<SEP>": 3}

    def __init__(self, max_vocab: int = 30_000):
        self.max_vocab = max_vocab
        self.word2idx: Dict[str, int] = dict(self.SPECIAL)
        self.idx2word: Dict[int, str] = {v: k for k, v in self.SPECIAL.items()}
        self._built = False

    @staticmethod
    def _clean(text: str) -> List[str]:
        text = text.lower()
        text = re.sub(r'https?://\S+', ' <URL> ', text)
        text = re.sub(r'\S+@\S+', ' <EMAIL> ', text)
        text = re.sub(r"[^a-z0-9\s<>_]", " ", text)
        return text.split()

    def build_vocab(self, texts: List[str], min_freq: int = 2) -> "SimpleTokenizer":
        """Build vocabulary from a list of raw text strings."""
        counter: Counter = Counter()
        for text in texts:
            counter.update(self._clean(text))

        most_common = counter.most_common(self.max_vocab - 4)
        for rank, (word, freq) in enumerate(most_common):
            if freq < min_freq:
                break
            idx = rank + 4
            self.word2idx[word] = idx
            self.idx2word[idx] = word

        self._built = True
        logger.info(
            f"Vocabulary built: {len(self.word2idx):,} tokens "
            f"(min_freq={min_freq}, max_vocab={self.max_vocab})"
        )
        return self

    def encode(self, text: str, max_length: int = 256, pad: bool = True) -> Tuple[List[int], List[int]]:
        """Returns (input_ids, attention_mask)."""
        tokens = self._clean(text)[: max_length - 2]
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

    def batch_encode(self, texts: List[str], max_length: int = 256) -> Dict[str, torch.Tensor]:
        all_ids, all_masks = [], []
        for text in texts:
            ids, mask = self.encode(text, max_length=max_length)
            all_ids.append(ids)
            all_masks.append(mask)
        return {
            "input_ids":      torch.tensor(all_ids,   dtype=torch.long),
            "attention_mask": torch.tensor(all_masks, dtype=torch.long),
        }

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
#  2.  POSITIONAL ENCODING
# ─────────────────────────────────────────────────────────────────────────────

class PositionalEncoding(nn.Module):
    """Fixed sinusoidal positional encoding — no learnable parameters."""

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
        pe = pe.unsqueeze(0)
        self.register_buffer("pe", pe)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = x + self.pe[:, : x.size(1)]
        return self.dropout(x)


# ─────────────────────────────────────────────────────────────────────────────
#  3.  SCRATCH TRANSFORMER CLASSIFIER
# ─────────────────────────────────────────────────────────────────────────────

class ScratchTransformerClassifier(nn.Module):
    """
    Compact Transformer encoder for binary text classification.
    All weights are randomly initialised — nothing is pre-trained.
    """

    def __init__(
        self,
        vocab_size:  int   = 30_000,
        embed_dim:   int   = 256,
        num_heads:   int   = 8,
        num_layers:  int   = 4,
        ffn_dim:     int   = 512,
        max_length:  int   = 256,
        num_classes: int   = 2,
        dropout:     float = 0.2,
        pad_idx:     int   = 0,
    ):
        super().__init__()

        assert embed_dim % num_heads == 0, (
            f"embed_dim ({embed_dim}) must be divisible by num_heads ({num_heads})"
        )

        self.embed_dim  = embed_dim
        self.max_length = max_length
        self.pad_idx    = pad_idx

        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=pad_idx)
        nn.init.normal_(self.embedding.weight, mean=0.0, std=0.02)
        with torch.no_grad():
            self.embedding.weight[pad_idx].fill_(0)

        self.pos_encoding = PositionalEncoding(embed_dim, max_len=max_length, dropout=dropout)

        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim, nhead=num_heads,
            dim_feedforward=ffn_dim, dropout=dropout,
            activation="gelu", batch_first=True, norm_first=True,
        )
        self.encoder = nn.TransformerEncoder(
            encoder_layer, num_layers=num_layers, enable_nested_tensor=False
        )

        self.classifier = nn.Sequential(
            nn.LayerNorm(embed_dim),
            nn.Linear(embed_dim, embed_dim // 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(embed_dim // 2, num_classes),
        )

        self.loss_fn = nn.CrossEntropyLoss()
        self._init_weights()

        total = sum(p.numel() for p in self.parameters())
        logger.info(
            f"ScratchTransformerClassifier initialised "
            f"(vocab={vocab_size:,}, embed={embed_dim}, layers={num_layers}, heads={num_heads}) "
            f"— {total:,} parameters — ALL WEIGHTS RANDOM"
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

    def _make_pad_mask(self, attention_mask: torch.Tensor) -> torch.Tensor:
        return attention_mask == 0

    def forward(
        self,
        input_ids:      torch.Tensor,
        attention_mask: torch.Tensor,
        labels:         Optional[torch.Tensor] = None,
    ) -> Dict[str, torch.Tensor]:
        x = self.embedding(input_ids) * math.sqrt(self.embed_dim)
        x = self.pos_encoding(x)
        pad_mask = self._make_pad_mask(attention_mask)
        x = self.encoder(x, src_key_padding_mask=pad_mask)
        mask_f = attention_mask.unsqueeze(-1).float()
        pooled = (x * mask_f).sum(dim=1) / mask_f.sum(dim=1).clamp(min=1e-9)
        logits = self.classifier(pooled)
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
#  5.  HIGH-LEVEL WRAPPER
# ─────────────────────────────────────────────────────────────────────────────

class ScratchModelForEmailSecurity:
    """
    Drop-in model wrapper.

    Training flow:
        model = ScratchModelForEmailSecurity()
        model.build_tokenizer(train_texts)          # builds vocab from YOUR data
        history = model.train_quick(train_texts, train_labels)
        model.save("models_saved/scratch_v1")

    Inference flow:
        model = ScratchModelForEmailSecurity.load("models_saved/scratch_v1")
        result = model.predict("URGENT: verify your GCash account now")
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

        self._vocab_size = vocab_size
        self._embed_dim  = embed_dim
        self._num_heads  = num_heads
        self._num_layers = num_layers
        self._ffn_dim    = ffn_dim
        self._dropout    = dropout
        self.model: Optional[ScratchTransformerClassifier] = None

    def build_tokenizer(self, texts: List[str], min_freq: int = 2) -> "ScratchModelForEmailSecurity":
        """Build vocabulary from provided training texts."""
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

    def predict(self, text: Union[str, List[str]]) -> Union[Dict, List[Dict]]:
        assert self.model is not None and self.tokenizer is not None, \
            "Model not ready. Load a saved model via .load() or call build_tokenizer() + train_quick()."

        self.model.eval()
        single = isinstance(text, str)
        texts  = [text] if single else text

        encoded        = self.tokenizer.batch_encode(texts, max_length=self.max_length)
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

    def train_quick(
        self,
        train_texts:   List[str],
        train_labels:  List[int],
        val_texts:     Optional[List[str]]  = None,
        val_labels:    Optional[List[int]]  = None,
        epochs:        int   = 5,
        batch_size:    int   = 32,
        learning_rate: float = 3e-4,
        weight_decay:  float = 1e-2,
    ) -> Dict:
        assert self.model is not None, "Call build_tokenizer() first."

        train_ds = EmailDataset(train_texts, train_labels, self.tokenizer, self.max_length)
        train_dl = DataLoader(train_ds, batch_size=batch_size, shuffle=True,
                              num_workers=0, pin_memory=(self.device.type == "cuda"))

        val_dl = None
        if val_texts and val_labels:
            val_ds = EmailDataset(val_texts, val_labels, self.tokenizer, self.max_length)
            val_dl = DataLoader(val_ds, batch_size=batch_size, shuffle=False, num_workers=0)

        optimizer    = AdamW(self.model.parameters(), lr=learning_rate, weight_decay=weight_decay)
        total_steps  = len(train_dl) * epochs
        scheduler    = OneCycleLR(
            optimizer, max_lr=learning_rate,
            total_steps=total_steps, pct_start=0.1,
        )

        history: Dict[str, list] = {"train_loss": [], "val_accuracy": [], "val_f1": []}

        logger.info(
            f"Training from scratch — {len(train_texts):,} samples, "
            f"{epochs} epochs, device={self.device}"
        )

        for epoch in range(1, epochs + 1):
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