#!/usr/bin/env python3
"""
scripts/train_model.py
======================
Train the scratch Transformer phishing detector.

Key improvements over the original:
  - --max-minutes  : hard time-limit (default 5 min) so training always finishes
  - GPU-first      : uses CUDA automatically if present (RTX 4060, etc.)
  - Rich progress  : tqdm bars per epoch + per batch so it never looks stuck
  - Graceful stop  : Ctrl-C saves the best checkpoint seen so far before exiting
  - --epochs / --lr / --batch-size  : quick override flags

Usage
-----
# Default: 5-minute cap, auto GPU, auto-download data if missing
python scripts/train_model.py

# Longer run with explicit settings
python scripts/train_model.py --max-minutes 15 --epochs 10 --batch-size 32

# Force CPU (useful for debugging)
python scripts/train_model.py --no-gpu

# Skip dataset download (data already in data/processed/)
python scripts/train_model.py --skip-download
"""

import argparse
import signal
import sys
import time
from pathlib import Path

# ── project root on path ─────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# ── third-party imports (done after path fix) ─────────────────────────────────
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    print("[warn] tqdm not installed — install it for progress bars: pip install tqdm")

import torch
import pandas as pd
from sklearn.model_selection import train_test_split
from loguru import logger

from src.models.scratch_transformer import ScratchModelForEmailSecurity, SimpleTokenizer
from src.models.scratch_transformer import ScratchTransformerClassifier, EmailDataset
from torch.utils.data import DataLoader
from torch.optim import AdamW
from torch.optim.lr_scheduler import OneCycleLR
import torch.nn as nn
from sklearn.metrics import accuracy_score, f1_score

# ── constants ─────────────────────────────────────────────────────────────────
DEFAULT_MAX_MINUTES = 5
MODEL_SAVE_PATH     = str(ROOT / "models_saved" / "email_security_model")
DATA_PATH           = ROOT / "data" / "processed" / "training_data.csv"
SYNTHETIC_PATH      = ROOT / "data" / "processed" / "synthetic_training_data.csv"

# ── graceful interrupt flag ───────────────────────────────────────────────────
_interrupted = False

def _handle_sigint(sig, frame):
    global _interrupted
    if not _interrupted:
        print("\n\n[!] Ctrl-C received — finishing current batch then saving best checkpoint …")
        _interrupted = True
    else:
        print("\n[!] Second Ctrl-C — force-exiting now.")
        sys.exit(1)

signal.signal(signal.SIGINT, _handle_sigint)


# ── helpers ───────────────────────────────────────────────────────────────────

def _fmt_time(seconds: float) -> str:
    m, s = divmod(int(seconds), 60)
    return f"{m}m {s:02d}s"


def _load_data(skip_download: bool) -> tuple:
    """Return (texts, labels) lists."""
    # Try processed data first
    for path in [DATA_PATH, SYNTHETIC_PATH]:
        if path.exists():
            logger.info(f"Loading data from {path}")
            df = pd.read_csv(path).dropna(subset=["text", "label"])
            if len(df) > 0:
                logger.info(f"  {len(df):,} rows loaded")
                return df["text"].tolist(), df["label"].astype(int).tolist()

    if skip_download:
        logger.error("No training data found and --skip-download was set.")
        logger.error(f"Run: python scripts/download_datasets.py --all")
        sys.exit(1)

    # Auto-download
    logger.info("No data found — auto-downloading datasets …")
    try:
        from scripts.download_datasets import DatasetDownloader
        dl = DatasetDownloader()
        results = dl.download_all()
        failed = [k for k, v in results.items() if not v]
        if failed:
            logger.warning(f"Some downloads failed: {failed}")
        path = dl.create_training_data(sample_frac=0.2)
        df = pd.read_csv(path).dropna(subset=["text", "label"])
        return df["text"].tolist(), df["label"].astype(int).tolist()
    except Exception as e:
        logger.error(f"Auto-download failed: {e}")
        logger.warning("Falling back to built-in synthetic data …")
        return _make_synthetic()


def _make_synthetic() -> tuple:
    """Tiny built-in dataset so the script always works offline."""
    legit = [
        "Meeting scheduled for tomorrow at 10am in Conference Room A",
        "Please find attached the quarterly report for your review",
        "Your leave request for next week has been approved by HR",
        "Reminder: team building event this Friday afternoon",
        "Monthly performance metrics are now available on the portal",
        "The project milestone has been completed on schedule",
        "Your expense report has been processed and approved",
        "Please review the draft document and provide feedback",
    ]
    phish = [
        "URGENT: Your account will be suspended click here to verify now",
        "You have won 1000000 dollars claim your prize provide bank details",
        "GCash account limited verify immediately at http://bit.ly/gcash",
        "Security Alert unusual login detected confirm your identity now",
        "Netflix subscription expiring update payment http://bit.ly/update",
        "DICT email verification required click here or account deactivated",
        "Your password expires today update at http://bit.ly/secure-login",
        "Congratulations selected winner provide personal details to claim",
    ]
    texts  = (legit + phish) * 150
    labels = ([0] * len(legit) + [1] * len(phish)) * 150
    logger.info(f"Using synthetic data: {len(texts):,} samples")
    return texts, labels


def _pick_device(use_gpu: bool) -> torch.device:
    if use_gpu and torch.cuda.is_available():
        name = torch.cuda.get_device_name(0)
        vram = torch.cuda.get_device_properties(0).total_memory // (1024**3)
        logger.info(f"GPU detected: {name} ({vram} GB VRAM) — training on CUDA")
        return torch.device("cuda")
    if use_gpu:
        logger.warning("No CUDA GPU detected — falling back to CPU")
    else:
        logger.info("--no-gpu flag set — using CPU")
    return torch.device("cpu")


# ── core training loop ────────────────────────────────────────────────────────

def train(
    texts: list,
    labels: list,
    device: torch.device,
    max_seconds: float,
    epochs: int,
    batch_size: int,
    learning_rate: float,
    val_split: float = 0.15,
) -> str:
    """
    Train the model.  Returns the path to the saved checkpoint.

    Stops early when:
      a) all epochs complete, OR
      b) wall-clock time >= max_seconds, OR
      c) user presses Ctrl-C
    """
    global _interrupted

    train_t, val_t, train_l, val_l = train_test_split(
        texts, labels, test_size=val_split, random_state=42, stratify=labels
    )
    logger.info(f"Split: {len(train_t):,} train / {len(val_t):,} val")

    # Build tokenizer
    logger.info("Building vocabulary …")
    tokenizer = SimpleTokenizer(max_vocab=30_000)
    tokenizer.build_vocab(train_t, min_freq=2)

    # Build model
    model = ScratchTransformerClassifier(
        vocab_size=tokenizer.vocab_size,
        embed_dim=256, num_heads=8, num_layers=4,
        ffn_dim=512, max_length=256, dropout=0.2,
    ).to(device)
    total_params = sum(p.numel() for p in model.parameters())
    logger.info(f"Model: {total_params:,} parameters on {device}")

    train_ds = EmailDataset(train_t, train_l, tokenizer, max_length=256)
    val_ds   = EmailDataset(val_t,   val_l,   tokenizer, max_length=256)
    pin = (device.type == "cuda")
    train_dl = DataLoader(train_ds, batch_size=batch_size, shuffle=True,
                          num_workers=0, pin_memory=pin)
    val_dl   = DataLoader(val_ds,   batch_size=batch_size, shuffle=False,
                          num_workers=0, pin_memory=pin)

    optimizer = AdamW(model.parameters(), lr=learning_rate, weight_decay=1e-2)
    total_steps = len(train_dl) * epochs
    scheduler = OneCycleLR(
        optimizer, max_lr=learning_rate,
        total_steps=max(total_steps, 1),
        pct_start=0.1, anneal_strategy="cos",
    )

    best_f1   = 0.0
    best_path = MODEL_SAVE_PATH
    deadline  = time.time() + max_seconds
    start_t   = time.time()

    print()
    print("=" * 65)
    print(f"  Training   — max {_fmt_time(max_seconds)} | {epochs} epochs | "
          f"bs={batch_size} | lr={learning_rate}")
    print(f"  Device     — {device}  ({train_t.__len__():,} train samples)")
    print("  Press Ctrl-C once to stop early and save best checkpoint")
    print("=" * 65)

    for epoch in range(1, epochs + 1):
        if _interrupted or time.time() >= deadline:
            logger.info("Time limit reached — stopping training loop")
            break

        # ── train epoch ───────────────────────────────────────────────────
        model.train()
        running_loss = 0.0
        n_batches    = 0
        remaining    = deadline - time.time()
        epoch_label  = f"Epoch {epoch}/{epochs} [train]"

        if HAS_TQDM:
            bar = tqdm(
                train_dl,
                desc=epoch_label,
                unit="batch",
                ncols=80,
                leave=True,
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]",
            )
            iterable = bar
        else:
            iterable = train_dl
            print(f"\n{epoch_label}  ({len(train_dl)} batches) …", flush=True)

        for batch in iterable:
            if _interrupted or time.time() >= deadline:
                break

            batch = {k: v.to(device) for k, v in batch.items()}
            out   = model(**batch)
            loss  = out["loss"]

            optimizer.zero_grad()
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()
            scheduler.step()

            running_loss += loss.item()
            n_batches    += 1

            if HAS_TQDM:
                elapsed  = time.time() - start_t
                time_left = max(0.0, deadline - time.time())
                bar.set_postfix(
                    loss=f"{loss.item():.4f}",
                    elapsed=_fmt_time(elapsed),
                    left=_fmt_time(time_left),
                )

        if HAS_TQDM:
            bar.close()

        avg_loss = running_loss / max(n_batches, 1)

        # ── validation ────────────────────────────────────────────────────
        model.eval()
        all_preds, all_labels = [], []
        val_label = f"Epoch {epoch}/{epochs} [ val ]"

        if HAS_TQDM:
            vbar = tqdm(val_dl, desc=val_label, unit="batch", ncols=80,
                        leave=True,
                        bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}")
            v_iterable = vbar
        else:
            v_iterable = val_dl

        with torch.no_grad():
            for batch in v_iterable:
                batch  = {k: v.to(device) for k, v in batch.items()}
                out    = model(**batch)
                preds  = out["logits"].argmax(-1).cpu().numpy()
                lbs    = batch["labels"].cpu().numpy()
                all_preds.extend(preds)
                all_labels.extend(lbs)

        if HAS_TQDM:
            vbar.close()

        acc = accuracy_score(all_labels, all_preds)
        f1  = f1_score(all_labels, all_preds, average="binary", zero_division=0)
        elapsed = time.time() - start_t

        status = "✓ NEW BEST" if f1 > best_f1 else ""
        print(f"  → loss={avg_loss:.4f}  acc={acc:.4f}  f1={f1:.4f}  "
              f"elapsed={_fmt_time(elapsed)}  {status}")

        if f1 > best_f1:
            best_f1 = f1
            _save(model, tokenizer, best_path)

    # ── final summary ─────────────────────────────────────────────────────
    elapsed = time.time() - start_t
    print()
    print("=" * 65)
    if _interrupted:
        print(f"  Training interrupted by user after {_fmt_time(elapsed)}")
    else:
        print(f"  Training complete in {_fmt_time(elapsed)}")
    print(f"  Best validation F1 : {best_f1:.4f}")
    print(f"  Checkpoint saved   : {best_path}")
    print("=" * 65)
    return best_path


def _save(model: ScratchTransformerClassifier, tokenizer: SimpleTokenizer, path: str):
    """Save model weights + tokenizer to directory."""
    import json
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), p / "model_weights.pt")
    tokenizer.save(str(p / "tokenizer.json"))
    config = {
        "vocab_size": model.embedding.num_embeddings,
        "embed_dim":  model.embed_dim,
        "num_heads":  8, "num_layers": 4,
        "ffn_dim":    512, "max_length": 256, "dropout": 0.2,
    }
    (p / "config.json").write_text(json.dumps(config, indent=2))
    logger.info(f"Checkpoint saved → {p}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="Train the Email Security Gateway AI model",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # 5-minute cap (default), GPU auto-detected
  python scripts/train_model.py

  # 15-minute run, 10 epochs
  python scripts/train_model.py --max-minutes 15 --epochs 10

  # Force CPU
  python scripts/train_model.py --no-gpu

  # Use pre-downloaded data, skip network
  python scripts/train_model.py --skip-download
        """,
    )
    p.add_argument("--max-minutes", type=float, default=DEFAULT_MAX_MINUTES,
                   help=f"Maximum training time in minutes (default: {DEFAULT_MAX_MINUTES})")
    p.add_argument("--epochs",      type=int,   default=20,
                   help="Max epochs (stopped early by time limit, default: 20)")
    p.add_argument("--batch-size",  type=int,   default=32,
                   help="Batch size (default: 32; reduce to 16 if OOM)")
    p.add_argument("--lr",          type=float, default=3e-4,
                   help="Learning rate (default: 3e-4)")
    p.add_argument("--no-gpu",      action="store_true",
                   help="Disable GPU even if available")
    p.add_argument("--skip-download", action="store_true",
                   help="Skip dataset download if data already present")
    p.add_argument("--sample",      type=float, default=0.2,
                   help="Fraction of data to use (default: 0.2 for speed)")
    return p.parse_args()


def main():
    args = parse_args()

    # ── announce settings ─────────────────────────────────────────────────
    print()
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║       Email Security Gateway — Model Trainer                ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(f"  Time limit  : {args.max_minutes} minute(s)")
    print(f"  Max epochs  : {args.epochs}")
    print(f"  Batch size  : {args.batch_size}")
    print(f"  GPU enabled : {not args.no_gpu}")
    print()

    device = _pick_device(use_gpu=not args.no_gpu)
    texts, labels = _load_data(skip_download=args.skip_download)

    # Sample fraction if requested
    if args.sample < 1.0 and len(texts) > 1000:
        import random
        random.seed(42)
        paired = list(zip(texts, labels))
        random.shuffle(paired)
        n = max(500, int(len(paired) * args.sample))
        paired = paired[:n]
        texts, labels = zip(*paired)
        texts, labels = list(texts), list(labels)
        logger.info(f"Sampled {len(texts):,} rows (fraction={args.sample})")

    max_seconds = args.max_minutes * 60.0

    saved_path = train(
        texts=texts,
        labels=labels,
        device=device,
        max_seconds=max_seconds,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.lr,
    )

    print()
    print("Next steps:")
    print("  • Start the API:       python -m uvicorn src.api.main:app --port 8000 --reload")
    print("  • Start the dashboard: python -m streamlit run src/dashboard/app.py")
    print("  • Or run everything:   python run.py")
    print()


if __name__ == "__main__":
    main()