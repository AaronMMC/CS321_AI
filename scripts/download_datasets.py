#!/usr/bin/env python3
"""
Dataset download script for Email Security Gateway.
All sources verified working as of April 2026.

Every dataset comes from one of two reliable sources:
  1. github.com/MWiechmann/enron_spam_data   (zip -> CSV)
  2. github.com/rokibulroni/Phishing-Email-Dataset  (multiple CSVs)

Usage:
    python scripts/download_datasets.py --all
    python scripts/download_datasets.py --all --sample 0.2
    python scripts/download_datasets.py --train --sample 0.5
    python scripts/download_datasets.py --preview enron_spam
"""

import io
import sys
import zipfile
import argparse
from pathlib import Path
from typing import Dict, List, Optional

import requests
import pandas as pd
from loguru import logger

# add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

logger.remove()
logger.add(
    sys.stdout, level="INFO",
    format="<green>{time:HH:mm:ss}</green> | <level>{level:<8}</level> | {message}",
)

# paths
DATA_DIR      = Path(__file__).parent.parent / "data"
RAW_DIR       = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
RAW_DIR.mkdir(parents=True, exist_ok=True)
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

# base URL for the rokibulroni repo (all files confirmed present)
_ROKI = "https://raw.githubusercontent.com/rokibulroni/Phishing-Email-Dataset/main"

# ---------------------------------------------------------------------------
# Dataset registry
#
#  format   : "csv"  -> download directly
#             "zip"  -> download zip, extract zip_member from it
#  text_col : name of column to use as text (None = auto-detect subject+body)
#  label_col: name of column to use as label
#  label_map: maps raw string values -> 0/1   (empty dict = already numeric)
# ---------------------------------------------------------------------------
DATASETS: Dict[str, Dict] = {

    # Enron 33k ham/spam (MWiechmann, packaged as zip)
    "enron_spam": {
        "url":        "https://github.com/MWiechmann/enron_spam_data/raw/master/enron_spam_data.zip",
        "filename":   "enron_spam_data.csv",
        "format":     "zip",
        "zip_member": "enron_spam_data.csv",
        "description": "Enron ham/spam  — 33k emails",
        "size_mb": 12,
        # original columns: Subject | Message | Spam/Ham | Date
        "text_col":  None,          # -> Subject + Message combined
        "label_col": "Spam/Ham",
        "label_map": {"spam": 1, "ham": 0},
    },

    # Nazario phishing corpus
    "nazario": {
        "url":        f"{_ROKI}/Nazario.csv",
        "filename":   "nazario.csv",
        "format":     "csv",
        "description": "Nazario phishing corpus  — verified phishing emails",
        "size_mb": 4,
        "text_col":  None,
        "label_col": "label",
        "label_map": {"phishing": 1, "legitimate": 0},
    },

    # SpamAssassin corpus
    "spamassassin": {
        "url":        f"{_ROKI}/SpamAssasin.csv",
        "filename":   "spamassassin.csv",
        "format":     "csv",
        "description": "SpamAssassin corpus  — spam / legitimate",
        "size_mb": 5,
        "text_col":  None,
        "label_col": "label",
        "label_map": {"phishing": 1, "spam": 1, "legitimate": 0, "ham": 0},
    },

    # Nigerian / advance-fee fraud emails
    "nigerian_fraud": {
        "url":        f"{_ROKI}/Nigerian_Fraud.csv",
        "filename":   "nigerian_fraud.csv",
        "format":     "csv",
        "description": "Nigerian fraud / advance-fee email corpus",
        "size_mb": 3,
        "text_col":  None,
        "label_col": "label",
        "label_map": {"phishing": 1, "spam": 1, "fraud": 1,
                      "legitimate": 0, "ham": 0},
    },

    # CEAS 2008 live spam challenge
    "ceas_08": {
        "url":        f"{_ROKI}/CEAS_08.csv",
        "filename":   "ceas_08.csv",
        "format":     "csv",
        "description": "CEAS 2008 spam challenge corpus",
        "size_mb": 6,
        "text_col":  None,
        "label_col": "label",
        "label_map": {"phishing": 1, "spam": 1, "legitimate": 0, "ham": 0},
    },

    # Enron (rokibulroni preprocessing — different column layout)
    "enron_roki": {
        "url":        f"{_ROKI}/Enron.csv",
        "filename":   "enron_roki.csv",
        "format":     "csv",
        "description": "Enron corpus (rokibulroni version)",
        "size_mb": 8,
        "text_col":  None,
        "label_col": "label",
        "label_map": {"phishing": 1, "spam": 1, "legitimate": 0, "ham": 0},
    },
}


class DatasetDownloader:

    # ------------------------------------------------------------------
    # Download
    # ------------------------------------------------------------------

    def download(self, key: str) -> Optional[Path]:
        """Download one dataset by key. Returns local path or None."""
        if key not in DATASETS:
            logger.error(f"Unknown key '{key}'. Available: {list(DATASETS)}")
            return None

        cfg      = DATASETS[key]
        out_path = RAW_DIR / cfg["filename"]

        if out_path.exists() and out_path.stat().st_size > 1024:
            logger.info(f"[{key}] already present ({out_path.stat().st_size // 1024} KB) — skipping")
            return out_path

        logger.info(f"[{key}] {cfg['description']}  (~{cfg['size_mb']} MB)")
        logger.info(f"[{key}] {cfg['url']}")

        try:
            resp = requests.get(cfg["url"], timeout=90, stream=True)
            resp.raise_for_status()
            raw = b"".join(resp.iter_content(chunk_size=16_384))
        except requests.HTTPError as exc:
            logger.error(f"[{key}] HTTP {exc.response.status_code}: {exc}")
            return None
        except Exception as exc:
            logger.error(f"[{key}] Download error: {exc}")
            return None

        try:
            if cfg["format"] == "zip":
                out_path = _extract_zip(raw, cfg["zip_member"], out_path)
            else:
                out_path.write_bytes(raw)
        except Exception as exc:
            logger.error(f"[{key}] Save error: {exc}")
            return None

        mb = out_path.stat().st_size / 1_048_576
        logger.success(f"[{key}] Saved -> {out_path}  ({mb:.1f} MB)")
        return out_path

    def download_all(self) -> Dict[str, Optional[Path]]:
        return {k: self.download(k) for k in DATASETS}

    # ------------------------------------------------------------------
    # Preview
    # ------------------------------------------------------------------

    def preview(self, key: str):
        cfg  = DATASETS[key]
        path = RAW_DIR / cfg["filename"]
        if not path.exists():
            logger.error(f"[{key}] not downloaded yet.")
            return
        try:
            df = pd.read_csv(path, nrows=5)
            logger.info(f"[{key}] columns: {df.columns.tolist()}")
            print(df.to_string())
        except Exception as exc:
            logger.error(f"[{key}] read error: {exc}")

    # ------------------------------------------------------------------
    # Build training_data.csv
    # ------------------------------------------------------------------

    def create_training_data(self, sample_frac: float = 1.0) -> Path:
        """
        Load every downloaded CSV, normalise to (text, label),
        concatenate, split into train/val/test CSVs, and save.
        Uses synthetic fallback if nothing was downloaded.
        """
        frames: List[pd.DataFrame] = []

        for key, cfg in DATASETS.items():
            path = RAW_DIR / cfg["filename"]
            if not path.exists():
                logger.warning(f"[{key}] not found — skipping")
                continue
            if path.stat().st_size < 1024:
                logger.warning(f"[{key}] file looks empty — skipping")
                continue

            try:
                df   = pd.read_csv(path, low_memory=False)
                norm = _normalise(df, cfg, key)
                if norm is not None and len(norm) > 0:
                    frames.append(norm[["text", "label"]])
                    n_phish = int(norm["label"].sum())
                    n_legit = len(norm) - n_phish
                    logger.info(
                        f"[{key}] {len(norm):,} rows  "
                        f"({n_phish:,} phishing / {n_legit:,} legit)"
                    )
            except Exception as exc:
                logger.error(f"[{key}] load error: {exc}")

        if not frames:
            logger.warning("No usable datasets — using synthetic fallback")
            return _create_synthetic()

        combined = (
            pd.concat(frames, ignore_index=True)
            .dropna(subset=["text", "label"])
            .assign(label=lambda d: d["label"].astype(int))
        )
        # drop trivially empty rows
        combined = combined[combined["text"].str.strip().str.len() > 10]

        if sample_frac < 1.0:
            combined = combined.sample(frac=sample_frac, random_state=42)

        combined = combined.sample(frac=1, random_state=42).reset_index(drop=True)

        # train / val / test split (70 / 10 / 20)
        from sklearn.model_selection import train_test_split

        train_val, test = train_test_split(
            combined, test_size=0.20, random_state=42,
            stratify=combined["label"],
        )
        train, val = train_test_split(
            train_val, test_size=0.125, random_state=42,
            stratify=train_val["label"],
        )

        combined.to_csv(PROCESSED_DIR / "training_data.csv",  index=False)
        train.to_csv(   PROCESSED_DIR / "train.csv",          index=False)
        val.to_csv(     PROCESSED_DIR / "validation.csv",     index=False)
        test.to_csv(    PROCESSED_DIR / "test.csv",           index=False)

        dist = combined["label"].value_counts().to_dict()
        logger.success(f"training_data.csv  — {len(combined):,} total rows")
        logger.info(   f"  label 0 (legit)   : {dist.get(0, 0):,}")
        logger.info(   f"  label 1 (phishing): {dist.get(1, 0):,}")
        logger.info(   f"  train={len(train):,}  val={len(val):,}  test={len(test):,}")

        return PROCESSED_DIR / "training_data.csv"


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _extract_zip(raw_bytes: bytes, member_name: str, out_path: Path) -> Path:
    """Extract one named file from a zip held in memory."""
    with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
        names = zf.namelist()
        match = next((n for n in names if n.lower() == member_name.lower()), None)
        if match is None:
            match = next((n for n in names if member_name.lower() in n.lower()), None)
        if match is None:
            raise FileNotFoundError(
                f"'{member_name}' not found in zip. Contents: {names}"
            )
        out_path.write_bytes(zf.read(match))
    return out_path


def _normalise(df: pd.DataFrame, cfg: Dict, key: str) -> Optional[pd.DataFrame]:
    """Map raw columns -> standard (text, label 0/1) DataFrame."""
    cols_lower = {c.lower(): c for c in df.columns}
    df = df.copy()

    # ── text column ──────────────────────────────────────────────────────────
    if cfg["text_col"] and cfg["text_col"].lower() in cols_lower:
        df["text"] = df[cols_lower[cfg["text_col"].lower()]].astype(str)
    else:
        subject_col = next(
            (cols_lower[c] for c in cols_lower if "subject" in c), None
        )
        body_col = next(
            (cols_lower[c] for c in cols_lower
             if c in ("body", "message", "content", "text",
                      "email text", "email_text")), None
        )
        if subject_col and body_col:
            df["text"] = (
                df[subject_col].fillna("").astype(str)
                + " "
                + df[body_col].fillna("").astype(str)
            ).str.strip()
        elif body_col:
            df["text"] = df[body_col].fillna("").astype(str)
        elif subject_col:
            df["text"] = df[subject_col].fillna("").astype(str)
        else:
            logger.warning(
                f"[{key}] no usable text column — skipping. "
                f"Columns: {list(df.columns)}"
            )
            return None

    # ── label column ─────────────────────────────────────────────────────────
    label_col = next(
        (cols_lower[c] for c in cols_lower
         if c == cfg["label_col"].lower()), None
    )
    if label_col is None:
        logger.warning(
            f"[{key}] label column '{cfg['label_col']}' not found — skipping. "
            f"Columns: {list(df.columns)}"
        )
        return None

    if cfg["label_map"]:
        df["label"] = (
            df[label_col].astype(str).str.lower().str.strip()
            .map(cfg["label_map"])
        )
    else:
        df["label"] = pd.to_numeric(df[label_col], errors="coerce")

    before = len(df)
    df = df.dropna(subset=["text", "label"])
    df["label"] = df["label"].astype(int)
    dropped = before - len(df)
    if dropped > 0:
        logger.warning(f"[{key}] dropped {dropped} rows with null/unmapped labels")

    return df


def _create_synthetic() -> Path:
    """Minimal synthetic dataset used as a last resort."""
    logger.warning("Generating synthetic training data as fallback ...")
    legitimate = [
        "Meeting scheduled for tomorrow at 10am in Conference Room A",
        "Please find attached the quarterly financial report for Q1",
        "Your leave request for next week has been approved",
        "Reminder: Team building event this Friday at 3pm",
        "Project update: all milestones achieved on schedule",
        "Invoice #12345 for consulting services is attached",
        "Welcome to the team! Here is your onboarding schedule",
        "System maintenance scheduled for Sunday from 2am to 4am",
        "Please review the attached project proposal before Thursday",
        "The board meeting minutes from last week are now available",
    ]
    phishing = [
        "URGENT: Your account will be suspended. Click here to verify now",
        "You have won 1000000 dollars claim your prize provide bank details",
        "GCash account limited. Verify immediately at http://bit.ly/gcash",
        "Security Alert: Unusual login detected. Confirm identity http://bit.ly/login",
        "Netflix subscription expiring. Update payment http://bit.ly/update",
        "DICT email requires verification. Click link http://bit.ly/verify-now",
        "PayPal transaction disputed. Sign in now http://bit.ly/paypal",
        "HR Department: Update your payroll information immediately or lose pay",
        "Your bank account has been locked. Click here to unlock now",
        "Congratulations you are our lucky winner claim reward today",
    ]
    texts  = (legitimate + phishing) * 80
    labels = ([0] * len(legitimate) + [1] * len(phishing)) * 80

    df   = pd.DataFrame({"text": texts, "label": labels})
    path = PROCESSED_DIR / "synthetic_training_data.csv"
    df.to_csv(path, index=False)
    logger.success(f"Synthetic: {len(df):,} rows -> {path}")
    return path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Download and prepare datasets for the Email Security Gateway"
    )
    parser.add_argument("--dataset", choices=list(DATASETS),
                        help="Download one specific dataset")
    parser.add_argument("--all",  action="store_true",
                        help="Download all datasets then build training_data.csv")
    parser.add_argument("--preview", choices=list(DATASETS),
                        help="Print first 5 rows of a downloaded dataset")
    parser.add_argument("--train", action="store_true",
                        help="Build training_data.csv from already-downloaded files")
    parser.add_argument("--sample", type=float, default=1.0,
                        help="Fraction to keep, e.g. 0.2 for 20%%")
    args = parser.parse_args()

    dl = DatasetDownloader()

    if args.all:
        results = dl.download_all()
        ok  = [k for k, v in results.items() if v]
        bad = [k for k, v in results.items() if not v]
        logger.info(f"OK      : {ok}")
        if bad:
            logger.warning(f"Failed  : {bad}")
        dl.create_training_data(args.sample)

    elif args.dataset:
        dl.download(args.dataset)
        if args.train:
            dl.create_training_data(args.sample)

    elif args.preview:
        dl.preview(args.preview)

    elif args.train:
        dl.create_training_data(args.sample)

    else:
        parser.print_help()
        print("\nExamples:")
        print("  python scripts/download_datasets.py --all")
        print("  python scripts/download_datasets.py --all --sample 0.2")
        print("  python scripts/download_datasets.py --train")
        print("  python scripts/download_datasets.py --preview enron_spam")


if __name__ == "__main__":
    main()