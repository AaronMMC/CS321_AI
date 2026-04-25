#!/usr/bin/env python3
"""
scripts/download_datasets.py  — UPDATED

Downloads external phishing / spam datasets AND optionally merges
researcher Gmail data (collected via src/data/gmail_collector.py)
into the final training/validation/test splits.

Usage examples
--------------
# Public datasets only (same as before)
python scripts/download_datasets.py --all
python scripts/download_datasets.py --all --sample 0.2

# Include Gmail data from two researchers
python scripts/download_datasets.py --all \\
    --gmail alice@gmail.com bob@gmail.com \\
    --gmail-max 300

# Build training_data.csv from already-downloaded files + existing Gmail CSVs
python scripts/download_datasets.py --train \\
    --gmail-csv data/raw/gmail_researcher_*.csv

# Preview one public dataset
python scripts/download_datasets.py --preview enron_spam
"""

import io
import sys
import glob
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

# ── Paths ──────────────────────────────────────────────────────────────────────
DATA_DIR      = Path(__file__).parent.parent / "data"
RAW_DIR       = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
RAW_DIR.mkdir(parents=True, exist_ok=True)
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

_ROKI = "https://raw.githubusercontent.com/rokibulroni/Phishing-Email-Dataset/main"

# ── Dataset registry (unchanged from original) ─────────────────────────────────
DATASETS: Dict[str, Dict] = {

    "enron_spam": {
        "url":        "https://github.com/MWiechmann/enron_spam_data/raw/master/enron_spam_data.zip",
        "filename":   "enron_spam_data.csv",
        "format":     "zip",
        "zip_member": "enron_spam_data.csv",
        "description": "Enron ham/spam  — 33k emails",
        "size_mb": 12,
        "text_col":  None,
        "label_col": "Spam/Ham",
        "label_map": {"spam": 1, "ham": 0},
    },
    "nazario": {
        "url":        f"{_ROKI}/Nazario.csv",
        "filename":   "nazario.csv",
        "format":     "csv",
        "description": "Nazario phishing corpus",
        "size_mb": 4,
        "text_col":  None,
        "label_col": "label",
        "label_map": {"phishing": 1, "legitimate": 0},
    },
    "spamassassin": {
        "url":        f"{_ROKI}/SpamAssasin.csv",
        "filename":   "spamassassin.csv",
        "format":     "csv",
        "description": "SpamAssassin corpus",
        "size_mb": 5,
        "text_col":  None,
        "label_col": "label",
        "label_map": {"phishing": 1, "spam": 1, "legitimate": 0, "ham": 0},
    },
    "nigerian_fraud": {
        "url":        f"{_ROKI}/Nigerian_Fraud.csv",
        "filename":   "nigerian_fraud.csv",
        "format":     "csv",
        "description": "Nigerian fraud corpus",
        "size_mb": 3,
        "text_col":  None,
        "label_col": "label",
        "label_map": {"phishing": 1, "spam": 1, "fraud": 1,
                      "legitimate": 0, "ham": 0},
    },
    "ceas_08": {
        "url":        f"{_ROKI}/CEAS_08.csv",
        "filename":   "ceas_08.csv",
        "format":     "csv",
        "description": "CEAS 2008 spam challenge",
        "size_mb": 6,
        "text_col":  None,
        "label_col": "label",
        "label_map": {"phishing": 1, "spam": 1, "legitimate": 0, "ham": 0},
    },
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


# ══════════════════════════════════════════════════════════════════════════════
class DatasetDownloader:

    # ── Download public datasets ──────────────────────────────────────────────

    def download(self, key: str) -> Optional[Path]:
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

    # ── NEW: Collect Gmail data live ──────────────────────────────────────────

    def collect_gmail(
        self,
        researcher_emails : List[str],
        max_per_account   : int = 300,
        anonymize         : bool = True,
    ) -> Optional[Path]:
        """
        Trigger live Gmail collection for the given researcher accounts.
        Requires google-auth libraries and config/gmail_credentials.json.
        Returns the path to the combined CSV, or None on failure.
        """
        try:
            from src.data.gmail_collector import collect_from_multiple_researchers
        except ImportError as exc:
            logger.error(f"Could not import gmail_collector: {exc}")
            return None

        logger.info(f"\nCollecting Gmail data from {len(researcher_emails)} account(s) …")
        return collect_from_multiple_researchers(
            researcher_emails=researcher_emails,
            max_per_account=max_per_account,
            anonymize=anonymize,
        )

    # ── NEW: Load pre-existing Gmail CSVs ────────────────────────────────────

    def load_gmail_csvs(self, patterns: List[str]) -> Optional[pd.DataFrame]:
        """
        Load one or more already-exported Gmail CSV files (glob patterns OK).

        Example patterns: ["data/raw/gmail_*.csv"]

        Each CSV must have at least 'text' and 'label' columns.
        Returns a combined DataFrame or None if nothing was found.
        """
        frames = []
        for pattern in patterns:
            for path in sorted(Path(".").glob(pattern)):
                try:
                    df = pd.read_csv(path)
                    if "text" not in df.columns or "label" not in df.columns:
                        logger.warning(f"[gmail] {path} missing text/label columns — skipping")
                        continue
                    df["source"] = df.get("source", f"gmail_file:{path.name}")
                    frames.append(df[["text", "label", "source"]])
                    logger.info(f"[gmail] loaded {path.name}  ({len(df)} rows)")
                except Exception as exc:
                    logger.warning(f"[gmail] could not load {path}: {exc}")

        if not frames:
            logger.warning("[gmail] No Gmail CSV files found matching the given patterns.")
            return None

        combined = pd.concat(frames, ignore_index=True)
        logger.success(
            f"[gmail] Total from files: {len(combined)} rows  "
            f"({int(combined['label'].sum())} phishing / "
            f"{len(combined) - int(combined['label'].sum())} legit)"
        )
        return combined

    # ── Build training_data.csv (updated to include Gmail) ───────────────────

    def create_training_data(
        self,
        sample_frac       : float = 1.0,
        gmail_df          : Optional[pd.DataFrame] = None,
        gmail_weight      : float = 1.0,
    ) -> Path:
        """
        Load every downloaded public CSV + optional Gmail data,
        normalise to (text, label), concatenate, split 70/10/20,
        and save to data/processed/*.csv.

        Args:
            sample_frac  : Fraction of public data to use (1.0 = all).
            gmail_df     : Pre-loaded Gmail DataFrame (text, label, source).
                           If None, only public datasets are used.
            gmail_weight : Repeat Gmail rows this many times so they are
                           proportionally represented despite being smaller.
                           1.0 = no up-weighting; 2.0 = doubled.
        """
        frames: List[pd.DataFrame] = []

        # ── Public datasets ───────────────────────────────────────────────
        for key, cfg in DATASETS.items():
            path = RAW_DIR / cfg["filename"]
            if not path.exists() or path.stat().st_size < 1024:
                logger.warning(f"[{key}] not found or empty — skipping")
                continue
            try:
                df   = pd.read_csv(path, low_memory=False)
                norm = _normalise(df, cfg, key)
                if norm is not None and len(norm) > 0:
                    norm["source"] = key
                    frames.append(norm[["text", "label", "source"]])
                    n_phish = int(norm["label"].sum())
                    logger.info(
                        f"[{key}] {len(norm):,} rows  "
                        f"({n_phish:,} phishing / {len(norm)-n_phish:,} legit)"
                    )
            except Exception as exc:
                logger.error(f"[{key}] load error: {exc}")

        # ── Gmail data ────────────────────────────────────────────────────
        if gmail_df is not None and len(gmail_df) > 0:
            # Repeat rows to up-weight researcher emails if requested
            if gmail_weight != 1.0:
                repeats = max(1, round(gmail_weight))
                gmail_df = pd.concat([gmail_df] * repeats, ignore_index=True)

            frames.append(gmail_df[["text", "label", "source"]])
            n_phish = int(gmail_df["label"].sum())
            logger.info(
                f"[gmail] {len(gmail_df):,} rows (after weighting ×{gmail_weight})  "
                f"({n_phish:,} phishing / {len(gmail_df)-n_phish:,} legit)"
            )
        else:
            logger.info("[gmail] No Gmail data included in this build.")

        if not frames:
            logger.warning("No usable datasets — using synthetic fallback")
            return _create_synthetic()

        combined = (
            pd.concat(frames, ignore_index=True)
            .dropna(subset=["text", "label"])
            .assign(label=lambda d: d["label"].astype(int))
        )
        combined = combined[combined["text"].str.strip().str.len() > 10]

        if sample_frac < 1.0:
            combined = combined.sample(frac=sample_frac, random_state=42)

        combined = combined.sample(frac=1, random_state=42).reset_index(drop=True)

        # ── 70 / 10 / 20 stratified split ─────────────────────────────────
        from sklearn.model_selection import train_test_split

        train_val, test = train_test_split(
            combined, test_size=0.20, random_state=42,
            stratify=combined["label"],
        )
        train, val = train_test_split(
            train_val, test_size=0.125, random_state=42,
            stratify=train_val["label"],
        )

        # ── Save ───────────────────────────────────────────────────────────
        combined.to_csv(PROCESSED_DIR / "training_data.csv",  index=False)
        train.to_csv(   PROCESSED_DIR / "train.csv",          index=False)
        val.to_csv(     PROCESSED_DIR / "validation.csv",     index=False)
        test.to_csv(    PROCESSED_DIR / "test.csv",           index=False)

        # Save a Gmail-only test set so you can evaluate on researcher emails
        # independently from the main public-dataset test split
        if gmail_df is not None:
            gmail_test = gmail_df[gmail_df.get("split", "train") == "test"] \
                if "split" in gmail_df.columns \
                else gmail_df.sample(frac=0.2, random_state=42)
            gmail_test[["text", "label", "source"]].to_csv(
                PROCESSED_DIR / "gmail_test.csv", index=False
            )
            logger.info(f"[gmail] Held-out Gmail test set → data/processed/gmail_test.csv  ({len(gmail_test)} rows)")

        dist = combined["label"].value_counts().to_dict()
        logger.success(f"\ntraining_data.csv  — {len(combined):,} total rows")
        logger.info(f"  label 0 (legit)   : {dist.get(0, 0):,}")
        logger.info(f"  label 1 (phishing): {dist.get(1, 0):,}")
        logger.info(f"  train={len(train):,}  val={len(val):,}  test={len(test):,}")

        # ── Source breakdown ────────────────────────────────────────────────
        if "source" in combined.columns:
            logger.info("\nData source breakdown:")
            for src, grp in combined.groupby("source"):
                pct = len(grp) / len(combined) * 100
                logger.info(f"  {src:<30} {len(grp):>7,} rows  ({pct:.1f}%)")

        return PROCESSED_DIR / "training_data.csv"


# ══════════════════════════════════════════════════════════════════════════════
# Module-level helpers (unchanged)
# ══════════════════════════════════════════════════════════════════════════════

def _extract_zip(raw_bytes: bytes, member_name: str, out_path: Path) -> Path:
    with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
        names = zf.namelist()
        match = next((n for n in names if n.lower() == member_name.lower()), None)
        if match is None:
            match = next((n for n in names if member_name.lower() in n.lower()), None)
        if match is None:
            raise FileNotFoundError(f"'{member_name}' not in zip. Contents: {names}")
        out_path.write_bytes(zf.read(match))
    return out_path


def _normalise(df: pd.DataFrame, cfg: Dict, key: str) -> Optional[pd.DataFrame]:
    cols_lower = {c.lower(): c for c in df.columns}
    df = df.copy()

    # text column
    if cfg["text_col"] and cfg["text_col"].lower() in cols_lower:
        df["text"] = df[cols_lower[cfg["text_col"].lower()]].astype(str)
    else:
        subject_col = next((cols_lower[c] for c in cols_lower if "subject" in c), None)
        body_col = next(
            (cols_lower[c] for c in cols_lower
             if c in ("body", "message", "content", "text", "email text", "email_text")), None
        )
        if subject_col and body_col:
            df["text"] = (
                df[subject_col].fillna("").astype(str) + " "
                + df[body_col].fillna("").astype(str)
            ).str.strip()
        elif body_col:
            df["text"] = df[body_col].fillna("").astype(str)
        elif subject_col:
            df["text"] = df[subject_col].fillna("").astype(str)
        else:
            logger.warning(f"[{key}] no usable text column — skipping. Columns: {list(df.columns)}")
            return None

    # label column
    label_col = next((cols_lower[c] for c in cols_lower if c == cfg["label_col"].lower()), None)
    if label_col is None:
        logger.warning(f"[{key}] label column '{cfg['label_col']}' not found — skipping.")
        return None

    if cfg["label_map"]:
        df["label"] = (
            df[label_col].astype(str).str.lower().str.strip().map(cfg["label_map"])
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
    logger.warning("Generating synthetic training data as fallback …")
    legitimate = [
        "Meeting scheduled for tomorrow at 10am in Conference Room A",
        "Please find attached the quarterly financial report for Q1",
        "Your leave request for next week has been approved",
        "Reminder: Team building event this Friday at 3pm",
        "Project update: all milestones achieved on schedule",
    ]
    phishing = [
        "URGENT: Your account will be suspended. Click here to verify now",
        "You have won 1000000 dollars claim your prize provide bank details",
        "GCash account limited. Verify immediately at http://bit.ly/gcash",
        "Security Alert: Unusual login detected. Confirm identity",
        "Netflix subscription expiring. Update payment http://bit.ly/update",
    ]
    texts  = (legitimate + phishing) * 100
    labels = ([0] * len(legitimate) + [1] * len(phishing)) * 100
    df     = pd.DataFrame({"text": texts, "label": labels, "source": "synthetic"})
    path   = PROCESSED_DIR / "synthetic_training_data.csv"
    df.to_csv(path, index=False)
    logger.success(f"Synthetic: {len(df):,} rows -> {path}")
    return path


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Download datasets and optionally include researcher Gmail data"
    )
    # existing args
    parser.add_argument("--dataset", choices=list(DATASETS),
                        help="Download one specific public dataset")
    parser.add_argument("--all",  action="store_true",
                        help="Download all public datasets")
    parser.add_argument("--preview", choices=list(DATASETS),
                        help="Preview first 5 rows of a downloaded dataset")
    parser.add_argument("--train", action="store_true",
                        help="Build training_data.csv from already-downloaded files")
    parser.add_argument("--sample", type=float, default=1.0,
                        help="Fraction of public data to use (default: 1.0)")

    # NEW: Gmail args
    parser.add_argument(
        "--gmail", nargs="+", metavar="EMAIL",
        help="Researcher Gmail addresses to collect live data from. "
             "Requires config/gmail_credentials.json."
    )
    parser.add_argument(
        "--gmail-max", type=int, default=300,
        help="Max emails per category per Gmail account (default: 300)"
    )
    parser.add_argument(
        "--gmail-csv", nargs="+", metavar="GLOB",
        help="Glob pattern(s) for already-exported Gmail CSVs, e.g. "
             "'data/raw/gmail_*.csv'. These are merged into training_data.csv."
    )
    parser.add_argument(
        "--gmail-weight", type=float, default=1.0,
        help="Up-weight Gmail rows by this factor to compensate for smaller size "
             "(default: 1.0, i.e. no weighting)"
    )
    parser.add_argument(
        "--no-anonymize", action="store_true",
        help="Skip PII scrubbing when collecting Gmail (not recommended)"
    )

    args = parser.parse_args()
    dl = DatasetDownloader()

    # ── Resolve Gmail data ──────────────────────────────────────────────────
    gmail_df = None

    if args.gmail:
        # Live collection
        combined_path = dl.collect_gmail(
            researcher_emails=args.gmail,
            max_per_account=args.gmail_max,
            anonymize=not args.no_anonymize,
        )
        if combined_path and combined_path.exists():
            gmail_df = pd.read_csv(combined_path)

    if args.gmail_csv:
        # Load from existing files
        loaded = dl.load_gmail_csvs(args.gmail_csv)
        if loaded is not None:
            gmail_df = pd.concat([gmail_df, loaded], ignore_index=True) \
                if gmail_df is not None else loaded

    # ── Main actions ────────────────────────────────────────────────────────
    if args.all:
        results = dl.download_all()
        bad = [k for k, v in results.items() if not v]
        if bad:
            logger.warning(f"Failed downloads: {bad}")
        dl.create_training_data(
            sample_frac=args.sample,
            gmail_df=gmail_df,
            gmail_weight=args.gmail_weight,
        )

    elif args.dataset:
        dl.download(args.dataset)
        if args.train:
            dl.create_training_data(
                sample_frac=args.sample,
                gmail_df=gmail_df,
                gmail_weight=args.gmail_weight,
            )

    elif args.preview:
        dl.preview(args.preview)

    elif args.train:
        dl.create_training_data(
            sample_frac=args.sample,
            gmail_df=gmail_df,
            gmail_weight=args.gmail_weight,
        )

    else:
        parser.print_help()
        print("\nExamples:")
        print("  # Public datasets only")
        print("  python scripts/download_datasets.py --all")
        print()
        print("  # Public datasets + live Gmail collection")
        print("  python scripts/download_datasets.py --all \\")
        print("      --gmail alice@gmail.com bob@gmail.com --gmail-max 300")
        print()
        print("  # Build from existing downloads + pre-exported Gmail CSVs")
        print("  python scripts/download_datasets.py --train \\")
        print("      --gmail-csv 'data/raw/gmail_*.csv' --gmail-weight 2.0")


if __name__ == "__main__":
    main()