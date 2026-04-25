"""
src/data/gmail_collector.py

Collects emails from researcher Gmail accounts via the Gmail API (OAuth2)
and exports them as labeled training / evaluation data.

REQUIREMENTS
------------
    pip install google-auth google-auth-oauthlib google-auth-httplib2 google-api-python-client

SETUP (one-time, per researcher)
---------------------------------
1.  Go to https://console.cloud.google.com/
2.  Create a project → Enable "Gmail API"
3.  OAuth consent screen → External → add your Gmail as a test user
4.  Credentials → Create OAuth client ID → Desktop app
5.  Download the JSON → save as  config/gmail_credentials.json
6.  Run this script once; a browser window opens for consent.
    The token is cached in  config/gmail_token_<hash>.json  for future runs.

PRIVACY NOTES
-------------
- Emails are stored LOCALLY only (data/raw/gmail_*.csv).
- No email body content is sent to any external service during collection.
- Researchers should only export emails they own or have explicit consent for.
- Strip personal identifiers (names, phone numbers) before committing data
  to a shared repository.  Use --anonymize flag to do this automatically.
"""

from __future__ import annotations

import re
import base64
import hashlib
import argparse
from pathlib import Path
from typing import TYPE_CHECKING, Any, List, Dict, Optional, Tuple

from loguru import logger

# ── Type-checking-only imports ─────────────────────────────────────────────────
# These lines are read by PyCharm / mypy but are NEVER executed at runtime.
# This is the standard fix for optional-dependency type hints (PEP 484).
if TYPE_CHECKING:
    from google.oauth2.credentials import Credentials

# ── Runtime imports (guarded) ──────────────────────────────────────────────────
try:
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials as _Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
    GOOGLE_API_AVAILABLE = True
except ImportError:
    GOOGLE_API_AVAILABLE = False
    logger.warning(
        "Google API client not installed. "
        "Run: pip install google-auth google-auth-oauthlib "
        "google-auth-httplib2 google-api-python-client"
    )

# ── Paths ──────────────────────────────────────────────────────────────────────
PROJECT_ROOT  = Path(__file__).parent.parent.parent
CONFIG_DIR    = PROJECT_ROOT / "config"
RAW_DIR       = PROJECT_ROOT / "data" / "raw"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"

CONFIG_DIR.mkdir(parents=True, exist_ok=True)
RAW_DIR.mkdir(parents=True, exist_ok=True)
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

CREDENTIALS = CONFIG_DIR / "gmail_credentials.json"

# Gmail API read-only scope — we never modify the researcher's mailbox
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

# ── Gmail label → our binary label ────────────────────────────────────────────
# Emails in SPAM or TRASH → phishing/spam (label 1).
# Everything in INBOX     → legitimate    (label 0).
# Researchers can also manually tag emails with the custom Gmail label
# "phishing-sample" to explicitly mark them as phishing.
SPAM_GMAIL_LABELS  = {"SPAM", "TRASH"}
PHISH_CUSTOM_LABEL = "phishing-sample"   # create this label in Gmail if desired


# ══════════════════════════════════════════════════════════════════════════════
# Authentication
# ══════════════════════════════════════════════════════════════════════════════

def _get_credentials(researcher_email: str) -> Optional[Credentials]:
    """
    Return (and if needed refresh / create) OAuth2 credentials for one account.
    Token is cached at  config/gmail_token_<hash>.json  so re-auth is rare.

    The return type  Optional[Credentials]  is resolved by PyCharm via the
    TYPE_CHECKING import above; at runtime the annotation is a lazy string
    thanks to  `from __future__ import annotations`  so no NameError occurs
    even when google-auth is not installed.

    Raises RuntimeError if the google-auth libraries are not installed.
    """
    if not GOOGLE_API_AVAILABLE:
        raise RuntimeError(
            "google-auth libraries not installed. "
            "Run: pip install google-auth google-auth-oauthlib "
            "google-auth-httplib2 google-api-python-client"
        )

    if not CREDENTIALS.exists():
        raise FileNotFoundError(
            f"Missing OAuth credentials file: {CREDENTIALS}\n"
            "Download it from Google Cloud Console → Credentials → OAuth 2.0 Client IDs."
        )

    # Hash the email so we never write the raw address to disk
    email_hash = hashlib.md5(researcher_email.encode()).hexdigest()[:12]
    token_path = CONFIG_DIR / f"gmail_token_{email_hash}.json"

    creds: Optional[Credentials] = None

    if token_path.exists():
        creds = _Credentials.from_authorized_user_file(str(token_path), SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            logger.info(f"Refreshing token for {researcher_email} …")
            creds.refresh(Request())
        else:
            logger.info(
                f"Opening browser for OAuth consent ({researcher_email}) …\n"
                "Please log in with the Gmail account you want to export."
            )
            flow = InstalledAppFlow.from_client_secrets_file(
                str(CREDENTIALS), SCOPES
            )
            creds = flow.run_local_server(port=0)

        token_path.write_text(creds.to_json())
        logger.info(f"Token cached → {token_path}")

    return creds


# ══════════════════════════════════════════════════════════════════════════════
# Email fetching
# ══════════════════════════════════════════════════════════════════════════════

class GmailCollector:
    """
    Fetches emails from a researcher's Gmail and converts them to
    (text, label) rows ready for training.
    """

    def __init__(self, researcher_email: str, anonymize: bool = True) -> None:
        """
        Args:
            researcher_email : The Gmail address to collect from.
            anonymize        : If True, strip PII from text before saving.
        """
        self.email     = researcher_email
        self.anonymize = anonymize
        # Any avoids depending on googleapiclient types at definition time
        self._service: Optional[Any] = None

    # ── Public API ────────────────────────────────────────────────────────────

    def collect(
        self,
        max_legitimate: int = 200,
        max_phishing:   int = 200,
    ) -> List[Dict]:
        """
        Fetch emails and return a list of dicts with keys:
            text    : str  — subject + body, cleaned
            label   : int  — 0 = legit, 1 = phishing/spam
            source  : str  — "gmail_<email_hash>"
            split   : str  — "train" or "test" (80 / 20 assigned here)

        Args:
            max_legitimate : cap on legitimate emails to fetch
            max_phishing   : cap on phishing/spam emails to fetch
        """
        svc  = self._get_service()
        rows: List[Dict] = []

        # Legitimate — from Inbox, excluding Spam / Trash
        logger.info(f"Fetching up to {max_legitimate} legitimate emails …")
        legit_ids = self._list_message_ids(
            svc,
            query="in:inbox -in:spam -in:trash",
            max_results=max_legitimate,
        )
        for msg_id in legit_ids:
            row = self._fetch_and_parse(svc, msg_id, label=0)
            if row:
                rows.append(row)

        # Phishing / Spam — from Spam folder or custom label
        logger.info(f"Fetching up to {max_phishing} spam/phishing emails …")
        spam_ids = self._list_message_ids(
            svc,
            query=f"in:spam OR label:{PHISH_CUSTOM_LABEL}",
            max_results=max_phishing,
        )
        for msg_id in spam_ids:
            row = self._fetch_and_parse(svc, msg_id, label=1)
            if row:
                rows.append(row)

        # Assign 80 / 20 train / test split
        import random
        random.seed(42)
        random.shuffle(rows)
        split_idx = int(len(rows) * 0.8)
        for i, row in enumerate(rows):
            row["split"] = "train" if i < split_idx else "test"

        logger.success(
            f"Collected {len(rows)} emails from {self.email}  "
            f"({sum(1 for r in rows if r['label'] == 0)} legit / "
            f"{sum(1 for r in rows if r['label'] == 1)} phishing)"
        )
        return rows

    def save_to_csv(self, rows: List[Dict], tag: str = "") -> Tuple[Path, Path]:
        """
        Save collected rows to:
            data/raw/gmail_<tag>_<hash>_train.csv
            data/raw/gmail_<tag>_<hash>_test.csv

        Returns (train_path, test_path).
        """
        import pandas as pd

        email_hash = hashlib.md5(self.email.encode()).hexdigest()[:8]
        prefix     = f"gmail_{tag}_{email_hash}" if tag else f"gmail_{email_hash}"

        df_all   = pd.DataFrame(rows)
        df_train = df_all[df_all["split"] == "train"][["text", "label", "source"]]
        df_test  = df_all[df_all["split"] == "test"][["text", "label", "source"]]

        train_path = RAW_DIR / f"{prefix}_train.csv"
        test_path  = RAW_DIR / f"{prefix}_test.csv"

        df_train.to_csv(train_path, index=False)
        df_test.to_csv(test_path,  index=False)

        logger.success(f"Train: {train_path}  ({len(df_train)} rows)")
        logger.success(f"Test : {test_path}   ({len(df_test)} rows)")
        return train_path, test_path

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _get_service(self) -> Any:
        """Lazy-load and return the authenticated Gmail API service object."""
        if self._service is None:
            creds = _get_credentials(self.email)
            self._service = build(
                "gmail", "v1", credentials=creds, cache_discovery=False
            )
        return self._service

    def _list_message_ids(
        self,
        svc: Any,
        query: str,
        max_results: int,
    ) -> List[str]:
        """Return up to max_results message IDs matching the Gmail search query."""
        ids:   List[str]      = []
        token: Optional[str]  = None

        while len(ids) < max_results:
            batch_size            = min(500, max_results - len(ids))
            kwargs: Dict[str, Any] = dict(userId="me", q=query, maxResults=batch_size)
            if token:
                kwargs["pageToken"] = token

            resp  = svc.users().messages().list(**kwargs).execute()
            msgs  = resp.get("messages", [])
            ids  += [m["id"] for m in msgs]
            token = resp.get("nextPageToken")

            if not token or not msgs:
                break

        return ids[:max_results]

    def _fetch_and_parse(
        self,
        svc: Any,
        msg_id: str,
        label: int,
    ) -> Optional[Dict]:
        """Fetch one message and return a cleaned row dict, or None on error."""
        try:
            msg = svc.users().messages().get(
                userId="me", id=msg_id, format="full"
            ).execute()
        except Exception as exc:
            logger.warning(f"Could not fetch message {msg_id}: {exc}")
            return None

        headers = {
            h["name"].lower(): h["value"]
            for h in msg.get("payload", {}).get("headers", [])
        }

        subject = headers.get("subject", "")
        body    = self._extract_body(msg.get("payload", {}))

        if not subject and not body:
            return None

        combined = f"{subject} {body}".strip()

        if self.anonymize:
            combined = self._anonymize(combined)

        # Discard rows that are too short after anonymization
        if len(combined.split()) < 5:
            return None

        email_hash = hashlib.md5(self.email.encode()).hexdigest()[:8]
        return {
            "text":   combined,
            "label":  label,
            "source": f"gmail_{email_hash}",
            "split":  "train",   # overwritten by collect() after shuffling
        }

    def _extract_body(self, payload: Dict, depth: int = 0) -> str:
        """Recursively extract plain-text body from a Gmail API payload dict."""
        if depth > 5:
            return ""

        mime      = payload.get("mimeType", "")
        body_data = payload.get("body", {}).get("data", "")

        if mime == "text/plain" and body_data:
            try:
                return base64.urlsafe_b64decode(body_data).decode(
                    "utf-8", errors="ignore"
                )
            except Exception:
                return ""

        # Recurse into multipart parts
        parts = payload.get("parts", [])
        texts = [self._extract_body(p, depth + 1) for p in parts]
        return " ".join(t for t in texts if t)

    # ── Anonymization ─────────────────────────────────────────────────────────

    @staticmethod
    def _anonymize(text: str) -> str:
        """
        Replace common PII patterns with placeholders.
        Best-effort — researchers should review output before committing
        to any shared repository.
        """
        # Email addresses
        text = re.sub(
            r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
            "[EMAIL]",
            text,
        )
        # Philippine mobile numbers (09xx or +639xx)
        text = re.sub(r"(\+?63|0)9\d{9}", "[PHONE]", text)
        # Generic phone numbers
        text = re.sub(r"\b\d{3}[-.\s]\d{3,4}[-.\s]\d{4}\b", "[PHONE]", text)
        # URLs
        text = re.sub(r"https?://\S+", "[URL]", text)
        # Collapse extra whitespace
        text = re.sub(r"\s+", " ", text).strip()
        return text


# ══════════════════════════════════════════════════════════════════════════════
# Multi-researcher batch collection
# ══════════════════════════════════════════════════════════════════════════════

def collect_from_multiple_researchers(
    researcher_emails: List[str],
    max_per_account:   int  = 300,
    anonymize:         bool = True,
) -> Optional[Path]:
    """
    Collect from every researcher's Gmail, combine all rows, and write to
    data/processed/gmail_combined.csv  (columns: text, label, source).

    Returns the path to the combined CSV, or None if nothing was collected.
    """
    import pandas as pd

    all_frames: List[pd.DataFrame] = []

    for email in researcher_emails:
        logger.info(f"\n{'=' * 60}")
        logger.info(f"Collecting from: {email}")
        logger.info(f"{'=' * 60}")
        try:
            collector = GmailCollector(email, anonymize=anonymize)
            rows      = collector.collect(
                max_legitimate=max_per_account,
                max_phishing=max_per_account,
            )
            collector.save_to_csv(rows, tag="researcher")
            all_frames.append(pd.DataFrame(rows))
        except Exception as exc:
            logger.error(f"Failed for {email}: {exc}")

    if not all_frames:
        logger.warning("No Gmail data collected from any account.")
        return None

    combined = pd.concat(all_frames, ignore_index=True)
    out_path = PROCESSED_DIR / "gmail_combined.csv"
    combined[["text", "label", "source"]].to_csv(out_path, index=False)

    n_phish = int(combined["label"].sum())
    n_legit = len(combined) - n_phish
    logger.success(
        f"\nCombined Gmail dataset: {len(combined)} rows  "
        f"({n_legit} legit / {n_phish} phishing)\n"
        f"Saved → {out_path}"
    )
    return out_path


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect researcher Gmail emails for model training data"
    )
    parser.add_argument(
        "--emails", nargs="+", required=True,
        metavar="GMAIL",
        help=(
            "One or more researcher Gmail addresses, "
            "e.g. --emails alice@gmail.com bob@gmail.com"
        ),
    )
    parser.add_argument(
        "--max", type=int, default=300,
        help="Max emails per category (legit / phishing) per account (default: 300)",
    )
    parser.add_argument(
        "--no-anonymize", action="store_true",
        help="Skip PII anonymization (not recommended for shared repos)",
    )
    args = parser.parse_args()

    if not GOOGLE_API_AVAILABLE:
        print(
            "\nERROR: Google API libraries not installed.\n"
            "Run: pip install google-auth google-auth-oauthlib "
            "google-auth-httplib2 google-api-python-client\n"
        )
        return

    collect_from_multiple_researchers(
        researcher_emails=args.emails,
        max_per_account=args.max,
        anonymize=not args.no_anonymize,
    )


if __name__ == "__main__":
    main()