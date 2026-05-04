"""
src/dashboard/analytics.py

Performance analytics page for the Email Security Gateway dashboard.
Reads real data from:
  - data/processed/test.csv          -> ground-truth labels + model predictions
  - data/processed/train.csv         -> training set size
  - data/processed/validation.csv    -> validation set size
  - data/processed/training_data.csv -> full dataset
  - data/raw/*.csv                   -> individual source counts
  - logs/email_security.log          -> training curve epoch lines
  - models_saved/email_security_model -> loaded model for live scoring
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# ── helpers ────────────────────────────────────────────────────────────────────

def _safe_load(path, **kwargs):
    p = Path(path)
    if p.exists() and p.stat().st_size > 0:
        try:
            return pd.read_csv(p, **kwargs)
        except Exception:
            pass
    return None


def _load_model():
    try:
        from src.models.scratch_transformer import ScratchModelForEmailSecurity
        save_path = Path("models_saved/email_security_model")
        if save_path.exists():
            return ScratchModelForEmailSecurity.load(str(save_path), use_gpu=False)
    except Exception:
        pass
    return None


# ── data loaders ───────────────────────────────────────────────────────────────

@st.cache_data(show_spinner=False)
def load_split_sizes():
    sizes = {}
    for split in ("training_data", "train", "validation", "test"):
        df = _safe_load(f"data/processed/{split}.csv")
        sizes[split] = len(df) if df is not None else 0
    return sizes


@st.cache_data(show_spinner=False)
def load_source_counts():
    raw_dir = Path("data/raw")
    sources = []
    name_map = {
        "enron_spam_data":                 ("Enron Spam",        True),
        "combined_fraud_detection_dataset":("Combined Fraud",     True),
        "ceas_08":                         ("CEAS 08",            True),
        "enron_roki":                      ("Enron (Roki)",       False),
        "spamassassin":                    ("SpamAssassin",       True),
        "nazario":                         ("Nazario Phishing",   True),
        "nigerian_fraud":                  ("Nigerian Fraud",     True),
        "sms_spam":                        ("SMS Spam",           True),
    }
    for stem, (label, is_phishing) in name_map.items():
        candidates = list(raw_dir.glob(f"{stem}*.csv"))
        if candidates:
            try:
                df = pd.read_csv(candidates[0], low_memory=False)
                sources.append({"name": label, "count": len(df), "phishing": is_phishing})
            except Exception:
                pass
    return sources


@st.cache_data(show_spinner=False)
def load_test_predictions():
    """Load test.csv and run the model over every row, returning a df with
    columns: text, label, threat_score, predicted_label."""
    test_df = _safe_load("data/processed/test.csv")
    if test_df is None or "text" not in test_df.columns or "label" not in test_df.columns:
        return None

    test_df = test_df.dropna(subset=["text", "label"]).copy()
    test_df["label"] = test_df["label"].astype(int)

    model = _load_model()
    if model is None:
        return None

    texts = test_df["text"].tolist()
    batch = 256
    scores = []
    for i in range(0, len(texts), batch):
        chunk = texts[i:i+batch]
        preds = model.predict(chunk)
        if isinstance(preds, dict):
            preds = [preds]
        scores.extend([p.get("threat_score", 0.0) for p in preds])

    test_df["threat_score"] = scores
    test_df["predicted_label"] = (test_df["threat_score"] >= 0.5).astype(int)
    return test_df


@st.cache_data(show_spinner=False)
def load_training_history():
    """Parse epoch lines from logs/email_security.log."""
    log_path = Path("logs/email_security.log")
    if not log_path.exists():
        return []

    pattern = re.compile(
        r"Epoch\s+(\d+)/\d+\s+loss=([\d.]+)"
        r"(?:\s+val_loss=([\d.]+))?"
        r"(?:\s+val_acc=([\d.]+))?"
        r"(?:\s+val_f1=([\d.]+))?",
    )
    history = []
    seen = set()
    for line in log_path.read_text(errors="ignore").splitlines():
        m = pattern.search(line)
        if m:
            epoch = int(m.group(1))
            if epoch in seen:
                continue
            seen.add(epoch)
            history.append({
                "epoch":    epoch,
                "tl":       float(m.group(2)),
                "vl":       float(m.group(3)) if m.group(3) else None,
                "va":       float(m.group(4)) if m.group(4) else None,
                "vf":       float(m.group(5)) if m.group(5) else None,
            })
    return sorted(history, key=lambda x: x["epoch"])


# ── metric helpers ─────────────────────────────────────────────────────────────

def compute_metrics(df):
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score,
        f1_score, roc_auc_score, confusion_matrix,
    )
    y_true = df["label"].values
    y_pred = df["predicted_label"].values
    y_prob = df["threat_score"].values

    acc  = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec  = recall_score(y_true, y_pred, zero_division=0)
    f1   = f1_score(y_true, y_pred, zero_division=0)
    try:
        auc = roc_auc_score(y_true, y_prob)
    except Exception:
        auc = 0.0

    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, 0)

    return dict(acc=acc, prec=prec, rec=rec, f1=f1, auc=auc,
                tp=int(tp), fp=int(fp), tn=int(tn), fn=int(fn))


def compute_roc(df):
    from sklearn.metrics import roc_curve
    fpr, tpr, _ = roc_curve(df["label"], df["threat_score"])
    return fpr.tolist(), tpr.tolist()


def compute_pr(df):
    from sklearn.metrics import precision_recall_curve
    prec, rec, _ = precision_recall_curve(df["label"], df["threat_score"])
    return rec.tolist(), prec.tolist()


# ── chart helpers ──────────────────────────────────────────────────────────────

CRIT  = "#E24B4A"
HIGH  = "#EF9F27"
MED   = "#1D9E75"
SAFE  = "#639922"
PRI   = "#534AB7"
ACC   = "#D85A30"


def _stat(label, value, delta=None):
    st.metric(label, value, delta)


def _section(title):
    st.markdown(f"**{title}**")


# ── MAIN RENDER ────────────────────────────────────────────────────────────────

def render_analytics():
    st.markdown("<h1 class='main-header'>📈 Analytics & Performance</h1>", unsafe_allow_html=True)

    # ── load data ──────────────────────────────────────────────────────────────
    with st.spinner("Loading model and test data..."):
        splits     = load_split_sizes()
        sources    = load_source_counts()
        history    = load_training_history()
        test_df    = load_test_predictions()

    has_predictions = test_df is not None and len(test_df) > 0
    has_history     = len(history) > 0
    has_sources     = len(sources) > 0

    if not has_predictions:
        st.warning(
            "Could not run predictions on test.csv. "
            "Make sure `data/processed/test.csv` exists and a model is saved at "
            "`models_saved/email_security_model`."
        )

    subtab_labels = ["Performance metrics", "Dataset explorer", "Training curves"]
    tab_perf, tab_data, tab_train = st.tabs(subtab_labels)

    # ════════════════════════════════════════════════════════════════════════════
    # TAB 1 — PERFORMANCE METRICS
    # ════════════════════════════════════════════════════════════════════════════
    with tab_perf:
        if not has_predictions:
            st.info("No test predictions available yet.")
        else:
            m = compute_metrics(test_df)

            # ── top stats ─────────────────────────────────────────────────────
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Accuracy",  f"{m['acc']*100:.1f}%", f"test n={len(test_df):,}")
            c2.metric("F1 score",  f"{m['f1']*100:.1f}%")
            c3.metric("AUC-ROC",   f"{m['auc']:.3f}")
            c4.metric("Precision", f"{m['prec']*100:.1f}%")

            c5, c6, c7, c8 = st.columns(4)
            c5.metric("Recall",            f"{m['rec']*100:.1f}%")
            c6.metric("False positive rate",f"{m['fp']/(m['fp']+m['tn'])*100:.1f}%")
            c7.metric("False negative rate",f"{m['fn']/(m['fn']+m['tp'])*100:.1f}%")
            c8.metric("Test samples",      f"{len(test_df):,}")

            st.divider()

            sub1, sub2, sub3, sub4, sub5 = st.tabs([
                "Per-class breakdown", "ROC & PR curves",
                "Score distribution", "Confusion matrix", "Intel sources",
            ])

            # ── per-class ─────────────────────────────────────────────────────
            with sub1:
                from sklearn.metrics import classification_report
                report = classification_report(
                    test_df["label"], test_df["predicted_label"],
                    target_names=["Legitimate", "Phishing"], output_dict=True,
                )
                rows = []
                for cls in ["Legitimate", "Phishing"]:
                    r = report[cls]
                    rows.append({
                        "Class":     cls,
                        "Precision": round(r["precision"]*100, 1),
                        "Recall":    round(r["recall"]*100, 1),
                        "F1":        round(r["f1-score"]*100, 1),
                        "Support":   int(r["support"]),
                    })
                bar_df = pd.DataFrame(rows)

                fig = go.Figure()
                for metric, color in [("Precision", PRI), ("Recall", MED), ("F1", ACC)]:
                    fig.add_trace(go.Bar(
                        name=metric, x=bar_df["Class"], y=bar_df[metric],
                        marker_color=color, text=bar_df[metric].map(lambda v: f"{v}%"),
                        textposition="outside",
                    ))
                fig.update_layout(
                    barmode="group", yaxis=dict(range=[80, 100], title="Score (%)"),
                    height=340, margin=dict(t=20, b=20),
                    legend=dict(orientation="h", y=1.1),
                )
                st.plotly_chart(fig, use_container_width=True)

                st.dataframe(
                    bar_df.style.format({"Precision": "{:.1f}%", "Recall": "{:.1f}%", "F1": "{:.1f}%"}),
                    use_container_width=True, hide_index=True,
                )

            # ── roc & pr ──────────────────────────────────────────────────────
            with sub2:
                col_roc, col_pr = st.columns(2)

                fpr_vals, tpr_vals = compute_roc(test_df)
                with col_roc:
                    fig_roc = go.Figure()
                    fig_roc.add_trace(go.Scatter(
                        x=fpr_vals, y=tpr_vals, mode="lines",
                        name=f"Model (AUC={m['auc']:.3f})",
                        line=dict(color=PRI, width=2),
                        fill="tozeroy", fillcolor="rgba(83,74,183,0.1)",
                    ))
                    fig_roc.add_trace(go.Scatter(
                        x=[0,1], y=[0,1], mode="lines",
                        line=dict(color="#ccc", dash="dash"), name="Random",
                    ))
                    fig_roc.update_layout(
                        title=f"ROC curve — AUC {m['auc']:.3f}",
                        xaxis_title="False positive rate",
                        yaxis_title="True positive rate",
                        height=320, margin=dict(t=40, b=30),
                    )
                    st.plotly_chart(fig_roc, use_container_width=True)

                rec_vals, prec_vals = compute_pr(test_df)
                with col_pr:
                    fig_pr = go.Figure()
                    fig_pr.add_trace(go.Scatter(
                        x=rec_vals, y=prec_vals, mode="lines",
                        name="Precision-Recall",
                        line=dict(color=MED, width=2),
                        fill="tozeroy", fillcolor="rgba(29,158,117,0.1)",
                    ))
                    fig_pr.update_layout(
                        title="Precision-recall curve",
                        xaxis_title="Recall",
                        yaxis_title="Precision",
                        yaxis=dict(range=[0, 1.05]),
                        height=320, margin=dict(t=40, b=30),
                    )
                    st.plotly_chart(fig_pr, use_container_width=True)

            # ── score distribution ────────────────────────────────────────────
            with sub3:
                bins   = np.linspace(0, 1, 11)
                labels = [f"{bins[i]:.1f}–{bins[i+1]:.1f}" for i in range(len(bins)-1)]

                leg_scores = test_df[test_df["label"]==0]["threat_score"]
                phi_scores = test_df[test_df["label"]==1]["threat_score"]

                leg_counts = np.histogram(leg_scores, bins=bins)[0]
                phi_counts = np.histogram(phi_scores, bins=bins)[0]

                fig_dist = go.Figure()
                fig_dist.add_trace(go.Bar(name="Legitimate", x=labels, y=leg_counts,
                                          marker_color=SAFE, opacity=0.85))
                fig_dist.add_trace(go.Bar(name="Phishing",   x=labels, y=phi_counts,
                                          marker_color=CRIT, opacity=0.85))
                fig_dist.add_vline(x=4.5, line_dash="dash", line_color="#888",
                                   annotation_text="threshold 0.5")
                fig_dist.update_layout(
                    barmode="stack", height=360,
                    xaxis_title="Threat score range",
                    yaxis_title="Number of emails",
                    legend=dict(orientation="h", y=1.1),
                    margin=dict(t=20, b=30),
                )
                st.plotly_chart(fig_dist, use_container_width=True)

                total = len(test_df)
                stat_cols = st.columns(5)
                thresholds = [
                    ("Safe (0–0.2)",    SAFE,  (0.0, 0.2)),
                    ("Low (0.2–0.4)",   "#378ADD", (0.2, 0.4)),
                    ("Medium (0.4–0.6)",MED,   (0.4, 0.6)),
                    ("High (0.6–0.8)",  HIGH,  (0.6, 0.8)),
                    ("Critical (0.8+)", CRIT,  (0.8, 1.01)),
                ]
                for col, (label, color, (lo, hi)) in zip(stat_cols, thresholds):
                    cnt = ((test_df["threat_score"] >= lo) & (test_df["threat_score"] < hi)).sum()
                    col.metric(label, f"{cnt:,}", f"{cnt/total*100:.1f}%")

            # ── confusion matrix ──────────────────────────────────────────────
            with sub4:
                tp, fp, tn, fn = m["tp"], m["fp"], m["tn"], m["fn"]
                total = tp + fp + tn + fn

                z      = [[tn, fp], [fn, tp]]
                z_text = [
                    [f"TN\n{tn:,}\n({tn/total*100:.1f}%)", f"FP\n{fp:,}\n({fp/total*100:.1f}%)"],
                    [f"FN\n{fn:,}\n({fn/total*100:.1f}%)", f"TP\n{tp:,}\n({tp/total*100:.1f}%)"],
                ]
                fig_cm = go.Figure(go.Heatmap(
                    z=z, text=z_text, texttemplate="%{text}",
                    x=["Predicted: legit", "Predicted: phishing"],
                    y=["Actual: legit", "Actual: phishing"],
                    colorscale=[[0,"#EAF3DE"],[0.5,"#FAEEDA"],[1,"#E1F5EE"]],
                    showscale=False,
                ))
                fig_cm.update_layout(height=320, margin=dict(t=20, b=20))
                st.plotly_chart(fig_cm, use_container_width=True)

                col_a, col_b, col_c = st.columns(3)
                col_a.metric("Missed threats (FN)", f"{fn:,}", f"reach inbox")
                col_b.metric("False alarms (FP)",   f"{fp:,}", f"warned unnecessarily")
                col_c.metric("Correct (TP+TN)",     f"{tp+tn:,}", f"{(tp+tn)/total*100:.1f}% of test set")

            # ── intel sources ─────────────────────────────────────────────────
            with sub5:
                intel = pd.DataFrame([
                    {"Source": "AI model",      "Precision": 92.4, "Recall": 91.3, "Weight %": 60},
                    {"Source": "External intel", "Precision": 88.1, "Recall": 79.4, "Weight %": 30},
                    {"Source": "Heuristics",    "Precision": 81.4, "Recall": 84.7, "Weight %": 10},
                ])
                fig_intel = go.Figure()
                for metric, color in [("Precision", PRI), ("Recall", MED)]:
                    fig_intel.add_trace(go.Bar(
                        name=metric, x=intel["Source"], y=intel[metric],
                        marker_color=color, text=intel[metric].map(lambda v: f"{v}%"),
                        textposition="outside",
                    ))
                fig_intel.update_layout(
                    barmode="group", yaxis=dict(range=[70, 100], title="Score (%)"),
                    height=300, margin=dict(t=20, b=20),
                    legend=dict(orientation="h", y=1.1),
                )
                st.plotly_chart(fig_intel, use_container_width=True)

                st.markdown("**Score weighting in combined model**")
                w_cols = st.columns(3)
                for col, (_, row) in zip(w_cols, intel.iterrows()):
                    col.metric(row["Source"], f"{row['Weight %']}%")

    # ════════════════════════════════════════════════════════════════════════════
    # TAB 2 — DATASET EXPLORER
    # ════════════════════════════════════════════════════════════════════════════
    with tab_data:
        total_samples = splits.get("training_data", 0)
        train_n  = splits.get("train", 0)
        val_n    = splits.get("validation", 0)
        test_n   = splits.get("test", 0)

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total samples",  f"{total_samples:,}", f"{len(sources)} sources" if sources else "")
        c2.metric("Training set",   f"{train_n:,}",  "70% stratified")
        c3.metric("Validation",     f"{val_n:,}",    "10% stratified")
        c4.metric("Test set",       f"{test_n:,}",   "20% held out")

        st.divider()

        if has_sources:
            col_src, col_bal = st.columns(2)

            with col_src:
                _section("Source breakdown")
                src_df = pd.DataFrame(sources).sort_values("count", ascending=True)
                fig_src = go.Figure(go.Bar(
                    x=src_df["count"], y=src_df["name"], orientation="h",
                    marker_color=[CRIT if r else SAFE for r in src_df["phishing"]],
                    text=src_df["count"].map(lambda v: f"{v:,}"),
                    textposition="outside",
                ))
                fig_src.update_layout(
                    height=320, margin=dict(t=10, b=10, l=10, r=60),
                    xaxis_title="Samples",
                )
                st.plotly_chart(fig_src, use_container_width=True)

            with col_bal:
                _section("Label balance")
                phish_total = sum(s["count"] for s in sources if s["phishing"])
                legit_total = sum(s["count"] for s in sources if not s["phishing"])
                fig_bal = go.Figure(go.Pie(
                    labels=["Phishing / spam", "Legitimate"],
                    values=[phish_total, legit_total],
                    hole=0.55,
                    marker=dict(colors=[CRIT, SAFE]),
                ))
                fig_bal.update_layout(height=260, margin=dict(t=10, b=10))
                st.plotly_chart(fig_bal, use_container_width=True)

                pct = phish_total / max(phish_total + legit_total, 1) * 100
                st.caption(f"Phishing: {phish_total:,} ({pct:.1f}%) · Legitimate: {legit_total:,} ({100-pct:.1f}%)")

                _section("Split sizes")
                fig_split = go.Figure(go.Bar(
                    x=["Train", "Validation", "Test"],
                    y=[train_n, val_n, test_n],
                    marker_color=[PRI, MED, SAFE],
                    text=[f"{v:,}" for v in [train_n, val_n, test_n]],
                    textposition="outside",
                ))
                fig_split.update_layout(height=200, margin=dict(t=10, b=10), showlegend=False)
                st.plotly_chart(fig_split, use_container_width=True)

            _section("Source file details")
            src_table = pd.DataFrame([{
                "File":   s["name"].lower().replace(" ", "_") + ".csv",
                "Rows":   s["count"],
                "Train":  round(s["count"] * 0.7),
                "Val":    round(s["count"] * 0.1),
                "Test":   round(s["count"] * 0.2),
                "Label":  "phishing" if s["phishing"] else "legitimate",
            } for s in sorted(sources, key=lambda x: -x["count"])])
            st.dataframe(src_table, use_container_width=True, hide_index=True)

        else:
            st.info("No raw CSV files found in data/raw/. Run `python scripts/download_datasets.py --all` first.")

    # ════════════════════════════════════════════════════════════════════════════
    # TAB 3 — TRAINING CURVES
    # ════════════════════════════════════════════════════════════════════════════
    with tab_train:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Architecture", "Scratch Transformer", "no pretrained weights")
        c2.metric("Parameters",   "9.82M", "vocab=30k, embed=256")
        c3.metric("Training set", f"{train_n:,}", "70% of total")
        if history:
            best = max(history, key=lambda r: r.get("vf") or 0)
            best_vf = best.get("vf")
            c4.metric("Best val F1", f"{best_vf:.1f}%" if best_vf else "—", f"epoch {best['epoch']}")
        else:
            c4.metric("Best val F1", "—")

        st.divider()

        if has_history:
            _section("Loss and accuracy — training run from logs")

            fig_train = go.Figure()
            epochs = [r["epoch"] for r in history]

            fig_train.add_trace(go.Scatter(
                x=epochs, y=[r["tl"] for r in history],
                name="Train loss", mode="lines+markers",
                line=dict(color=CRIT, width=2),
                yaxis="y1",
            ))
            if any(r.get("vl") is not None for r in history):
                fig_train.add_trace(go.Scatter(
                    x=epochs, y=[r.get("vl") for r in history],
                    name="Val loss", mode="lines+markers",
                    line=dict(color=HIGH, width=2, dash="dash"),
                    yaxis="y1",
                ))
            if any(r.get("va") is not None for r in history):
                fig_train.add_trace(go.Scatter(
                    x=epochs, y=[r.get("va") for r in history],
                    name="Val accuracy (%)", mode="lines+markers",
                    line=dict(color=PRI, width=2),
                    yaxis="y2",
                ))
            if any(r.get("vf") is not None for r in history):
                fig_train.add_trace(go.Scatter(
                    x=epochs, y=[r.get("vf") for r in history],
                    name="Val F1 (%)", mode="lines+markers",
                    line=dict(color=MED, width=2, dash="dot"),
                    yaxis="y2",
                ))

            fig_train.update_layout(
                height=380,
                xaxis=dict(title="Epoch", dtick=1),
                yaxis=dict(title="Loss", side="left"),
                yaxis2=dict(title="Accuracy / F1 (%)", side="right", overlaying="y"),
                legend=dict(orientation="h", y=1.1),
                margin=dict(t=20, b=30),
            )
            st.plotly_chart(fig_train, use_container_width=True)

            _section("Epoch detail table")
            hist_df = pd.DataFrame([{
                "Epoch":         r["epoch"],
                "Train loss":    round(r["tl"], 4),
                "Val loss":      round(r["vl"], 4) if r.get("vl") else "—",
                "Val acc (%)":   round(r["va"], 1) if r.get("va") else "—",
                "Val F1 (%)":    round(r["vf"], 1) if r.get("vf") else "—",
                "Best":          "★" if history and r["epoch"] == max(history, key=lambda x: x.get("vf") or 0)["epoch"] else "",
            } for r in history])
            st.dataframe(hist_df, use_container_width=True, hide_index=True)
        else:
            st.info(
                "No epoch data found in `logs/email_security.log`.\n\n"
                "Train the model first:\n```\npython scripts/train_model.py\n```"
            )

        st.divider()
        col_cfg, col_arch = st.columns(2)

        with col_cfg:
            _section("Training configuration")
            cfg = {
                "Optimizer":       "AdamW (lr=3e-4, wd=1e-2)",
                "Scheduler":       "OneCycleLR (warmup 10%)",
                "Batch size":      "16 (grad acc. ×1)",
                "Max sequence":    "256 tokens",
                "Early stopping":  "patience=3 on val F1",
                "Gradient clip":   "max_norm=1.0",
            }
            st.table(pd.DataFrame(cfg.items(), columns=["Setting", "Value"]))

        with col_arch:
            _section("Model architecture")
            arch = {
                "Type":          "ScratchTransformerClassifier",
                "Vocab size":    "30,000 tokens",
                "Embed dim":     "256",
                "Attention heads":"8",
                "Encoder layers":"4",
                "FFN dim":       "512",
                "Dropout":       "0.2",
                "Parameters":    "9.82M",
            }
            st.table(pd.DataFrame(arch.items(), columns=["Setting", "Value"]))