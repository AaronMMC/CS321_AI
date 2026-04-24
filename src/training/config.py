"""
Training configuration dataclasses.

BUG FIX: Removed the stale `model_name` field that pointed to the
HuggingFace model "huawei-noah/TinyBERT_4L_312D". The entire model stack
was rewritten to use a from-scratch Transformer (ScratchModelForEmailSecurity)
which builds its own vocabulary from training data and never calls
`from_pretrained()`. Keeping that field caused confusion and made it look
like a HuggingFace download was expected.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class TrainingConfig:
    """Hyperparameters and paths for model training."""

    # --- Model architecture (scratch Transformer) ---
    # BUG FIX: was "huawei-noah/TinyBERT_4L_312D" — irrelevant after the
    # model was rewritten to train from scratch with no pretrained weights.
    embed_dim:   int   = 256
    num_heads:   int   = 8
    num_layers:  int   = 4
    ffn_dim:     int   = 512
    vocab_size:  int   = 30_000
    num_labels:  int   = 2
    max_length:  int   = 256
    dropout:     float = 0.2

    # --- Data ---
    data_dir:   Path = Path("data")
    output_dir: Path = Path("models_saved")
    train_file: Optional[Path] = None      # auto-discovered if None
    val_split:  float = 0.1
    test_split: float = 0.1
    augment_data:   bool = True
    augment_factor: int  = 1

    # --- Training loop ---
    epochs:                      int   = 5
    batch_size:                  int   = 16
    learning_rate:               float = 3e-4
    warmup_ratio:                float = 0.1
    gradient_accumulation_steps: int   = 1
    max_grad_norm:               float = 1.0
    weight_decay:                float = 0.01

    # --- Early stopping ---
    early_stopping:  bool = True
    patience:        int  = 3
    monitor_metric:  str  = "f1"

    # --- Misc ---
    seed:            int  = 42
    use_gpu:         bool = True
    save_best_model: bool = True
    log_every_n_steps:   int = 50
    eval_every_n_epochs: int = 1

    # --- Class weights (for imbalanced data) ---
    class_weights: Optional[List[float]] = None

    def __post_init__(self):
        self.output_dir = Path(self.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)


@dataclass
class InferenceConfig:
    """Settings used at inference / serving time."""

    model_path:       Path  = Path("models_saved/best_model")
    use_gpu:          bool  = True
    max_length:       int   = 256
    batch_size:       int   = 32
    threat_threshold: float = 0.5
    confidence_min:   float = 0.6

    score_weights: dict = field(
        default_factory=lambda: {
            "model":     0.60,
            "external":  0.30,
            "heuristic": 0.10,
        }
    )