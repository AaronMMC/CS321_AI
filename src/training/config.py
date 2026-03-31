"""
Training configuration dataclasses.
Import ``TrainingConfig`` and override fields as needed.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class TrainingConfig:
    """Hyperparameters and paths for model training."""

    # --- Model ---
    model_name: str = "huawei-noah/TinyBERT_4L_312D"
    num_labels: int = 2
    max_length: int = 256
    dropout: float = 0.3

    # --- Data ---
    data_dir: Path = Path("data")
    output_dir: Path = Path("models_saved")
    train_file: Optional[Path] = None          # auto-discovered if None
    val_split: float = 0.1
    test_split: float = 0.1
    augment_data: bool = True
    augment_factor: int = 1                    # extra copies per sample

    # --- Training loop ---
    epochs: int = 5
    batch_size: int = 16
    learning_rate: float = 2e-5
    warmup_ratio: float = 0.1                  # fraction of steps used for warmup
    gradient_accumulation_steps: int = 1
    max_grad_norm: float = 1.0
    weight_decay: float = 0.01

    # --- Early stopping ---
    early_stopping: bool = True
    patience: int = 3
    monitor_metric: str = "f1"                # accuracy | f1 | recall | precision

    # --- Misc ---
    seed: int = 42
    use_gpu: bool = True
    save_best_model: bool = True
    log_every_n_steps: int = 50
    eval_every_n_epochs: int = 1

    # --- Class weights (for imbalanced data) ---
    class_weights: Optional[List[float]] = None   # e.g. [1.0, 3.0] to upweight phishing

    def __post_init__(self):
        self.output_dir = Path(self.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    @property
    def warmup_steps_from_data(self) -> int:
        """Compute warmup steps given approximate dataset size."""
        # Requires actual dataloader length; used as a fallback estimate
        estimated_steps_per_epoch = 500
        total_steps = estimated_steps_per_epoch * self.epochs
        return int(total_steps * self.warmup_ratio)


@dataclass
class InferenceConfig:
    """Settings used at inference / serving time."""

    model_path: Path = Path("models_saved/best_model")
    use_gpu: bool = True
    max_length: int = 256
    batch_size: int = 32
    threat_threshold: float = 0.5    # above this → flagged
    confidence_min: float = 0.6      # below this → mark as uncertain

    score_weights: dict = field(
        default_factory=lambda: {
            "model": 0.60,
            "external": 0.30,
            "heuristic": 0.10,
        }
    )