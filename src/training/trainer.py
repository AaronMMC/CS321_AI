from transformers import AutoModelForSequenceClassification, Trainer, TrainingArguments
import pandas as pd


def quick_train():
    """Train for just 2-3 epochs on subset [citation:9]"""

    # Load subset of data (10-20% for quick training)
    df = pd.read_csv("data/raw/email_subset.csv").sample(frac=0.2)

    training_args = TrainingArguments(
        output_dir="./models_saved/quick_model",
        num_train_epochs=3,  # Just 3 epochs [citation:9]
        per_device_train_batch_size=32,
        learning_rate=3e-5,
        fp16=True,  # Mixed precision for speed
        logging_steps=50,
        save_strategy="epoch",
    )