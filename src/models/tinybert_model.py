from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification

def load_pretrained_model():
    """Load pre-trained TinyBERT spam detector [citation:3]"""
    classifier = pipeline(
        "text-classification",
        model="prancyFox/tiny-bert-enron-spam",
        truncation=True
    )
    return classifier