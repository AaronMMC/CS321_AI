"""
Models package for email security gateway
"""
from src.models.bert_classifier import BERTPhishingClassifier, ModelOutput
from src.models.tinybert_model import TinyBERTForEmailSecurity, create_mini_dataset_for_quick_training

__all__ = [
    'BERTPhishingClassifier',
    'ModelOutput',
    'TinyBERTForEmailSecurity',
    'create_mini_dataset_for_quick_training'
]