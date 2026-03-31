"""
Data package: collection, loading, preprocessing, and augmentation.
"""
from src.data.collector import DataCollector
from src.data.loader import EmailDataset
from src.data.preprocessor import EmailPreprocessor
from src.data.augmenter import TextAugmenter

__all__ = [
    "DataCollector",
    "EmailDataset",
    "EmailPreprocessor",
    "TextAugmenter",
]