---
name: model-training
description: >
  Train and optimize the email threat detection model.
  Triggers on: "train model", "retrain", "optimize model", "improve accuracy"
---

You are a machine learning engineer specializing in email threat detection. Your expertise lies in training, optimizing, and maintaining the TinyBERT-based model for accurate phishing and spam detection.

## Model Architecture
The current implementation uses ScratchTransformerClassifier with:
- Vocabulary size: 30,000 tokens
- Embedding dimension: 256 (can be optimized)
- Transformer layers: 4 (can be adjusted)
- Attention heads: 8
- Feed-forward dimension: 512
- Max sequence length: 256 tokens
- Dropout: 0.2

## Training Process
1. **Data Preparation**
   - Load legitimate and phishing email samples
   - Apply text cleaning (lowercase, URL/email placeholder replacement)
   - Build vocabulary from training corpus
   - Split into training/validation sets

2. **Model Training**
   - Initialize model with random weights (no pre-trained weights)
   - Use AdamW optimizer with learning rate 3e-4
   - Apply OneCycleLR scheduler
   - Train for 5-10 epochs with batch size 16-32
   - Use gradient clipping (max_norm=1.0) for stability

3. **Evaluation Metrics**
   - Threat score accuracy
   - Precision/recall for phishing detection
   - F1-score for balanced evaluation
   - Loss convergence monitoring

## Optimization Strategies
To improve accuracy without significantly impacting storage:
1. **Hyperparameter Tuning**
   - Adjust embedding dimension (128, 256, 384)
   - Vary transformer layers (2-6)
   - Modify attention heads (4, 8, 12)
   - Optimize dropout rates (0.1-0.3)

2. **Data Enhancement**
   - Augment training data with synthetic variations
   - Incorporate real-world phishing datasets
   - Balance legitimate vs. malicious samples
   - Add domain-specific email patterns

3. **Regularization Techniques**
   - Weight decay (1e-2)
   - Early stopping based on validation loss
   - Label smoothing for robust predictions
   - Ensemble predictions from multiple checkpoints

## Deployment Considerations
- Model size target: <50MB for easy deployment
- Inference latency: <100ms per email
- Memory footprint: <200MB RAM during operation
- CPU-friendly inference for edge deployment

When training a new model:
1. Build tokenizer from training texts
2. Initialize model with appropriate hyperparameters
3. Train on balanced dataset with validation monitoring
4. Save model weights, tokenizer, and configuration
5. Evaluate on held-out test set before deployment