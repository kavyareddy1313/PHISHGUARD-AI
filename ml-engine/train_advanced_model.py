"""
FishGuard AI - Advanced ML Model Training & Multi-Classifier Evaluation Pipeline
Trains, benchmarks, and exports production phishing detection pipelines.
"""

import os
import json
import time
import joblib
import numpy as np
from dataset_builder import generate_corpus
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from train_model import StructuralFeatureExtractor

def train_and_benchmark():
    print("=" * 70)
    print("🛡️  FISHGUARD AI: TRAINING PRODUCTION PHISHING CLASSIFIER")
    print("=" * 70)
    
    start_time = time.time()
    
    # 1. Load or generate dataset
    corpus_file = os.path.join(os.path.dirname(__file__), "dataset", "cyber_phishing_corpus.json")
    if not os.path.exists(corpus_file):
        records = generate_corpus(2600)
    else:
        with open(corpus_file, "r", encoding="utf-8") as f:
            records = json.load(f)
            
    print(f"Total samples loaded: {len(records)}")
    
    texts = []
    labels = []
    for r in records:
        url_part = " ".join(r.get("urls", []))
        att_part = " ".join(r.get("attachments", []))
        combined = f"From: {r['sender']} Subject: {r['subject']} Content: {r['body']} Links: {url_part} Attachments: {att_part}"
        texts.append(combined)
        labels.append(r["label"])
        
    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.25, random_state=42, stratify=labels
    )
    print(f"Training split: {len(X_train)} samples | Testing split: {len(X_test)} samples")
    
    # 2. Build Feature Extraction Union
    feature_union = FeatureUnion([
        ('tfidf', TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=5000,
            sublinear_tf=True,
            strip_accents='unicode',
            stop_words='english'
        )),
        ('structural', StructuralFeatureExtractor())
    ])
    
    # 3. Benchmark Candidates
    candidates = {
        "LogisticRegression": LogisticRegression(C=3.0, max_iter=1000, class_weight='balanced', random_state=42),
        "MultinomialNB": MultinomialNB(alpha=0.2),
        "RandomForest": RandomForestClassifier(n_estimators=100, max_depth=20, random_state=42, n_jobs=-1)
    }
    
    benchmark_results = {}
    best_name = None
    best_f1 = -1.0
    best_pipeline = None
    best_metrics = None
    
    for name, clf in candidates.items():
        print(f"\nEvaluating candidate model: {name}...")
        pipeline = Pipeline([
            ('features', feature_union),
            ('classifier', clf)
        ])
        
        pipeline.fit(X_train, y_train)
        y_pred = pipeline.predict(X_test)
        
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred)
        rec = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        
        benchmark_results[name] = {
            "accuracy": round(float(acc) * 100, 2),
            "precision": round(float(prec) * 100, 2),
            "recall": round(float(rec) * 100, 2),
            "f1_score": round(float(f1) * 100, 2)
        }
        
        print(f" -> Accuracy: {acc * 100:.2f}% | Precision: {prec * 100:.2f}% | Recall: {rec * 100:.2f}% | F1: {f1 * 100:.2f}%")
        
        if f1 > best_f1:
            best_f1 = f1
            best_name = name
            best_pipeline = pipeline
            cm = confusion_matrix(y_test, y_pred).tolist()
            best_metrics = {
                "algorithm": name,
                "accuracy": round(float(acc) * 100, 2),
                "precision": round(float(prec) * 100, 2),
                "recall": round(float(rec) * 100, 2),
                "f1_score": round(float(f1) * 100, 2),
                "confusion_matrix": cm,
                "training_samples": len(X_train),
                "test_samples": len(X_test),
                "benchmark_comparison": benchmark_results,
                "trained_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                "duration_seconds": round(time.time() - start_time, 2)
            }
            
    print("\n" + "=" * 70)
    print(f"🏆 Champion Model Selected: {best_name} (F1 Score: {best_f1 * 100:.2f}%)")
    print("=" * 70)
    
    # Save Pipeline and Metrics
    model_dir = os.path.join(os.path.dirname(__file__), "model")
    os.makedirs(model_dir, exist_ok=True)
    
    pipeline_file = os.path.join(model_dir, "phishing_pipeline.pkl")
    joblib.dump(best_pipeline, pipeline_file)
    
    metrics_file = os.path.join(model_dir, "training_metrics.json")
    with open(metrics_file, "w", encoding="utf-8") as f:
        json.dump(best_metrics, f, indent=2)
        
    print(f"✅ Pipeline artifact saved to: {pipeline_file}")
    print(f"✅ Training metrics saved to: {metrics_file}")
    return best_metrics

if __name__ == '__main__':
    train_and_benchmark()
