import pandas as pd
import numpy as np
import pickle
import json
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

try:
    from xgboost import XGBClassifier
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False
    print("⚠️  XGBoost not installed. Install with: pip install xgboost")

try:
    import shap
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAS_SHAP = True
except ImportError:
    HAS_SHAP = False
    print("⚠️  SHAP not installed. Install with: pip install shap matplotlib")


# -------- LOAD PROCESSED DATA --------
data = pd.read_csv("processed_dataset.csv")

print(f"📊 Loaded {len(data)} samples")
print(f"   Features: {list(data.columns[:-1])}")

X = data.drop("label", axis=1)
y = data["label"]

feature_names = list(X.columns)

# -------- SPLIT --------
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    stratify=y,
    random_state=42
)

print(f"   Train: {len(X_train)} | Test: {len(X_test)}")


# -------- EVALUATION HELPER --------
def evaluate_model(model, name, X_test, y_test):
    """Evaluate a model and return metrics dict."""
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred).tolist()
    report = classification_report(y_test, y_pred, output_dict=True)

    metrics = {
        "model": name,
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "confusion_matrix": cm,
        "classification_report": report
    }

    print(f"\n{'='*50}")
    print(f"📈 {name} Results")
    print(f"{'='*50}")
    print(f"   Accuracy:  {acc:.4f}")
    print(f"   Precision: {prec:.4f}")
    print(f"   Recall:    {rec:.4f}")
    print(f"   F1-Score:  {f1:.4f}")
    print(f"   Confusion Matrix:")
    print(f"     TN={cm[0][0]}  FP={cm[0][1]}")
    print(f"     FN={cm[1][0]}  TP={cm[1][1]}")

    return metrics


# -------- TRAIN RANDOM FOREST --------
print("\n🌲 Training Random Forest...")
rf_model = RandomForestClassifier(
    n_estimators=500,
    class_weight="balanced",
    n_jobs=-1,
    random_state=42
)
rf_model.fit(X_train, y_train)
rf_metrics = evaluate_model(rf_model, "Random Forest", X_test, y_test)

# -------- TRAIN XGBOOST --------
xgb_metrics = None
xgb_model = None

if HAS_XGBOOST:
    print("\n⚡ Training XGBoost...")

    # Calculate scale_pos_weight for imbalanced data
    neg_count = (y_train == 0).sum()
    pos_count = (y_train == 1).sum()
    scale_weight = neg_count / pos_count if pos_count > 0 else 1

    xgb_model = XGBClassifier(
        n_estimators=500,
        max_depth=6,
        learning_rate=0.1,
        scale_pos_weight=scale_weight,
        use_label_encoder=False,
        eval_metric="logloss",
        n_jobs=-1,
        random_state=42
    )
    xgb_model.fit(X_train, y_train)
    xgb_metrics = evaluate_model(xgb_model, "XGBoost", X_test, y_test)


# -------- SELECT BEST MODEL --------
print("\n" + "="*50)
print("🏆 Model Comparison")
print("="*50)

results = {"random_forest": rf_metrics}
best_model = rf_model
best_name = "Random Forest"
best_f1 = rf_metrics["f1_score"]

if xgb_metrics:
    results["xgboost"] = xgb_metrics

    print(f"   {'Metric':<15} {'Random Forest':>15} {'XGBoost':>15}")
    print(f"   {'-'*45}")
    for m in ["accuracy", "precision", "recall", "f1_score"]:
        rf_val = rf_metrics[m]
        xgb_val = xgb_metrics[m]
        marker = " ⬅️" if rf_val >= xgb_val else ""
        marker2 = " ⬅️" if xgb_val > rf_val else ""
        print(f"   {m:<15} {rf_val:>15.4f}{marker} {xgb_val:>13.4f}{marker2}")

    if xgb_metrics["f1_score"] > rf_metrics["f1_score"]:
        best_model = xgb_model
        best_name = "XGBoost"
        best_f1 = xgb_metrics["f1_score"]
else:
    print(f"   Only Random Forest trained (XGBoost unavailable)")
    print(f"   F1-Score: {rf_metrics['f1_score']:.4f}")

results["best_model"] = best_name
print(f"\n   🏆 Best Model: {best_name} (F1={best_f1:.4f})")


# -------- SAVE MODELS --------
pickle.dump(rf_model, open("rf_model.pkl", "wb"))
print("   💾 Saved rf_model.pkl")

if xgb_model:
    pickle.dump(xgb_model, open("xgb_model.pkl", "wb"))
    print("   💾 Saved xgb_model.pkl")

# Save best model as model.pkl for backward compat
pickle.dump(best_model, open("model.pkl", "wb"))
print(f"   💾 Saved model.pkl (best: {best_name})")


# -------- SAVE EVALUATION RESULTS --------
with open("evaluation_results.json", "w") as f:
    json.dump(results, f, indent=2, default=str)
print("   💾 Saved evaluation_results.json")


# -------- SHAP EXPLAINABILITY --------
if HAS_SHAP:
    print("\n🔍 Generating SHAP explanations...")

    os.makedirs("shap_outputs", exist_ok=True)

    # Use a smaller sample for SHAP (faster)
    sample_size = min(500, len(X_test))
    X_sample = X_test.iloc[:sample_size]

    explainer = shap.TreeExplainer(best_model)
    shap_values = explainer.shap_values(X_sample)

    # For binary classification, shap_values may be a list [class0, class1]
    if isinstance(shap_values, list):
        shap_vals = shap_values[1]  # Use class 1 (phishing) SHAP values
    else:
        shap_vals = shap_values

    # Feature importance bar plot
    plt.figure(figsize=(10, 6))
    shap.summary_plot(shap_vals, X_sample, feature_names=feature_names,
                      plot_type="bar", show=False)
    plt.title("SHAP Feature Importance (Phishing Detection)")
    plt.tight_layout()
    plt.savefig("shap_outputs/feature_importance.png", dpi=150)
    plt.close()
    print("   📊 Saved shap_outputs/feature_importance.png")

    # Summary dot plot
    plt.figure(figsize=(10, 6))
    shap.summary_plot(shap_vals, X_sample, feature_names=feature_names,
                      show=False)
    plt.title("SHAP Summary Plot")
    plt.tight_layout()
    plt.savefig("shap_outputs/summary_plot.png", dpi=150)
    plt.close()
    print("   📊 Saved shap_outputs/summary_plot.png")

    # Save mean absolute SHAP values for API use
    mean_shap = np.abs(shap_vals).mean(axis=0)
    # Handle case where mean_shap elements might be arrays
    shap_importance = {}
    for name, v in zip(feature_names, mean_shap):
        if hasattr(v, '__len__'):
            shap_importance[name] = round(float(np.mean(v)), 4)
        else:
            shap_importance[name] = round(float(v), 4)
    shap_importance = dict(sorted(shap_importance.items(), key=lambda x: x[1], reverse=True))

    with open("shap_outputs/feature_importance.json", "w") as f:
        json.dump(shap_importance, f, indent=2)
    print("   💾 Saved shap_outputs/feature_importance.json")

    # Save explainer for API
    with open("shap_outputs/explainer.pkl", "wb") as f:
        pickle.dump(explainer, f)
    print("   💾 Saved shap_outputs/explainer.pkl")

else:
    print("\n⚠️  Skipping SHAP (not installed)")


print("\n✅ Training pipeline complete!")