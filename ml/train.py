import pandas as pd
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# -------- LOAD PROCESSED DATA --------
data = pd.read_csv("processed_dataset.csv")

X = data.drop("label", axis=1)
y = data["label"]

# -------- SPLIT --------
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    stratify=y,
    random_state=42
)

# -------- MODEL --------
model = RandomForestClassifier(
    n_estimators=500,
    class_weight="balanced",
    n_jobs=-1,
    random_state=42
)

model.fit(X_train, y_train)

pickle.dump(model, open("model.pkl","wb"))

print("✅ Model trained successfully")