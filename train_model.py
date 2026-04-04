import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib

# simple synthetic data
data = []

for _ in range(1000):
    data.append([0, 500, 0])  # normal

for _ in range(100):
    data.append([0, 50000, 10])  # anomaly

X = np.array(data)

model = IsolationForest(contamination=0.1)
model.fit(X)

joblib.dump(model, "model.pkl")

print("Model trained and saved!")
