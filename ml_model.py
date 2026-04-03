import joblib
import numpy as np

model = joblib.load("model.pkl")

def extract_features(pkt):
    proto = 0
    length = len(pkt)
    flags = 0

    if pkt.haslayer("TCP"):
        flags = int(pkt["TCP"].flags)

    return np.array([[proto, length, flags]])

def predict_anomaly(pkt):
    try:
        features = extract_features(pkt)
        result = model.predict(features)
        return result[0] == -1
    except:
        return False