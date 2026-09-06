from flask import Flask, request, jsonify, send_from_directory
import joblib
import os
import numpy as np
import json

app = Flask(__name__, static_folder='static')

# Load model (N=15)
MODEL_PATH = 'models/rf_model_n15.joblib'
try:
    model = joblib.load(MODEL_PATH)
    print(f"Loaded model from {MODEL_PATH}")
except Exception as e:
    print(f"Error loading model: {e}")
    model = None

import random

# Load real samples for the UI simulator
try:
    with open('data/real_samples.json', 'r') as f:
        real_samples = json.load(f)
except:
    real_samples = {}

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/get_sample/<app_name>')
def get_sample(app_name):
    if app_name in real_samples and len(real_samples[app_name]) > 0:
        sample = random.choice(real_samples[app_name])
        return jsonify({"features": sample})
    return jsonify({"error": "No samples found"}), 404

@app.route('/predict', methods=['POST'])
def predict():
    if model is None:
        return jsonify({"error": "Model not loaded"}), 500
        
    data = request.json
    features = data.get("features", [])
    
    if len(features) != 45: # 15 packets * 3 features (size, dir, iat)
        return jsonify({"error": f"Expected 45 features, got {len(features)}"}), 400
        
    # Convert to 2D array for sklearn
    X = np.array(features).reshape(1, -1)
    
    # Predict
    prediction = model.predict(X)[0]
    probabilities = model.predict_proba(X)[0]
    
    # Get top 3 classes
    classes = model.classes_
    top_indices = np.argsort(probabilities)[::-1][:3]
    top_predictions = [{"class": classes[i], "prob": float(probabilities[i])} for i in top_indices]
    
    return jsonify({
        "prediction": prediction,
        "confidence": float(probabilities[top_indices[0]]),
        "top_3": top_predictions
    })

if __name__ == '__main__':
    # Ensure static folder exists
    os.makedirs('static', exist_ok=True)
    app.run(debug=True, port=5000)
