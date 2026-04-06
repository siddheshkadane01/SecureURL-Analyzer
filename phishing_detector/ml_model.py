from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import numpy as np
import os
import pickle
from .dataset_loader import load_dataset
from .logger import Logger

class PhishingModel:
    def __init__(self, dataset_path="Dataset1.csv"):
        self.dataset_path = dataset_path
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.feature_names = None
        self.is_trained = False

    def train(self):
        model_file = "rf_model.pkl"
        if os.path.exists(model_file):
            Logger.ml(f"Loading pre-trained model from {model_file}...")
            with open(model_file, "rb") as f:
                saved_data = pickle.load(f)
                self.model = saved_data["model"]
                self.feature_names = saved_data["feature_names"]
            self.is_trained = True
            return True

        Logger.ml(f"Loading dataset from {self.dataset_path}...")
        try:
            X, y = load_dataset(self.dataset_path)
        except Exception as e:
            Logger.error(str(e))
            return False

        self.feature_names = X.columns.tolist()

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        Logger.ml("Training Random Forest classifier...")
        self.model.fit(X_train, y_train)

        # Evaluate model accuracy
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred) * 100
        Logger.ml(f"Model accuracy: {accuracy:.2f}%")
        
        # Save model to file
        Logger.ml(f"Saving trained model to {model_file}...")
        with open(model_file, "wb") as f:
            pickle.dump({"model": self.model, "feature_names": self.feature_names}, f)

        self.is_trained = True
        return True

    def predict(self, feature_vector):
        if not self.is_trained:
            Logger.error("Model is not trained yet!")
            return None, None

        # RandomForest expects a 2D array or DataFrame
        import pandas as pd
        fv_df = pd.DataFrame([feature_vector], columns=self.feature_names)
        
        # Determine log probabilities and single prediction
        prob = self.model.predict_proba(fv_df)[0]
        prediction_val = self.model.predict(fv_df)[0]

        prediction_label = "PHISHING" if prediction_val == 1 else "LEGITIMATE"
        confidence = prob[1] if prediction_val == 1 else prob[0]

        return prediction_label, round(confidence, 2)

    def print_feature_importance(self):
        if not self.is_trained or self.feature_names is None:
            return

        importances = self.model.feature_importances_
        print("\nFeature Importance:")
        for name, importance in zip(self.feature_names, importances):
            print(f"{name}: {importance:.2f}")
        print("-" * 30)

