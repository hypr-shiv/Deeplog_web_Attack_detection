from pathlib import Path

import joblib
import pandas as pd

from feature_exactor import EXPECTED_FEATURES, extract_features, validate_features


DEFAULT_MODEL_PATH = Path(__file__).with_name("deeplog_web_attack_model.pkl")
DEFAULT_FEATURES_PATH = Path(__file__).with_name("deeplog_features.pkl")
DEFAULT_THRESHOLD = 0.45


class Predictor:
    def __init__(
        self,
        model_path=DEFAULT_MODEL_PATH,
        features_path=DEFAULT_FEATURES_PATH,
        threshold=DEFAULT_THRESHOLD,
    ):
        if not 0 <= threshold <= 1:
            raise ValueError("threshold must be between 0 and 1")

        self.model = joblib.load(model_path)
        self.features = list(joblib.load(features_path))
        self.threshold = float(threshold)

        if self.features != EXPECTED_FEATURES:
            raise ValueError(
                "Model feature schema does not match the shared feature extractor."
            )

        model_features = list(getattr(self.model, "feature_names_in_", []))
        if model_features and model_features != self.features:
            raise ValueError(
                "Model feature names do not match the saved feature schema."
            )

        if 1 not in self.model.classes_:
            raise ValueError("Model must contain class label 1 for Attack")

        self.attack_class_index = list(self.model.classes_).index(1)

    @staticmethod
    def classify_signals(features, raw_prob, threshold):
        sql = (
            features.get("sql_keyword_count", 0) > 0
            or features.get("sql_comment_count", 0) > 0
            or features.get("sql_logic_count", 0) > 0
            or features.get("query_sql_keyword_count", 0) > 0
        )
        xss = (
            features.get("xss_angle_bracket_count", 0) > 0
            or features.get("javascript_keyword_count", 0) > 0
        )
        traversal = (
            features.get("dot_dot_count", 0) > 0
            or features.get("etc_passwd_indicator", 0) > 0
        )
        ssi = features.get("ssi_exec_indicator", 0) > 0
        anomalous = (
            features.get("special_char_count", 0) >= 3
            or features.get("encoding_count", 0) >= 3
            or features.get("content_encoded_count", 0) >= 3
        )

        has_attack_signal = sql or xss or traversal or ssi or anomalous
        if not has_attack_signal:
            prob = min(raw_prob, 0.05 + 0.1 * features.get("sensitive_endpoint_indicator", 0))
        else:
            prob = raw_prob

        if sql:
            attack_type = "SQL Injection"
        elif xss:
            attack_type = "Cross-Site Scripting (XSS)"
        elif traversal:
            attack_type = "Path Traversal"
        elif ssi:
            attack_type = "Command Injection / SSI"
        elif anomalous:
            attack_type = "Malicious Encoding / Anomaly"
        elif prob >= threshold:
            attack_type = "Suspicious Request"
        else:
            attack_type = "None"

        prediction = "Attack" if prob >= threshold else "Normal"
        return prediction, round(prob, 4), attack_type

    def predict_features(self, feature_data, threshold=None):
        features = dict(feature_data)
        validate_features(features)

        selected_threshold = self.threshold if threshold is None else float(threshold)
        if not 0 <= selected_threshold <= 1:
            raise ValueError("threshold must be between 0 and 1")

        input_df = pd.DataFrame([features], columns=self.features)
        probabilities = self.model.predict_proba(input_df)[0]
        raw_probability = float(probabilities[self.attack_class_index])
        prediction, attack_probability, attack_type = self.classify_signals(
            features, raw_probability, selected_threshold
        )

        return {
            "prediction": prediction,
            "attack_probability": attack_probability,
            "threshold": selected_threshold,
            "attack_type": attack_type,
            "features": features,
        }

    def predict_request(
        self,
        url,
        method="GET",
        content="",
        content_type="",
        content_length=None,
        threshold=None,
    ):
        features = extract_features(
            url=url,
            method=method,
            content=content,
            content_type=content_type,
            content_length=content_length,
        )
        return self.predict_features(features, threshold=threshold)

    def predict_requests(self, requests, threshold=None):
        """Predict many requests in one model call for upload-scale workloads."""
        features = [
            extract_features(
                url=request.get("url", ""),
                method=request.get("method", "GET"),
                content=request.get("content", ""),
                content_type=request.get("content_type", ""),
                content_length=request.get("content_length"),
            )
            for request in requests
        ]
        if not features:
            return []

        selected_threshold = self.threshold if threshold is None else float(threshold)
        if not 0 <= selected_threshold <= 1:
            raise ValueError("threshold must be between 0 and 1")

        input_df = pd.DataFrame(features, columns=self.features)
        raw_probabilities = self.model.predict_proba(input_df)[:, self.attack_class_index]
        results = []
        for feature_dict, raw_prob in zip(features, raw_probabilities):
            prediction, attack_prob, attack_type = self.classify_signals(
                feature_dict, float(raw_prob), selected_threshold
            )
            results.append({
                "prediction": prediction,
                "attack_probability": attack_prob,
                "threshold": selected_threshold,
                "attack_type": attack_type,
                "features": feature_dict,
            })
        return results
