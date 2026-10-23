from __future__ import annotations

from typing import Any

from predictor import Predictor

from app.core.config import settings


class MLService:
    def __init__(self) -> None:
        self.predictor: Predictor | None = None

    def load(self) -> Predictor:
        if self.predictor is None:
            self.predictor = Predictor(threshold=settings.detection_threshold)
        return self.predictor

    @staticmethod
    def risk_level(probability: float, prediction: str) -> str:
        if prediction != "Attack":
            return "Low"
        if probability >= 0.9:
            return "Critical"
        if probability >= 0.7:
            return "High"
        return "Medium"

    def predict_many(self, requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
        predictions = self.load().predict_requests(requests)
        return [
            {
                **prediction,
                "risk": self.risk_level(prediction["attack_probability"], prediction["prediction"]),
                "model_version": settings.model_version,
            }
            for prediction in predictions
        ]

    def predict_one(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.predict_many([request])[0]

    def predict(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.predict_one(request)


ml_service = MLService()
