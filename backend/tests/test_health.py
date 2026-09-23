"""
Tests — Health endpoint
========================
Verifies GET /api/health returns expected shape and status.
"""

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_returns_200():
    response = client.get("/api/health")
    assert response.status_code == 200


def test_health_response_body():
    response = client.get("/api/health")
    body = response.json()
    assert body["status"] == "healthy"
    assert body["service"] == "n-casa-backend"


def test_health_content_type():
    response = client.get("/api/health")
    assert "application/json" in response.headers["content-type"]
