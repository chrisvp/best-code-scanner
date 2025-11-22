from fastapi.testclient import TestClient
from app.main import app
import os

client = TestClient(app)

def test_read_main():
    response = client.get("/")
    assert response.status_code == 200
    assert "Security Scans" in response.text

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_create_scan():
    # Mock the background task to avoid actual execution during test if needed, 
    # but for now let's just see if the endpoint accepts the request.
    # We need to mock the DB or use a test DB. 
    # The config uses sqlite:///./scans.db, which is fine for a simple test, 
    # but ideally we'd override it.
    
    response = client.post(
        "/scan/start",
        data={"target_url": "https://github.com/test/repo.git"},
        headers={"HX-Request": "true"}
    )
    assert response.status_code == 200
    # HTMX returns a partial
    assert "test/repo.git" in response.text
