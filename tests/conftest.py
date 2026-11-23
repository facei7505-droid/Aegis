import pytest


@pytest.fixture(autouse=True)
def _private_ai_ledger(tmp_path, monkeypatch):
    """Tests never touch the real spending ledger (~/.aegis/ai-spend.json) or the user's AI limits."""
    monkeypatch.setenv("AEGIS_AI_LEDGER", str(tmp_path / "ai-spend.json"))
    monkeypatch.delenv("AEGIS_AI_BUDGET", raising=False)
    monkeypatch.delenv("AEGIS_AI_TOTAL_BUDGET", raising=False)
