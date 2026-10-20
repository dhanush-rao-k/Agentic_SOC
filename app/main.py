
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from app.elastic import check_connection, search_ssh_failures

app = FastAPI(
    title="Agentic SOC",
    description="Alert investigation API",
    version="0.1.0",
)


class AlertInput(BaseModel):
    alert_id: str
    rule_name: str
    host_name: str
    message: str
    timestamp: str
    source_ip: str | None = None


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/health/elasticsearch")
def elasticsearch_health():
    try:
        return check_connection()
    except Exception as exc:
        print(f"Elasticsearch health check failed: {type(exc).__name__}: {exc}")
        raise HTTPException(
            status_code=503,
            detail=f"{type(exc).__name__}: {exc}",
        )


@app.get("/evidence/ssh-failures")
def ssh_failures(size: int = 10):
    if not 1 <= size <= 100:
        raise HTTPException(
            status_code=400,
            detail="size must be between 1 and 100",
        )

    try:
        events = search_ssh_failures(size=size)
        return {
            "count": len(events),
            "events": events,
        }
    except Exception:
        raise HTTPException(
            status_code=502,
            detail="Failed to retrieve SSH evidence from Elasticsearch.",
        )


@app.post("/investigate")
def investigate(alert: AlertInput):
    return {
        "alert_id": alert.alert_id,
        "status": "received",
        "summary": (
            f"Received alert '{alert.rule_name}' "
            f"for host '{alert.host_name}'."
        ),
    }
