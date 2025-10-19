# threat_detection/responses_routes.py
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from .responses_service import list_responses, create_response
from .responses_schema import ResponseOut
from .rule_engine import RuleEngine
from .test_logs import sample_logs

router = APIRouter(prefix="/threats", tags=["Threat Detection"])


@router.get("/responses", response_model=list[ResponseOut])
def get_all_responses(db: Session = Depends(get_db)):
    """Fetch the latest rule-engine responses."""
    return list_responses(db)


@router.post("/run_rules", response_model=list[ResponseOut])
def run_rules(db: Session = Depends(get_db)):
    """
    Run rule engine on sample logs (demo endpoint).
    Simulates integrity break + records detections into the responses table.
    """
    # Simulate integrity check failure (for demo)
    def fake_integrity_check():
        return False

    # Initialize rule engine
    engine = RuleEngine(integrity_check_fn=fake_integrity_check)

    # Run on sample logs
    detections = engine.run(sample_logs())

    # Save detections into database
    saved = [create_response(db, d.to_dict()) for d in detections]

    return saved
