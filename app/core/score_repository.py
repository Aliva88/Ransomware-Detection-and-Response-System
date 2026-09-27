from app.database import SessionLocal
from app.models import Score


def save_score(score, level, system_id):
    """
    Save a threat score and threat level
    into the scores table.
    """

    db = SessionLocal()

    try:
        score_record = Score(
            score=score,
            level=level,
            system_id=system_id
        )

        db.add(score_record)
        db.commit()
        db.refresh(score_record)

        return score_record

    finally:
        db.close()