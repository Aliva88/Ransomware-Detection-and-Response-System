from app.core.score_repository import save_score


def test_save_score():

    record = save_score(
        score=70,
        level="High"
    )

    assert record.id is not None
    assert record.score == 70
    assert record.level == "High"