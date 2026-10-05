from app.core.score_repository import save_score


TEST_SYSTEM_ID = 62


def test_save_score():

    record = save_score(
        system_id=TEST_SYSTEM_ID,
        score=70,
        level="High"
    )

    assert record.id is not None
    assert record.score == 70
    assert record.level == "High"