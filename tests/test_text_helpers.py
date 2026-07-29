from __future__ import annotations

import pytest

import main


@pytest.mark.parametrize("max_chars", list(range(1, 60)))
def test_shorten_middle_never_exceeds_its_limit(max_chars):
    """Regression: limits 9 to 21 used to return strings longer than max_chars.

    shorten_middle feeds fixed width table cells and card labels, so a result
    that is longer than the requested limit defeats the whole point of calling
    it and pushes the layout wider than the column.
    """
    result = main.shorten_middle("x" * 200, max_chars)
    assert len(result) <= max_chars, f"limit {max_chars} produced {len(result)} chars"


def test_shorten_middle_leaves_short_text_alone():
    assert main.shorten_middle("short", 40) == "short"
    assert main.shorten_middle("exactly-ten", 11) == "exactly-ten"


def test_shorten_middle_keeps_both_ends_and_marks_the_cut():
    result = main.shorten_middle("start-" + "m" * 100 + "-end", 30)
    assert result.startswith("start-")
    assert result.endswith("-end")
    assert "..." in result
    assert len(result) <= 30


def test_shorten_middle_is_still_useful_at_the_limits_the_app_uses():
    """The real call sites pass these limits."""
    long_url = "https://example.com/" + "segment/" * 40
    for limit in (main.TABLE_URL_LIMIT, main.TABLE_MESSAGE_LIMIT, main.CARD_URL_LIMIT, main.CARD_MESSAGE_LIMIT, 32, 34):
        out = main.shorten_middle(long_url, limit)
        assert len(out) <= limit
        assert "..." in out
