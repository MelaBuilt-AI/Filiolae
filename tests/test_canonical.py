from __future__ import annotations

import pytest

from filiolae.canonical import CanonicalValueError, canonical_json


def test_canonical_json_is_stable() -> None:
    assert canonical_json({"z": 1, "a": [True, None, "μ"]}) == '{"a":[true,null,"μ"],"z":1}'.encode()


@pytest.mark.parametrize("value", [1.5, {1: "bad"}, {"x": object()}])
def test_canonical_rejects_ambiguous_values(value: object) -> None:
    with pytest.raises(CanonicalValueError):
        canonical_json(value)
