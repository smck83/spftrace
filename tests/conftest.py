from __future__ import annotations

import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--rfc-strict",
        action="store_true",
        default=False,
        help=(
            "Fail rather than skip if the RFC 7208 corpus cannot be fetched. "
            "CI passes this so a network blip can never be mistaken for a pass."
        ),
    )


@pytest.fixture(scope="session")
def rfc_strict(request) -> bool:
    return bool(request.config.getoption("--rfc-strict"))
