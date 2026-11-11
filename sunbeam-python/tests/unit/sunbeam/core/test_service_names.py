# SPDX-FileCopyrightText: 2026 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

from sunbeam.core.service_names import (
    APPLICATION_ALIASES,
    SERVICE_ALIASES,
    display_name,
    resolve_service,
)


def test_resolve_service_alias():
    assert resolve_service("compute") == "nova"


def test_resolve_service_application_name_is_kept():
    assert resolve_service("nova") == "nova"


def test_resolve_service_unknown_name_is_kept():
    assert resolve_service("gnocchi") == "gnocchi"
    assert resolve_service("nope") == "nope"


def test_display_name_known_application():
    assert display_name("nova") == "compute"


def test_display_name_unknown_application_is_kept():
    assert display_name("gnocchi") == "gnocchi"


def test_aliases_are_unique():
    assert len(APPLICATION_ALIASES) == len(SERVICE_ALIASES)
