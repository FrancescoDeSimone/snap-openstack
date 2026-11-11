# SPDX-FileCopyrightText: 2026 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

from sunbeam.core.policy_advisories import advisories_for


def test_known_rule_returns_impact_note():
    assert advisories_for("neutron", "create_subnet: role:admin\n") == [
        "create_subnet: affects instances, routers, CaaS clusters and load "
        "balancers, which all need a subnet"
    ]


def test_comment_only_policy_has_no_note():
    assert advisories_for("neutron", "# only a comment\n") == []


def test_unparseable_policy_has_no_note():
    assert advisories_for("neutron", "not yaml: [\n") == []


def test_rule_known_for_another_application_has_no_note():
    assert advisories_for("glance", "create_subnet: role:admin\n") == []


def test_nova_server_create_returns_one_note():
    notes = advisories_for("nova", "os_compute_api:servers:create: role:admin\n")

    assert len(notes) == 1
    assert notes[0].startswith("os_compute_api:servers:create: affects ")


def test_repeated_rule_is_not_duplicated():
    text = "create_subnet: role:admin\ncreate_subnet: role:reader\n"

    assert len(advisories_for("neutron", text)) == 1
