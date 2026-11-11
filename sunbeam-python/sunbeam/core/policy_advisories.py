# SPDX-FileCopyrightText: 2026 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

"""Which functionality a well known oslo.policy rule affects."""

import yaml

RULE_IMPACT: dict[str, dict[str, str]] = {
    "neutron": {
        "create_network": (
            "instances, routers, CaaS clusters and load balancers, "
            "which all need a network"
        ),
        "create_subnet": (
            "instances, routers, CaaS clusters and load balancers, "
            "which all need a subnet"
        ),
        "create_subnetpool": (
            "subnets carved from an address pool, used by the same services"
        ),
        "create_port": "interface attachment for instances, routers and load balancers",
        "create_port:fixed_ips": (
            "interface attachment on a fixed IP for instances, routers "
            "and load balancers"
        ),
        "create_floatingip": "external reachability of instances and load balancers",
    },
    "glance": {
        "get_image": (
            "single image visibility, which instance and CaaS cluster launches read"
        ),
        "get_images": "image listing, which instance and CaaS cluster launches read",
    },
    "nova": {
        "os_compute_api:servers:create": (
            "instance creation, called by CaaS clusters and every automation"
        ),
        "os_compute_api:servers:index": "instance listing for project members",
        "os_compute_api:servers:detail": "instance detail listing for project members",
        "os_compute_api:servers:show": (
            "instance lookup by project members and operators"
        ),
    },
}


def advisories_for(app: str, policy_text: str) -> list[str]:
    """Return one impact note per rule the policy text defines and the table knows."""
    try:
        rules = yaml.safe_load(policy_text)
    except yaml.YAMLError:
        return []
    if not isinstance(rules, dict):
        return []
    known = RULE_IMPACT.get(app, {})
    notes: list[str] = []
    for rule in rules:
        impact = known.get(str(rule))
        if impact is None:
            continue
        note = f"{rule}: affects {impact}"
        if note not in notes:
            notes.append(note)
    return notes
