# SPDX-FileCopyrightText: 2026 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

"""Customer facing service names for the ``sunbeam cluster`` override commands."""

SERVICE_ALIASES: dict[str, str] = {
    "compute": "nova",
    "network": "neutron",
    "image": "glance",
    "identity": "keystone",
    "placement": "placement",
    "block-storage": "cinder",
    "dashboard": "horizon",
    "caas": "magnum",
    "dns": "designate",
    "orchestration": "heat",
    "loadbalancer": "octavia",
    "secrets": "barbican",
    "baremetal": "ironic",
    "shared-filesystem": "manila",
    "telemetry": "aodh",
    "resource-optimization": "watcher",
    "instance-recovery": "masakari",
    "images-sync": "images-sync",
    "cloudkitty": "cloudkitty",
    "openstack-exporter": "openstack-exporter",
}

APPLICATION_ALIASES: dict[str, str] = {
    app: alias for alias, app in SERVICE_ALIASES.items()
}


def resolve_service(name: str) -> str:
    """Return the juju application name for a service name."""
    return SERVICE_ALIASES.get(name, name)


def display_name(app: str) -> str:
    """Return the customer facing name for a juju application."""
    return APPLICATION_ALIASES.get(app, app)
