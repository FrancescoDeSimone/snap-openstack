# SPDX-FileCopyrightText: 2026 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

"""Cluster wide configuration and policy overrides for OpenStack services."""

import functools
import logging
from pathlib import Path
from typing import Literal

import click
from rich.console import Console
from rich.table import Column, Table

from sunbeam.core.checks import JujuLoginCheck, run_preflight_checks
from sunbeam.core.common import CONTEXT_SETTINGS
from sunbeam.core.config_overrides import (
    ConfigOverridesError,
    ValidationResult,
    apply_overrides,
    attach_overrides,
    check_charm_support,
    get_applied_overrides,
    get_override,
    read_overrides,
    set_override,
    set_override_half,
    validate_overrides,
)
from sunbeam.core.deployment import Deployment
from sunbeam.core.juju import JujuException, JujuHelper
from sunbeam.core.policy_advisories import advisories_for
from sunbeam.core.service_names import display_name, resolve_service
from sunbeam.utils import CatchGroup, click_option_show_hints

LOG = logging.getLogger(__name__)
console = Console()

Half = Literal["config", "policy"]

CONFIG_LABEL = "service configuration"
POLICY_LABEL = "policy"


# --- shared plumbing -------------------------------------------------------


def _handle_errors(func):
    """Turn config-override/juju errors into clean click errors."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (ConfigOverridesError, JujuException) as e:
            raise click.ClickException(str(e)) from e

    return wrapper


def _jhelper(deployment: Deployment) -> JujuHelper:
    return JujuHelper(deployment.juju_controller)


def _preflight_checks(deployment: Deployment) -> None:
    run_preflight_checks([JujuLoginCheck(deployment.juju_account)], console)


def _read_file(file: Path) -> str:
    """Read an override file, refusing an empty file.

    An empty override file means "no override" to the charm, so accepting it
    here would silently clear an override instead of setting one.
    """
    try:
        text = file.read_text()
    except OSError as e:
        raise click.ClickException(f"unable to read {file}: {e}") from e
    if not text.strip():
        raise click.ClickException(f"{file} is empty")
    return text


def _print_validation(result: ValidationResult) -> None:
    for error in result.errors:
        console.print(f"[red]error:[/red] {error}")
    for warning in result.warnings:
        console.print(f"[yellow]warning:[/yellow] {warning}")
    for name, check in result.checks.items():
        console.print(f"check {name}: {check}")
    if result.valid:
        console.print("[green]Validation succeeded.[/green]")
    elif not result.errors and result.summary:
        console.print(f"[red]{result.summary}[/red]")


def _print_advisories(app: str, policy_text: str) -> None:
    for note in advisories_for(app, policy_text):
        console.print(f"[yellow]impact:[/yellow] {note}")


def _validate_half(jhelper: JujuHelper, app: str, text: str) -> bool:
    """Validate one override file on the unit; True when the service accepts it."""
    result = validate_overrides(jhelper, app, text)
    _print_validation(result)
    return result.valid


def _apply_record(
    deployment: Deployment,
    jhelper: JujuHelper,
    app: str,
    record: dict,
    label: str,
) -> None:
    """Attach the stored record and apply it, then mark the record enabled."""
    attach_overrides(jhelper, app, record.get("config"), record.get("policy"))
    result = apply_overrides(jhelper, app)
    _print_validation(result)
    if not result.valid:
        raise ConfigOverridesError(
            f"Validation failed for {display_name(app)!r}; "
            "the override was not applied."
        )
    record["enabled"] = True
    set_override(deployment.get_client(), app, record)
    console.print(f"Applied {label} override for {display_name(app)!r}.")


def _detach(jhelper: JujuHelper, app: str) -> None:
    """Clear the attached resources and let the charm drop both drop-ins."""
    attach_overrides(jhelper, app, None, None)
    _print_validation(apply_overrides(jhelper, app))


def _write_overrides(output_dir: Path, overrides: dict) -> int:
    """Write every stored override into ``output_dir``, returning the count."""

    def _write(path: Path, text: str) -> None:
        try:
            path.write_text(text)
        except OSError as e:
            raise click.ClickException(f"unable to write {path}: {e}") from e

    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise click.ClickException(f"unable to create {output_dir}: {e}") from e
    written = 0
    for app in sorted(overrides):
        record = overrides[app]
        if record.get("config") is not None:
            _write(output_dir / f"{app}.conf", record["config"])
            written += 1
        if record.get("policy") is not None:
            _write(output_dir / f"{app}.policy.yaml", record["policy"])
            written += 1
    return written


# --- verb implementations --------------------------------------------------


def _set(ctx: click.Context, service: str, file: Path, half: Half, label: str) -> None:
    deployment: Deployment = ctx.obj
    app = resolve_service(service)
    text = _read_file(file)
    _preflight_checks(deployment)
    jhelper = _jhelper(deployment)
    check_charm_support(jhelper, app, policy=half == "policy")
    if half == "policy":
        _print_advisories(app, text)
    client = deployment.get_client()
    record = set_override_half(client, app, half, text)
    console.print(
        f"Stored {label} override for {display_name(app)!r} "
        f"(sha256 {record['sha256'][:12]})."
    )
    if not _validate_half(jhelper, app, text):
        raise ConfigOverridesError(
            f"Validation failed for {display_name(app)!r}; "
            "the override was stored but not applied."
        )
    _apply_record(deployment, jhelper, app, record, label)


def _show(
    ctx: click.Context,
    service: str,
    half: Half,
    label: str,
    output: Path | None,
) -> None:
    deployment: Deployment = ctx.obj
    app = resolve_service(service)
    record = get_override(deployment.get_client(), app)
    text = record.get(half)
    if text is None:
        raise ConfigOverridesError(
            f"no {label} override stored for {display_name(app)!r}"
        )
    if output is not None:
        try:
            output.write_text(text)
        except OSError as e:
            raise click.ClickException(f"unable to write {output}: {e}") from e
        console.print(f"Wrote {label} to {output}")
    else:
        console.print(text, markup=False, highlight=False)
        if half == "policy":
            _print_advisories(app, text)
    console.print(
        f"Enabled: {'yes' if record.get('enabled') else 'no'} "
        f"(sha256 {str(record.get('sha256', ''))[:12]})"
    )
    try:
        applied = get_applied_overrides(_jhelper(deployment), app)
    except (ConfigOverridesError, JujuException) as e:
        LOG.debug("Could not fetch applied overrides for %s: %r", app, e)
        return
    console.print(f"Applied on the unit: {', '.join(applied) or 'none'}")


def _clear(ctx: click.Context, service: str, half: Half, label: str) -> None:
    deployment: Deployment = ctx.obj
    app = resolve_service(service)
    client = deployment.get_client()
    record = get_override(client, app)
    if record.get(half) is None:
        raise ConfigOverridesError(
            f"no {label} override stored for {display_name(app)!r}"
        )
    _preflight_checks(deployment)
    jhelper = _jhelper(deployment)
    record = set_override_half(client, app, half, None)
    if record["config"] is None and record["policy"] is None:
        _detach(jhelper, app)
        console.print(f"Cleared {label} override for {display_name(app)!r}.")
        return
    _apply_record(deployment, jhelper, app, record, label)


def _list(ctx: click.Context, output_dir: Path | None) -> None:
    overrides = read_overrides(ctx.obj.get_client())
    if not overrides:
        console.print("No service overrides stored.")
        return
    if output_dir is not None:
        written = _write_overrides(output_dir, overrides)
        console.print(f"Collected {written} override(s) into {output_dir}.")
        return
    table = Table(
        Column("Service"),
        Column("Application"),
        Column("Config"),
        Column("Policy"),
        Column("Enabled"),
        Column("sha256"),
        title="Service overrides",
    )
    for app in sorted(overrides):
        record = overrides[app]
        table.add_row(
            display_name(app),
            app,
            "yes" if record.get("config") is not None else "no",
            "yes" if record.get("policy") is not None else "no",
            "yes" if record.get("enabled") else "no",
            str(record.get("sha256", ""))[:12],
        )
    console.print(table)


# --- command factories -----------------------------------------------------


def _make_set(half: Half, label: str) -> click.Command:
    @click.command("set")
    @click.argument("service", type=str)
    @click.argument(
        "file",
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
    )
    @click_option_show_hints
    @click.pass_context
    @_handle_errors
    def set_command(
        ctx: click.Context, service: str, file: Path, show_hints: bool
    ) -> None:
        """Store an override file for a service and apply it.

        The content is validated on the deployed service first: content the
        service rejects is stored but never attached, so it can be inspected
        and fixed.  The other half of the override is left untouched.
        """
        _set(ctx, service, file, half, label)

    return set_command


def _make_show(half: Half, label: str) -> click.Command:
    @click.command("show")
    @click.argument("service", type=str)
    @click.option(
        "--output",
        type=click.Path(dir_okay=False, path_type=Path),
        default=None,
        help="Write the stored file to this path instead of printing it.",
    )
    @click.pass_context
    @_handle_errors
    def show_command(ctx: click.Context, service: str, output: Path | None) -> None:
        """Print the stored override of a service and what the unit applies."""
        _show(ctx, service, half, label, output)

    return show_command


def _make_clear(half: Half, label: str) -> click.Command:
    @click.command("clear")
    @click.argument("service", type=str)
    @click_option_show_hints
    @click.pass_context
    @_handle_errors
    def clear_command(ctx: click.Context, service: str, show_hints: bool) -> None:
        """Drop the stored override of a service and remove it from the unit."""
        _clear(ctx, service, half, label)

    return clear_command


def _make_list() -> click.Command:
    @click.command("list")
    @click.option(
        "--output-dir",
        type=click.Path(file_okay=False, path_type=Path),
        default=None,
        help="Write every stored override into this directory.",
    )
    @click.pass_context
    @_handle_errors
    def list_command(ctx: click.Context, output_dir: Path | None) -> None:
        """List the services with a stored override."""
        _list(ctx, output_dir)

    return list_command


@click.group("config", context_settings=CONTEXT_SETTINGS, cls=CatchGroup)
@click.pass_context
def config_group(ctx: click.Context) -> None:
    """Manage service configuration (oslo.config) overrides."""


@click.group("policy", context_settings=CONTEXT_SETTINGS, cls=CatchGroup)
@click.pass_context
def policy_group(ctx: click.Context) -> None:
    """Manage service policy (oslo.policy) overrides."""


config_group.add_command(_make_set("config", CONFIG_LABEL))
config_group.add_command(_make_show("config", CONFIG_LABEL))
config_group.add_command(_make_clear("config", CONFIG_LABEL))
config_group.add_command(_make_list())

policy_group.add_command(_make_set("policy", POLICY_LABEL))
policy_group.add_command(_make_show("policy", POLICY_LABEL))
policy_group.add_command(_make_clear("policy", POLICY_LABEL))
policy_group.add_command(_make_list())
