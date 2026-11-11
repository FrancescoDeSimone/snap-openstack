# SPDX-FileCopyrightText: 2026 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner

from sunbeam.clusterd.service import ConfigItemNotFoundException
from sunbeam.commands.overrides import config_group, policy_group
from sunbeam.core import config_overrides as co
from sunbeam.core.juju import JujuException

VALIDATE_OK = {
    "valid": "true",
    "errors": "[]",
    "warnings": "[]",
    "checks": "{}",
}


@pytest.fixture()
def runner():
    return CliRunner()


@pytest.fixture()
def deployment():
    d = Mock()
    d.juju_controller = "controller"
    d.juju_account = Mock()
    return d


@pytest.fixture()
def client(deployment):
    return deployment.get_client.return_value


def _empty_store(client):
    client.cluster.get_config.side_effect = ConfigItemNotFoundException()


def _seed(client, overrides):
    client.cluster.get_config.side_effect = None
    client.cluster.get_config.return_value = json.dumps({"overrides": overrides})


def _written_overrides(client):
    key, value = client.cluster.update_config.call_args.args
    assert key == co.CONFIG_FILE_OVERRIDES_KEY
    return json.loads(value)["overrides"]


@pytest.fixture()
def preflight_patch():
    with patch("sunbeam.commands.overrides.run_preflight_checks") as p:
        yield p


@pytest.fixture()
def jhelper_patch():
    with patch("sunbeam.commands.overrides.JujuHelper") as p:
        helper = p.return_value
        helper.get_application_resources.return_value = [
            {"name": "config-override", "type": "file"},
            {"name": "policy-override", "type": "file"},
        ]
        helper.get_leader_unit.return_value = "glance/0"
        helper.run_action.return_value = dict(VALIDATE_OK)
        yield p


def _capture_attaches(helper):
    attached = {}

    def _capture(app, model, resource, path):
        attached[resource] = (Path(path).name, Path(path).read_text())

    helper.attach_resource.side_effect = _capture
    return attached


def _action_calls(helper):
    return [call.args for call in helper.run_action.call_args_list]


def test_policy_set_stores_validates_attaches_and_applies(
    runner, deployment, client, preflight_patch, jhelper_patch, tmp_path
):
    _empty_store(client)
    policy_file = tmp_path / "glance.policy.yaml"
    policy_file.write_text("get_image: role:admin\n")
    helper = jhelper_patch.return_value
    attached = _capture_attaches(helper)

    result = runner.invoke(
        policy_group, ["set", "glance", str(policy_file)], obj=deployment
    )

    assert result.exit_code == 0, result.output
    record = _written_overrides(client)["glance"]
    assert record["policy"] == "get_image: role:admin\n"
    assert record["config"] is None
    assert record["enabled"] is True
    assert attached["policy-override"] == ("override.yaml", "get_image: role:admin\n")
    assert _action_calls(helper) == [
        (
            "glance/0",
            co.OPENSTACK_MODEL,
            co.VALIDATE_OVERRIDES_ACTION,
            {"content": "get_image: role:admin\n"},
        ),
        ("glance/0", co.OPENSTACK_MODEL, co.APPLY_OVERRIDES_ACTION, {}),
    ]
    assert "Applied policy override for 'image'." in result.output


def test_set_alias_resolves_to_application(
    runner, deployment, client, preflight_patch, jhelper_patch, tmp_path
):
    _empty_store(client)
    policy_file = tmp_path / "nova.policy.yaml"
    policy_file.write_text("os_compute_api:servers:create: role:admin\n")
    helper = jhelper_patch.return_value
    helper.get_leader_unit.return_value = "nova/0"

    result = runner.invoke(
        policy_group, ["set", "compute", str(policy_file)], obj=deployment
    )

    assert result.exit_code == 0, result.output
    assert "nova" in _written_overrides(client)
    assert "compute" not in _written_overrides(client)
    assert helper.attach_resource.call_args.args[0] == "nova"
    assert "Applied policy override for 'compute'." in result.output


def test_policy_set_prints_impact_note(
    runner, deployment, client, preflight_patch, jhelper_patch, tmp_path
):
    _empty_store(client)
    policy_file = tmp_path / "neutron.policy.yaml"
    policy_file.write_text("create_subnet: role:admin\n")
    helper = jhelper_patch.return_value
    helper.get_leader_unit.return_value = "neutron/0"

    result = runner.invoke(
        policy_group, ["set", "network", str(policy_file)], obj=deployment
    )

    assert result.exit_code == 0, result.output
    assert "impact:" in result.output
    assert "create_subnet: affects" in result.output


def test_config_set_keeps_policy_half(
    runner, deployment, client, preflight_patch, jhelper_patch, tmp_path
):
    _seed(client, {"nova": co.make_record(None, "os_compute_api:servers:index: x\n")})
    config_file_ = tmp_path / "nova.conf"
    config_file_.write_text("[DEFAULT]\ndebug = true\n")
    helper = jhelper_patch.return_value
    helper.get_leader_unit.return_value = "nova/0"

    result = runner.invoke(
        config_group, ["set", "compute", str(config_file_)], obj=deployment
    )

    assert result.exit_code == 0, result.output
    record = _written_overrides(client)["nova"]
    assert record["config"] == "[DEFAULT]\ndebug = true\n"
    assert record["policy"] == "os_compute_api:servers:index: x\n"


def test_set_invalid_content_stored_not_applied(
    runner, deployment, client, preflight_patch, jhelper_patch, tmp_path
):
    _empty_store(client)
    policy_file = tmp_path / "bad.yaml"
    policy_file.write_text("not yaml: [\n")
    helper = jhelper_patch.return_value
    helper.run_action.return_value = {
        "valid": "false",
        "errors": '["bad"]',
        "warnings": "[]",
        "checks": "{}",
    }

    result = runner.invoke(
        policy_group, ["set", "glance", str(policy_file)], obj=deployment
    )

    assert result.exit_code != 0
    assert "the override was stored but not applied" in result.output
    helper.attach_resource.assert_not_called()
    assert _written_overrides(client)["glance"]["enabled"] is False


def test_set_empty_file_rejected(runner, deployment, client, tmp_path):
    _empty_store(client)
    policy_file = tmp_path / "empty.yaml"
    policy_file.write_text("")

    result = runner.invoke(
        policy_group, ["set", "glance", str(policy_file)], obj=deployment
    )

    assert result.exit_code != 0
    assert "is empty" in result.output
    client.cluster.update_config.assert_not_called()


def test_set_missing_policy_resource_rejected(
    runner, deployment, client, preflight_patch, jhelper_patch, tmp_path
):
    _empty_store(client)
    policy_file = tmp_path / "glance.policy.yaml"
    policy_file.write_text("get_image: role:admin\n")
    helper = jhelper_patch.return_value
    helper.get_application_resources.return_value = [
        {"name": "config-override", "type": "file"},
    ]

    result = runner.invoke(
        policy_group, ["set", "glance", str(policy_file)], obj=deployment
    )

    assert result.exit_code != 0
    assert "'policy-override'" in result.output
    client.cluster.update_config.assert_not_called()


def test_set_unknown_application_rejected(
    runner, deployment, client, preflight_patch, jhelper_patch, tmp_path
):
    _empty_store(client)
    policy_file = tmp_path / "glance.policy.yaml"
    policy_file.write_text("get_image: role:admin\n")
    helper = jhelper_patch.return_value
    helper.get_application_resources.side_effect = JujuException("gone")

    result = runner.invoke(
        policy_group, ["set", "glance", str(policy_file)], obj=deployment
    )

    assert result.exit_code != 0
    assert "is not deployed in model" in result.output
    client.cluster.update_config.assert_not_called()


def test_show_prints_stored_half_and_applied_paths(
    runner, deployment, client, jhelper_patch
):
    _seed(client, {"glance": co.make_record(None, "get_image: role:admin\n")})
    helper = jhelper_patch.return_value
    helper.run_action.return_value = {"applied": '["/etc/glance/zz-override.yaml"]'}

    result = runner.invoke(policy_group, ["show", "glance"], obj=deployment)

    assert result.exit_code == 0, result.output
    assert "get_image: role:admin" in result.output
    assert "Applied on the unit: /etc/glance/zz-override.yaml" in result.output
    assert "impact:" in result.output


def test_show_missing_half_rejected(runner, deployment, client, jhelper_patch):
    _seed(client, {"glance": co.make_record("[glance]\n", None)})

    result = runner.invoke(policy_group, ["show", "glance"], obj=deployment)

    assert result.exit_code != 0
    assert "no policy override stored for 'image'" in result.output


def test_show_output_writes_half(runner, deployment, client, jhelper_patch, tmp_path):
    _seed(client, {"glance": co.make_record("[glance]\nfoo = bar\n", None)})
    output = tmp_path / "out.conf"

    result = runner.invoke(
        config_group, ["show", "glance", "--output", str(output)], obj=deployment
    )

    assert result.exit_code == 0, result.output
    assert output.read_text() == "[glance]\nfoo = bar\n"
    assert "Wrote service configuration to" in result.output


def test_clear_keeps_other_half_and_reapplies(
    runner, deployment, client, preflight_patch, jhelper_patch
):
    _seed(client, {"glance": co.make_record("[glance]\nfoo = bar\n", "a: b\n")})
    helper = jhelper_patch.return_value
    attached = _capture_attaches(helper)

    result = runner.invoke(policy_group, ["clear", "glance"], obj=deployment)

    assert result.exit_code == 0, result.output
    assert attached == {
        "config-override": ("override.conf", "[glance]\nfoo = bar\n"),
        "policy-override": ("override.yaml", ""),
    }
    record = _written_overrides(client)["glance"]
    assert record["config"] == "[glance]\nfoo = bar\n"
    assert record["policy"] is None


def test_clear_last_half_detaches_and_drops_record(
    runner, deployment, client, preflight_patch, jhelper_patch
):
    _seed(client, {"glance": co.make_record(None, "a: b\n")})
    helper = jhelper_patch.return_value
    attached = _capture_attaches(helper)

    result = runner.invoke(policy_group, ["clear", "glance"], obj=deployment)

    assert result.exit_code == 0, result.output
    assert attached == {
        "config-override": ("override.conf", ""),
        "policy-override": ("override.yaml", ""),
    }
    assert ("glance/0", co.OPENSTACK_MODEL, co.APPLY_OVERRIDES_ACTION, {}) in (
        _action_calls(helper)
    )
    assert _written_overrides(client) == {}
    assert "Cleared policy override for 'image'." in result.output


def test_clear_missing_half_rejected(
    runner, deployment, client, preflight_patch, jhelper_patch
):
    _seed(client, {"glance": co.make_record("[glance]\n", None)})

    result = runner.invoke(policy_group, ["clear", "glance"], obj=deployment)

    assert result.exit_code != 0
    assert "no policy override stored" in result.output


def test_list_empty_message(runner, deployment, client):
    _empty_store(client)

    result = runner.invoke(policy_group, ["list"], obj=deployment)

    assert result.exit_code == 0, result.output
    assert "No service overrides stored." in result.output


def test_list_shows_service_alias_and_halves(runner, deployment, client):
    nova = co.make_record(None, "a: b\n")
    nova["enabled"] = True
    _seed(
        client,
        {
            "glance": co.make_record("[glance]\n", None),
            "nova": nova,
        },
    )

    result = runner.invoke(policy_group, ["list"], obj=deployment)

    assert result.exit_code == 0, result.output
    assert "compute" in result.output
    assert "nova" in result.output
    assert "glance" in result.output
    assert "Config" in result.output
    assert "Policy" in result.output


def test_list_output_dir_writes_files(runner, deployment, client, tmp_path):
    _seed(client, {"glance": co.make_record("[glance]\nfoo = bar\n", "a: b\n")})
    output_dir = tmp_path / "collected"

    result = runner.invoke(
        config_group, ["list", "--output-dir", str(output_dir)], obj=deployment
    )

    assert result.exit_code == 0, result.output
    assert (output_dir / "glance.conf").read_text() == "[glance]\nfoo = bar\n"
    assert (output_dir / "glance.policy.yaml").read_text() == "a: b\n"
    assert "Collected 2 override(s) into" in result.output
