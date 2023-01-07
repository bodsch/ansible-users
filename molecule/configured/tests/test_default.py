# coding: utf-8
from __future__ import unicode_literals

from ansible.parsing.dataloader import DataLoader
from ansible.template import Templar

import json
import pytest
import os

import testinfra.utils.ansible_runner

HOST = 'instance'

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts(HOST)


def pp_json(json_thing, sort=True, indents=2):
    if type(json_thing) is str:
        print(json.dumps(json.loads(json_thing), sort_keys=sort, indent=indents))
    else:
        print(json.dumps(json_thing, sort_keys=sort, indent=indents))
    return None


def base_directory():
    """
    """
    cwd = os.getcwd()

    if 'group_vars' in os.listdir(cwd):
        directory = "../.."
        molecule_directory = "."
    else:
        directory = "."
        molecule_directory = f"molecule/{os.environ.get('MOLECULE_SCENARIO_NAME')}"

    return directory, molecule_directory


def read_ansible_yaml(file_name, role_name):
    """
    """
    read_file = None

    for e in ["yml", "yaml"]:
        test_file = f"{file_name}.{e}"
        if os.path.isfile(test_file):
            read_file = test_file
            break

    return f"file={read_file} name={role_name}"


@pytest.fixture()
def get_vars(host):
    """
        parse ansible variables
        - defaults/main.yml
        - vars/main.yml
        - vars/${DISTRIBUTION}.yaml
        - molecule/${MOLECULE_SCENARIO_NAME}/group_vars/all/vars.yml
    """
    base_dir, molecule_dir = base_directory()
    distribution = host.system_info.distribution
    operation_system = None

    if distribution in ['debian', 'ubuntu']:
        operation_system = "debian"
    elif distribution in ['redhat', 'ol', 'centos', 'rocky', 'almalinux']:
        operation_system = "redhat"
    elif distribution in ['arch', 'artix']:
        operation_system = f"{distribution}linux"

    # print(" -> {} / {}".format(distribution, os))
    # print(" -> {}".format(base_dir))

    file_defaults      = read_ansible_yaml(f"{base_dir}/defaults/main", "role_defaults")
    file_vars          = read_ansible_yaml(f"{base_dir}/vars/main", "role_vars")
    file_distibution   = read_ansible_yaml(f"{base_dir}/vars/{operation_system}", "role_distibution")
    file_molecule      = read_ansible_yaml(f"{molecule_dir}/group_vars/all/vars", "test_vars")
    # file_host_molecule = read_ansible_yaml("{}/host_vars/{}/vars".format(base_dir, HOST), "host_vars")

    defaults_vars      = host.ansible("include_vars", file_defaults).get("ansible_facts").get("role_defaults")
    vars_vars          = host.ansible("include_vars", file_vars).get("ansible_facts").get("role_vars")
    distibution_vars   = host.ansible("include_vars", file_distibution).get("ansible_facts").get("role_distibution")
    molecule_vars      = host.ansible("include_vars", file_molecule).get("ansible_facts").get("test_vars")
    # host_vars          = host.ansible("include_vars", file_host_molecule).get("ansible_facts").get("host_vars")

    ansible_vars = defaults_vars
    ansible_vars.update(vars_vars)
    ansible_vars.update(distibution_vars)
    ansible_vars.update(molecule_vars)
    # ansible_vars.update(host_vars)

    templar = Templar(loader=DataLoader(), variables=ansible_vars)
    result = templar.template(ansible_vars, fail_on_undefined=False)

    return result


@pytest.mark.parametrize("dirs", [
    "/home/dread_zandra",
    "/home/etta_ruthless",
    "/home/bodsch",
    "/home/bodsch/.ssh",
])
def test_directories(host, dirs):
    d = host.file(dirs)
    assert d.is_directory
    assert d.exists


@pytest.mark.parametrize("files", [
    "/home/dread_zandra/.bashrc",
    "/home/etta_ruthless/.bashrc",
    "/home/bodsch/.bashrc",
    "/etc/ssh/authorized_key/etta_ruthless",
])
def test_files(host, files):
    f = host.file(files)
    assert f.exists
    assert f.is_file


def test_user_dread_zandra(host):
    assert host.group("dread_zandra").exists
    assert host.user("dread_zandra").exists
    assert "dread_zandra" in host.user("dread_zandra").groups
    assert host.user("dread_zandra").shell == "/bin/bash"
    assert host.user("dread_zandra").home == "/home/dread_zandra"
    assert host.user("dread_zandra").password == "!"


def test_user_etta_ruthless(host):
    assert host.group("etta_ruthless").exists
    assert host.user("etta_ruthless").exists
    assert "etta_ruthless" in host.user("etta_ruthless").groups
    assert host.user("etta_ruthless").shell == "/bin/bash"
    assert host.user("etta_ruthless").home == "/home/etta_ruthless"
    assert host.user("etta_ruthless").password == "!$6$7ILaolIu7Q0VbCVw$JvxT.lIM.bqZ8mioVq6jKQMzNKYTsljB5AXTfFA7IYuWdiSIyYJm43iog6ZxoLx50hEHIpi/DktzUr3pJgGwI."

    key = host.file("/etc/ssh/authorized_key/etta_ruthless")
    assert key.exists
    assert key.mode == 0o644


def test_no_directories(host):
    d = host.file("/home/blonde_feared")
    assert not d.exists


def test_user_not_exists(host):
    assert not host.group("blonde_feared").exists
    assert not host.user("blonde_feared").exists
