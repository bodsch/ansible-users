
from ansible.parsing.dataloader import DataLoader
from ansible.template import Templar
import pytest
import os
import testinfra.utils.ansible_runner

import pprint
pp = pprint.PrettyPrinter()

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')


def base_directory():
    cwd = os.getcwd()

    if('group_vars' in os.listdir(cwd)):
        directory = "../.."
        molecule_directory = "."
    else:
        directory = "."
        molecule_directory = "molecule/{}".format(os.environ.get('MOLECULE_SCENARIO_NAME'))

    return directory, molecule_directory


@pytest.fixture()
def get_vars(host):
    """

    """
    base_dir, molecule_dir = base_directory()

    file_defaults = "file={}/defaults/main.yml name=role_defaults".format(base_dir)
    file_vars = "file={}/vars/main.yml name=role_vars".format(base_dir)
    file_molecule = "file={}/group_vars/all/vars.yml name=test_vars".format(molecule_dir)

    defaults_vars = host.ansible("include_vars", file_defaults).get("ansible_facts").get("role_defaults")
    vars_vars = host.ansible("include_vars", file_vars).get("ansible_facts").get("role_vars")
    molecule_vars = host.ansible("include_vars", file_molecule).get("ansible_facts").get("test_vars")

    ansible_vars = defaults_vars
    ansible_vars.update(vars_vars)
    ansible_vars.update(molecule_vars)

    templar = Templar(loader=DataLoader(), variables=ansible_vars)
    result = templar.template(ansible_vars, fail_on_undefined=False)

    return result


@pytest.mark.parametrize("dirs", [
    "/home/dread_zandra",
    "/home/etta_ruthless",
    "/home/etta_ruthless/.ssh",
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
])
def test_files(host, files):
    f = host.file(files)
    assert f.exists
    assert f.is_file


def test_user_foo(host):
    assert host.group("dread_zandra").exists
    assert host.user("dread_zandra").exists
    assert "dread_zandra" in host.user("dread_zandra").groups
    assert host.user("dread_zandra").shell == "/bin/bash"
    assert host.user("dread_zandra").home == "/home/dread_zandra"
    assert host.user("dread_zandra").password == "!"


def test_user_bar(host):
    assert host.group("etta_ruthless").exists
    assert host.user("etta_ruthless").exists
    assert "etta_ruthless" in host.user("etta_ruthless").groups
    assert host.user("etta_ruthless").shell == "/bin/bash"
    assert host.user("etta_ruthless").home == "/home/etta_ruthless"
    assert host.user("etta_ruthless").password == "$6$7ILaolIu7Q0VbCVw$JvxT.lIM.bqZ8mioVq6jKQMzNKYTsljB5AXTfFA7IYuWdiSIyYJm43iog6ZxoLx50hEHIpi/DktzUr3pJgGwI."

    key = host.file("/home/etta_ruthless/.ssh/authorized_keys")
    assert key.exists
    assert key.mode == 0o600

# test removed users
#
def test_no_directories(host):
    d = host.file("/home/blonde_feared")
    assert not d.exists

# the home directory should not be exists
#
def test_user_not_exists(host):
    assert not host.group("blonde_feared").exists
    assert not host.user("blonde_feared").exists
