
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


def read_ansible_yaml(file_name, role_name):
    ext_arr = ["yml", "yaml"]

    read_file = None

    for e in ext_arr:
        test_file = "{}.{}".format(file_name, e)
        if os.path.isfile(test_file):
            read_file = test_file
            break

    return "file={} name={}".format(read_file, role_name)


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

    print(" -> {}".format(distribution))
    print(" -> {}".format(base_dir))

    if distribution in ['debian', 'ubuntu']:
        os = "debian"
    elif distribution in ['redhat', 'ol', 'centos', 'rocky', 'almalinux']:
        os = "redhat"
    elif distribution in ['arch']:
        os = "archlinux"

    print(" -> {} / {}".format(distribution, os))

    file_defaults      = read_ansible_yaml("{}/defaults/main".format(base_dir), "role_defaults")
    file_vars          = read_ansible_yaml("{}/vars/main".format(base_dir), "role_vars")
    file_distibution   = read_ansible_yaml("{}/vars/{}".format(base_dir, os), "role_distibution")
    file_molecule      = read_ansible_yaml("{}/group_vars/all/vars".format(molecule_dir), "test_vars")
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

    key = host.file("/etc/ssh/authorized_key/etta_ruthless")
    assert key.exists
    assert key.mode == 0o600


def test_no_directories(host):
    d = host.file("/home/blonde_feared")
    assert not d.exists


def test_user_not_exists(host):
    assert not host.group("blonde_feared").exists
    assert not host.user("blonde_feared").exists