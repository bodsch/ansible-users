# coding: utf-8
from __future__ import annotations, unicode_literals

import os

import pytest
import testinfra.utils.ansible_runner
from helper.molecule import get_vars, infra_hosts, local_facts

testinfra_hosts = infra_hosts(host_name="instance")

# --- tests -----------------------------------------------------------------


@pytest.mark.parametrize(
    "dirs",
    [
        "/home/dread_zandra",
        "/home/etta_ruthless",
        "/home/bodsch",
        "/home/bodsch/.ssh",
    ],
)
def test_directories(host, dirs):
    d = host.file(dirs)
    assert d.is_directory
    assert d.exists


@pytest.mark.parametrize(
    "files",
    [
        "/home/dread_zandra/.bashrc",
        "/home/etta_ruthless/.bashrc",
        "/home/bodsch/.bashrc",
        "/etc/ssh/authorized_key/etta_ruthless",
    ],
)
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
    assert (
        host.user("etta_ruthless").password
        == "!$6$7ILaolIu7Q0VbCVw$JvxT.lIM.bqZ8mioVq6jKQMzNKYTsljB5AXTfFA7IYuWdiSIyYJm43iog6ZxoLx50hEHIpi/DktzUr3pJgGwI."
    )

    key = host.file("/etc/ssh/authorized_key/etta_ruthless")
    assert key.exists
    assert key.mode == 0o644


def test_no_directories(host):
    d = host.file("/home/blonde_feared")
    assert not d.exists


def test_user_not_exists(host):
    assert not host.group("blonde_feared").exists
    assert not host.user("blonde_feared").exists
