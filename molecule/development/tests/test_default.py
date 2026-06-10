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
        "/home/foo-bar",
        "/home/foo-bar/.ssh",
        "/home/bodsch",
        "/etc/ssh/authorized_key",
    ],
)
def test_directories(host, dirs):
    d = host.file(dirs)
    assert d.is_directory
    assert d.exists


@pytest.mark.parametrize(
    "files",
    [
        "/home/foo-bar/.bashrc",
        "/home/bodsch/.bashrc",
        "/etc/ssh/authorized_key/bodsch",
    ],
)
def test_files(host, files):
    f = host.file(files)
    assert f.exists
    assert f.is_file


def test_user_foo(host):
    assert host.group("foo-bar").exists
    assert host.user("foo-bar").exists
    assert "foo-bar" in host.user("foo-bar").groups
    assert host.user("foo-bar").shell == "/bin/bash"
    assert host.user("foo-bar").home == "/home/foo-bar"
    assert host.user("foo-bar").password == "!"


# def test_user_bar(host):
#     assert host.group("etta_ruthless").exists
#     assert host.user("etta_ruthless").exists
#     assert "etta_ruthless" in host.user("etta_ruthless").groups
#     assert host.user("etta_ruthless").shell == "/bin/bash"
#     assert host.user("etta_ruthless").home == "/home/etta_ruthless"
#     assert host.user("etta_ruthless").password == "$6$7ILaolIu7Q0VbCVw$JvxT.lIM.bqZ8mioVq6jKQMzNKYTsljB5AXTfFA7IYuWdiSIyYJm43iog6ZxoLx50hEHIpi/DktzUr3pJgGwI."
#
#     key = host.file("/etc/ssh/authorized_key/etta_ruthless")
#     assert key.exists
#     assert key.mode == 0o600
#
#
# def test_no_directories(host):
#     d = host.file("/home/blonde_feared")
#     assert not d.exists
#
#
# def test_user_not_exists(host):
#     assert not host.group("blonde_feared").exists
#     assert not host.user("blonde_feared").exists
