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
    ],
)
def test_directories(host, dirs):
    d = host.file(dirs)
    assert d.is_directory


@pytest.mark.parametrize(
    "files",
    [
        "/home/foo-bar/.bashrc",
        "/home/foo-bar/.ssh/id_ed25519",
        "/home/foo-bar/.ssh/id_ed25519.pub",
    ],
)
def test_files(host, files):
    f = host.file(files)

    assert f.is_file
