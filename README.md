
Role to manage users on linux.


[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/bodsch/ansible-users/CI)][ci]
[![GitHub issues](https://img.shields.io/github/issues/bodsch/ansible-users)][issues]
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/bodsch/ansible-users)][releases]

[ci]: https://github.com/bodsch/ansible-users/actions
[issues]: https://github.com/bodsch/ansible-users/issues?q=is%3Aopen+is%3Aissue
[releases]: https://github.com/bodsch/ansible-users/releases


Add users, change passwords, lock/unlock user accounts, manage sudo access (per user), add ssh key(s) for sshkey based authentication.

## Operating systems

Tested on

* Debian 9 / 10 / 11
* Ubuntu 18.04 / 20.04
* CentOS 7 / 8
* OracleLinux 7 / 8
* ArchLinux


## How to generate password

* on Ubuntu - Install `whois` package

```bash
mkpasswd --method=SHA-512
```

* on RedHat - Use Python

```bash
python -c 'import crypt,getpass; print(crypt.crypt(getpass.getpass(), crypt.mksalt(crypt.METHOD_SHA512)))'
```

## Default Settings

```yaml
---
default_update_password: on_create
default_shell: /bin/bash

users: []
```

## User Settings


| parameter           | default     |               | description                                                    |
| :------------------ | :----:      | :-----        | :-----------                                                   |
| `username`          |             | **required**  | username - no spaces                                           |
| `uid`               |             | optional      | The numerical value of the user's ID                           |
| `user_state`        |             | **required**  | `present` / `lock`                                             |
| `password`          |             | optional      | sha512 encrypted password. If not set, password is set to `!`  |
| `update_password`   | `on_create` | optional      | `always` / `on_create`.<br>**NOTE**: when `always`, password will be change to password value.<br>If you are using `always` on an **existing** users, **make sure to have the password set**. |
| `comment`           |             | optional      | Full name and Department or description of application (But you should set this!) |
| `groups`            |             | optional      | Comma separated list of groups the user will be added to (appended).<br>If group doesn't exist it will be created on the specific server. This is not the primary group (primary group is not modified) |
| `shell`             | `/bin/bash` | optional      | path to login shell                                            |
| `ssh_key_directory` | `-`         | optional      | path for central stored ssh key e.g. `/etc/ssh/authorized_key` |
| `ssh_key`           |             | optional      | ssh key for ssh key based authentication                       |
| `exclusive_ssh_key` | `false`     | optional      | `true` / `false` <br>**NOTE**: `true` - will remove any ssh keys not defined here! `false` - will add any key specified. |
| `use_sudo`          | `false`     | optional      | `true` / `false`                                               |
| `use_sudo_nopass`   | `false`     | optional      | `true` / `false`. set to `true` for passwordless sudo.         |


## usage

see [molecule tests](molecule/default/converge.yml)

```
- hosts: all
  any_errors_fatal: false

  vars:
    users:
      - username: bodsch
        comment: Bodo Schulz
        password: $6$ptDt6US1NuMioXBL$QVbF04V0Cpj12w1t1YxY7Yw.yqT8RQz1ahT0soYWvJI/1dlZMX19pPXGZn5fn0YQpjS/5ml.sKRCZFt0aPZIa.
        update_password: on_create
        shell: /bin/bash
        ssh_key: |
          ssh-ed25519 AAAAC3NzaC1lYDI1NTE5AAAAIL+LmfwIhn8kxZcyusbcITtwsAOnI1I/d/c40XnGBg7J bar.foo <bar.foo@test.com>
        exclusive_ssh_key: true
        use_sudo: true
        use_sudo_nopass: true
        user_state: present

      - username: blonde_feared
        user_state: absent

  roles:
    - role: ansible-users
```

## Tests

`tox -e py38-ansible29 -- molecule test`


## License

MIT
