
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

* Arch Linux
* Debian based
    - Debian 10 / 11
    - Ubuntu 20.10
* RedHat based
    - Alma Linux 8
    - Rocky Linux 8
    - Oracle Linux 8


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
| `user_state`        |             | **required**  | `present` / `absent` / `lock`                                  |
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
| `ssh_private_key`   | `-`         | optional      | A list of private ssh keys to be deployed for this user.       |


### `ssh_private_key`



```yaml
users:
  - username: foo-bar
    ssh_private_key:
      - type: id_ed25519
        content: |
          -----BEGIN OPENSSH PRIVATE KEY-----
          b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAXYpRZio
          BDw+o+oic9MwrqAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIK6jjUFopFO9kV4G
          WIkR0gNzpoaOgpwFFRLWKcpeG8THAAAAkHtt03xiYPgAEc7T0nEtnCjt67sN6msNP2Nxgv
          +Fd8BANdzbYFzsMoQ45Ldja2gsOt1KAecwO+xY+5BRCA0huWCTHwbd7Y6BqCKLEpHwXWG1
          UI4GzDt6+hD1LZSbYTFpi+LhiQ1PlrmG5eRQOXzlEAY6AziN7gajlQRsOxkmTW98DuVzWw
          S/KVZZ/wwzyaIPYQ==
          -----END OPENSSH PRIVATE KEY-----

```


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
