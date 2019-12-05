# ansible-users

Role to manage users on linux.

Add users, change passwords, lock/unlock user accounts, manage sudo access (per user), add ssh key(s) for sshkey based authentication.


**Note:** Deleting users is not done on purpose.

## Distros tested

* Ubuntu 18.04 / 16.04
* Debian 8 / 9 / 10
* CentOS 7 / 8

## How to generate password

* on Ubuntu - Install "whois" package

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

File Location: vars/secret

| parameter           | default     |               | description                              |
| :------------------ | :----:      |               | :-----------   |
| `username`          |             | **required**  | username - no spaces  |
| `uid`               |             | optional      | The numerical value of the user's ID |
| `user_state`        |             | **required**  | `present` / `lock`  |
| `password`          |             | optional      | sha512 encrypted password. If not set, password is set to `!` |
| `update_password`   | `on_create` | optional      | `always` / `on_create`.<br>**NOTE**: when `always`, password will be change to password value.<br>If you are using `always` on an **existing** users, **make sure to have the password set**. |
| `comment`           |             | optional      | Full name and Department or description of application (But you should set this!) |
| `groups`            |             | optional      | Comma separated list of groups the user will be added to (appended).<br>If group doesn't exist it will be created on the specific server. This is not the primary group (primary group is not modified) |
| `shell`             | `/bin/bash` | optional      | path to login shell |
| `ssh_key`           |             | optional      | ssh key for ssh key based authentication |
| `exclusive_ssh_key` | `false`     | optional      | `true` / `false` <br>**NOTE**: `true` - will remove any ssh keys not defined here! `false` - will add any key specified. |
| `use_sudo`          | `false`     | optional      | `true` / `false` |
| `use_sudo_nopass`   | `false`     | optional      | `true` / `false`. set to `true` for passwordless sudo. |
