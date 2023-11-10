
# Ansible Role:  `users`

Role to manage multiple users on linux.

[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/bodsch/ansible-users/main.yml?branch=main)][ci]
[![GitHub issues](https://img.shields.io/github/issues/bodsch/ansible-users)][issues]
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/bodsch/ansible-users)][releases]
[![Ansible Quality Score](https://img.shields.io/ansible/quality/50067?label=role%20quality)][quality]

[ci]: https://github.com/bodsch/ansible-users/actions
[issues]: https://github.com/bodsch/ansible-users/issues?q=is%3Aopen+is%3Aissue
[releases]: https://github.com/bodsch/ansible-users/releases
[quality]: https://galaxy.ansible.com/bodsch/users

Add users, change passwords, lock/unlock user accounts, manage sudo access (per user), add ssh key(s) for sshkey based authentication.

## Operating systems

Tested on

* Arch Linux
* Debian based
    - Debian 10 / 11 / 12
    - Ubuntu 20.04 / 22.04

> **RedHat-based systems are no longer officially supported! May work, but does not have to.**



## How to generate password

* on Ubuntu - Install `whois` package

```bash
mkpasswd --method=SHA-512
```

* on RedHat - Use Python

```bash
python -c 'import crypt,getpass; print(crypt.crypt(getpass.getpass(), crypt.mksalt(crypt.METHOD_SHA512)))'
```


```bash
# MD5 (OBSOLETE!)
openssl passwd -1  -salt 5RPVAd clear-text-passwd43

# SHA-256
openssl passwd -5  -salt 5RPVAd clear-text-passwd43

# SHA-512
openssl passwd -6  -salt 5RPVAd clear-text-passwd43

# blowfish
python -c 'import bcrypt; print(bcrypt.hashpw(b"clear-text-passwd43", bcrypt.gensalt(rounds=15)).decode("ascii"))'
```



## Default Settings

```yaml
---
users_output: "compact"  # or: 'full' for more output

users: []
```

## User Settings


| parameter                  | default     |               | description                                                    |
| :------------------        | :----:      | :-----        | :-----------                                                   |
| `username`                 |             | **required**  | username - no spaces                                           |
| `uid`                      |             | optional      | The numerical value of the user's ID                           |
| `state`                    |             | **required**  | `present` / `absent` / `lock`                                  |
| `password`                 |             | optional      | sha512 encrypted password. If not set, password is set to `!`  |
| `update_password`          | `always`    | optional      | `always` / `on_create`.<br>**NOTE**: when `always`, password will be change to password value.<br>If you are using `always` on an **existing** users, **make sure to have the password set**. |
| `comment`                  |             | optional      | Full name and Department or description of application (But you should set this!) |
| `groups`                   |             | optional      | Comma separated list of groups the user will be added to (appended).<br>If group doesn't exist it will be created on the specific server. This is not the primary group (primary group is not modified) |
| `shell`                    | `/bin/bash` | optional      | path to login shell                                            |
| `authorized_key_directory` | `-`         | optional      | path for central stored ssh key e.g. `/etc/ssh/authorized_key` |
| `authorized_keys`          | `[]`        | optional      | a list with authorized_keys. stored in `$HOME/.ssh/authorized_keys` or under `authorized_key_directory` |
| `ssh_keys`                 |             | optional      | dictionary with varios ssh_keys. You can use this to deploy static public or private keyfiles                   |
| `sudo`                     | `{}`        | optional      | a dictionary with sudo settings. (see below)                                            |
| `remove`                   | `False`     | optional      | This only affects `state=absent`, it attempts to remove directories associated with the user. |


### `ssh_keys`

If you have to roll out static public or private SSH keys via Ansible, you can define them here.
The data can be available as plain text or as base64 encoded strings.

> **(If anyone thinks I'm using real existing SSH keys here ... sorry, you are wrong!)**

```yaml
users:
  - username: foo-bar
    ssh_keys:
      id_ed25519: |
          -----BEGIN OPENSSH PRIVATE KEY-----
          b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAXYpRZio
          BDw+o+oic9MwrqAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIK6jjUFopFO9kV4G
          WIkR0gNzpoaOgpwFFRLWKcpeG8THAAAAkHtt03xiYPgAEc7T0nEtnCjt67sN6msNP2Nxgv
          +Fd8BANdzbYFzsMoQ45Ldja2gsOt1KAecwO+xY+5BRCA0huWCTHwbd7Y6BqCKLEpHwXWG1
          UI4GzDt6+hD1LZSbYTFpi+LhiQ1PlrmG5eRQOXzlEAY6AziN7gajlQRsOxkmTW98DuVzWw
          S/KVZZ/wwzyaIPYQ==
          -----END OPENSSH PRIVATE KEY-----
      id_ed25519.pub: ssh-ed25519 AAAAC3NzaC1lYDI1NTE5AAAAIL+LmfwIhn8kxZcyusbcITtwsAOnI1I/d/c40XnGBg7J bar.foo <bar.foo@test.com>

      id_rsa: "LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KaCtmZVZZQVg1Sm1EM2QvdEx6UkxUbTBmUm5CL1NVTDFFQ21jK1gwZ3dLL3UvUG4zU2RJOE0zVk9aMUJkUWJNNjkrU2oyYgozLzRRN1NsbUZObEVXaG43M2VHUFhTTTBLU1VUcGk5bFk0dVJndEhDdGYrejhsaVNBNFlvRlJKcTcxYi9JWHZ1SkUxVks1Ck5jQ3dSUFZRSGRUc0VEdG52M09lNDdFbW9XWFgzOUdFazRoQWNqV1BoeVRvZWFvSWNYTXZDbkVTMXp6SS8wQ2RsVUo2TGEKU1p4Njk2aFE0a1dPZ2k5UE0vVERHdytBRDZGbGVNTUtTK0FtalNuWHBYTjMwTzVacTFuMEhEWGd4ak55VVZ4SjdEVUNDMgpwZ2p1RHpPdDF3QUFBOGhNeC9oMlRNZjRkZ0FBQUFkemMyZ3Rjbk5oQUFBQkFRQytDRGdQYzllZnhvcWZQKzNoc0FBOFMvCm1Kb04wR2xwc2haNEZNNnVrWFdWc3RTQS9ONmJPSDU5NVZnQmZrbVlQZDMrMHZORXRPYlI5R2NIOUpRdlVRS1p6NWZTREEKcis3OCtmZEowand6ZFU1blVGMUJzenIzNUtQWnZmL2hEdEtXWVUyVVJhR2Z2ZDRZOWRJelFwSlJPbUwyVmppNUdDMGNLMQovN1B5V0pJRGhpZ1ZFbXJ2VnY4aGUrNGtUVlVyazF3TEJFOVZBZDFPd1FPMmUvYzU3anNTYWhaZGZmMFlTVGlFQnlOWStICklqNTlnck8ydldDa3JSTTd1Vk9sTUEzSnQ2ZDVkSDE4RDN5Vk5HWHB5dnVROUxXWUxWUGdvMlVUV0lVV3VHR2djVXNydVYKVm8xYm1HUTBsSnlQTkpVUmdUTnJ4dGd0emdEdUdoWWZGMzU2QVJkaHVUeXhBQUFBZ1FDT2hlMHF1bzhlakphalM0dUxydApqTkg2b1FNaWF3NGxMMkJtTWlMc3I5STdVWE5BMXZhRzl6R2J6Ym5wS3pSV0VKMWIxRExUWm42bnRMR2l1UVlCaGNuRUx5CnF3aVdrUDlqNnFZd2NtNlJ3b2tkTGMzWHkvdzdrZXluUVU5SlR4YlVtSGpLQnNKRW9YaGUyS1JVNlhDK0pLYm16cHF3M1QKbkpKcXdodVFNWjBXN3lBMzdheWtYenpLejV2Qlpac1pvekY4MEpXc3FITHBXMTh4ZCtoM1JxWDB3c1dUcjVLcUxWdEN6bgp0UzBKYTl6TXppTWp6S2Z2RDRlT0wwR3NWTXdFc042SUM1bGhkYjdBcGRHTkwyVVpzQUFBQ0JBTVZIc2EwaEFTYW01MVdUCkJkRW5HNjNJZkhwcjhFWjFBQUFBRDJKdlpITmphRUJrWVhKclkybDBlUUVDQXc9PQotLS0tLUVORCBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0K"
```

### `authorized_keys`

To roll out authorised_keys, a corresponding .ssh directory is created in $HOME and stored there.  
If it is desired that the users do not maintain their SSH keys themselves, they can also be stored in an inaccessible directory (e.g. `/etc/ssh/authorised_key`).

> However, the sshd must be configured accordingly **before** doing this!

The following configuration line would make sense: `AuthorizedKeysFile: /etc/ssh/authorized_keys/%u .ssh/authorized_keys`.

### `sudo`

A simple sudo rule can be configured for each user.
The emphasis is on **simple**!

The following configuration 

```yaml
  - username: foo-bar
    sudo:
      nopassword: true
      runas: "ALL"
      commands: ALL
```

would result in this sudoers file

```bash
foo-bar ALL=(ALL)NOPASSWD: ALL
```

The following configuration options are available:

| parameter             | default   | type               | description                                                    |
| :------------------   | :----:    | :-----             | :-----------                                                   |
| `nopassword`          | `False`   | `bool`             | Whether a password will be required to run the sudo command. |
| `runas`               | `-`       | `string`           | Specify the target user the command(s) will run as. |
| `commands`            | `-`       | `string` or `list` | The commands allowed by the sudoers rule.<br>Multiple can be added by passing a list of commands. |
| `group`               | `-`       | `string`           | The name of the group for the sudoers rule. | 


## usage

see [molecule tests](molecule/development/group_vars/all/vars.yml)

```
- hosts: all
  any_errors_fatal: false

  vars:
    users:
      - username: foo-bar
        update_password: always
        comment: Foo Bar
        # password: foo-barbar
        shell: /bin/bash
        ssh_keys:
          id_ed25519: |
              -----BEGIN OPENSSH PRIVATE KEY-----
              b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAXYpRZio
              BDw+o+oic9MwrqAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIK6jjUFopFO9kV4G
              WIkR0gNzpoaOgpwFFRLWKcpeG8THAAAAkHtt03xiYPgAEc7T0nEtnCjt67sN6msNP2Nxgv
              +Fd8BANdzbYFzsMoQ45Ldja2gsOt1KAecwO+xY+5BRCA0huWCTHwbd7Y6BqCKLEpHwXWG1
              UI4GzDt6+hD1LZSbYTFpi+LhiQ1PlrmG5eRQOXzlEAY6AziN7gajlQRsOxkmTW98DuVzWw
              S/KVZZ/wwzyaIPYQ==
              -----END OPENSSH PRIVATE KEY-----
          id_ed25519.pub: ssh-ed25519 AAAAC3NzaC1lYDI1NTE5AAAAIL+LmfwIhn8kxZcyusbcITtwsAOnI1I/d/c40XnGBg7J bar.foo <bar.foo@test.com>
          id_rsa: "LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KaCtmZVZZQVg1Sm1EM2QvdEx6UkxUbTBmUm5CL1NVTDFFQ21jK1gwZ3dLL3UvUG4zU2RJOE0zVk9aMUJkUWJNNjkrU2oyYgozLzRRN1NsbUZObEVXaG43M2VHUFhTTTBLU1VUcGk5bFk0dVJndEhDdGYrejhsaVNBNFlvRlJKcTcxYi9JWHZ1SkUxVks1Ck5jQ3dSUFZRSGRUc0VEdG52M09lNDdFbW9XWFgzOUdFazRoQWNqV1BoeVRvZWFvSWNYTXZDbkVTMXp6SS8wQ2RsVUo2TGEKU1p4Njk2aFE0a1dPZ2k5UE0vVERHdytBRDZGbGVNTUtTK0FtalNuWHBYTjMwTzVacTFuMEhEWGd4ak55VVZ4SjdEVUNDMgpwZ2p1RHpPdDF3QUFBOGhNeC9oMlRNZjRkZ0FBQUFkemMyZ3Rjbk5oQUFBQkFRQytDRGdQYzllZnhvcWZQKzNoc0FBOFMvCm1Kb04wR2xwc2haNEZNNnVrWFdWc3RTQS9ONmJPSDU5NVZnQmZrbVlQZDMrMHZORXRPYlI5R2NIOUpRdlVRS1p6NWZTREEKcis3OCtmZEowand6ZFU1blVGMUJzenIzNUtQWnZmL2hEdEtXWVUyVVJhR2Z2ZDRZOWRJelFwSlJPbUwyVmppNUdDMGNLMQovN1B5V0pJRGhpZ1ZFbXJ2VnY4aGUrNGtUVlVyazF3TEJFOVZBZDFPd1FPMmUvYzU3anNTYWhaZGZmMFlTVGlFQnlOWStICklqNTlnck8ydldDa3JSTTd1Vk9sTUEzSnQ2ZDVkSDE4RDN5Vk5HWHB5dnVROUxXWUxWUGdvMlVUV0lVV3VHR2djVXNydVYKVm8xYm1HUTBsSnlQTkpVUmdUTnJ4dGd0emdEdUdoWWZGMzU2QVJkaHVUeXhBQUFBZ1FDT2hlMHF1bzhlakphalM0dUxydApqTkg2b1FNaWF3NGxMMkJtTWlMc3I5STdVWE5BMXZhRzl6R2J6Ym5wS3pSV0VKMWIxRExUWm42bnRMR2l1UVlCaGNuRUx5CnF3aVdrUDlqNnFZd2NtNlJ3b2tkTGMzWHkvdzdrZXluUVU5SlR4YlVtSGpLQnNKRW9YaGUyS1JVNlhDK0pLYm16cHF3M1QKbkpKcXdodVFNWjBXN3lBMzdheWtYenpLejV2Qlpac1pvekY4MEpXc3FITHBXMTh4ZCtoM1JxWDB3c1dUcjVLcUxWdEN6bgp0UzBKYTl6TXppTWp6S2Z2RDRlT0wwR3NWTXdFc042SUM1bGhkYjdBcGRHTkwyVVpzQUFBQ0JBTVZIc2EwaEFTYW01MVdUCkJkRW5HNjNJZkhwcjhFWjFBQUFBRDJKdlpITmphRUJrWVhKclkybDBlUUVDQXc9PQotLS0tLUVORCBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0K"
          id_rsa.pub: "c3NoLXJzYSBBQUFBQjNOemFDMXljMkVBQUFBREFRQUJBQUFCQTVWZ0Jma21ZUGQzKzB2TkV0T2JSOUdjSDlKUXZVUUtaejVmU0RBTzJlL2M1N2pzU2FoWmRmZjBZU1RpRUJ5TlkrSEpPaGRlbGMzZlE3bG1yV2ZRY05lREdNM0pSWEVuc05RSUxhbUNPNFBNNjNYIGJhckBkZm9vYmFyLmNvbQo="
        sudo:
          nopassword: true
          runas: "ALL"
          commands:
            - ALL
            - /bin/systemctl restart my-service
            - /bin/systemctl reload my-service
          group: wheel
        state: present

  roles:
    - role: ansible-users
```

---

## Author and License

- Bodo Schulz

## License

[MIT](LICENSE)

**FREE SOFTWARE, HELL YEAH!**
