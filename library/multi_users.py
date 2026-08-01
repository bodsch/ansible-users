#!/usr/bin/python3

# -*- coding: utf-8 -*-

# (c) 2022, Bodo Schulz <bodo@boone-schulz.de>
# BSD 2-clause (see LICENSE or https://opensource.org/licenses/BSD-2-Clause)

from __future__ import annotations

import base64
import binascii
import grp
import hashlib
import json
import os
import pwd
import re
import shutil
import time
from typing import Any

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native

DOCUMENTATION = """
---
module: multi_users
author:
  - Bodo Schulz (@bodsch)
short_description: Manage multiple local users in a single task.
description:
  - Creates, modifies, locks and removes multiple local users in one module call.
  - Designed for Linux targets (Arch Linux and Debian based distributions).
  - Wraps C(useradd), C(usermod) and C(userdel) and additionally manages
    C(authorized_keys), static C(ssh_keys) and a simple C(sudo) rule per user.
options:
  users:
    description:
      - A list of user definitions.
    required: true
    type: list
    elements: dict
    suboptions:
      username:
        description: The login name of the user.
        required: true
        type: str
      state:
        description:
          - Desired state of the user account.
          - V(lock) ensures the account exists but is locked.
        type: str
        choices: [present, absent, lock]
        default: present
      uid:
        description: The numerical value of the user's ID.
        type: int
      group:
        description:
          - The primary group for the user.
          - The group must already exist; it will not be created.
        type: str
      groups:
        description:
          - A list of supplementary groups the user is added to.
          - Groups that do not exist are skipped with a warning.
        type: list
        elements: str
      comment:
        description: The GECOS field (full name / description).
        type: str
      password:
        description:
          - The encrypted (SHA-256 / SHA-512 / Blowfish) password hash.
          - MD5 hashes are rejected.
        type: str
      password_lock:
        description: Lock the account.
        type: bool
        default: true
      update_password:
        description:
          - V(always) updates the password to the given value.
          - V(on_create) only sets the password on user creation.
        type: str
        choices: [always, on_create]
        default: always
      shell:
        description: The user's login shell.
        type: str
        default: /bin/bash
      home:
        description: The user's home directory. Defaults to C(/home/<username>).
        type: str
      create_home:
        description: Create the home directory when the user is created.
        type: bool
        default: true
      move_home:
        description: Move the home directory when C(home) changes.
        type: bool
        default: false
      expires:
        description: Account expiration time as a struct_time.
        type: raw
      force:
        description: Force removal (only with O(users[].state=absent)).
        type: bool
        default: false
      remove:
        description: Remove the home directory (only with O(users[].state=absent)).
        type: bool
        default: false
      authorized_keys:
        description: A list of authorized_keys for the user.
        type: list
        elements: str
      authorized_key_directory:
        description:
          - Central directory for authorized_keys (e.g. C(/etc/ssh/authorized_key)).
          - When unset the keys are written to C($HOME/.ssh/authorized_keys).
        type: str
      ssh_keys:
        description:
          - A dictionary of static ssh key files to deploy.
          - Values may be plain text or base64 encoded.
        type: dict
      sudo:
        description: A simple sudo rule for the user.
        type: dict
        suboptions:
          nopassword:
            description: Whether the rule uses NOPASSWD.
            type: bool
            default: false
          runas:
            description: Target user the commands run as.
            type: str
          group:
            description: Apply the rule to a group instead of the user.
            type: str
          commands:
            description: The command(s) allowed by the rule.
            type: raw
  output:
    description: Amount of detail in the module result.
    type: str
    choices: [compact, full]
    default: compact
"""

EXAMPLES = """
- name: create multiple users
  multi_users:
    output: compact
    users:
      - username: foo-bar
        comment: Foo Bar
        shell: /bin/bash
        state: present
        sudo:
          nopassword: true
          runas: ALL
          commands:
            - ALL
          group: wheel
      - username: legacy
        state: absent
        remove: true
"""

RETURN = """
changed:
  description: Whether any user was created, modified or removed.
  type: bool
  returned: always
failed:
  description: Whether at least one user could not be processed.
  type: bool
  returned: always
result_changed:
  description: Per-user results for all changed users.
  type: dict
  returned: when changed
result_failed:
  description: Per-user results for all failed users.
  type: dict
  returned: when failed
output:
  description: Full per-user result map.
  type: dict
  returned: when O(output=full)
"""

# ---------------------------------------------------------------------------------------


def validate_password_hash(password: str | None) -> tuple[bool, str | None]:
    """
    Validate that ``password`` looks like a supported crypt(3) hash.

    The module never hashes a plaintext password itself, so the value
    passed in must already be encrypted. Supported algorithms are
    SHA-256 (``$5$``), SHA-512 (``$6$``) and Blowfish (``$2a$`` / ``$2y$``).
    The outdated MD5 (``$1$``) algorithm is explicitly rejected.

    :param password: the (already encrypted) password value to check.
    :returns: a tuple ``(invalid, msg)`` where ``invalid`` is ``True`` when
        the value must be rejected and ``msg`` explains why.
    """
    if not password:
        return (False, "no password given.")

    # Special values used to disable / lock an account are always accepted.
    if password in {"*", "!", "*************"}:
        return (False, None)

    not_hashed_msg = (
        "The input password appears not to have been hashed.\n"
        "The 'password' argument must be encrypted for this module to work properly."
    )

    # ':' is the field delimiter, '*' disables and '!' locks an account; none
    # of these characters may appear inside an actual hash.
    if any(char in password for char in ":*!"):
        return (True, not_hashed_msg)

    if "$" not in password:
        return (True, not_hashed_msg)

    # format: '$id$salt$hashed'
    parts = password.split("$")
    if len(parts) != 4:
        return (True, not_hashed_msg)

    _, algorithm, salt, pwd_hash = parts
    if not (algorithm and salt and pwd_hash):
        return (True, not_hashed_msg)

    if algorithm == "1":
        return (
            True,
            (
                "The password entered seems to have been hashed, but with the outdated MD5 algorithm!\n"
                "This algorithm is no longer supported!\n"
                "Please create a new password with a modern hash algorithm (SHA-256, SHA-512, Blowfish)."
            ),
        )

    # SHA-256 / SHA-512 hashes have a fixed length and a restricted character
    # set; anything else means the value is not a proper hash.
    if algorithm == "5" and len(pwd_hash) != 43:
        return (True, not_hashed_msg)

    if algorithm == "6" and len(pwd_hash) != 86:
        return (True, not_hashed_msg)

    if re.search(r"[^a-zA-Z0-9./=]", pwd_hash):
        return (True, not_hashed_msg)

    return (False, None)


def group_exists(group: str | int) -> bool:
    """
    Return ``True`` when ``group`` exists, looked up by GID first then name.
    """
    try:
        # Try group as a gid first
        grp.getgrgid(int(group))
        return True
    except (ValueError, KeyError):
        try:
            grp.getgrnam(group)
            return True
        except KeyError:
            return False


def group_info(group: str | int) -> list | bool:
    """
    Return the ``grp`` record for ``group`` as a list, or ``False`` when the
    group does not exist.

    The list follows the layout of :func:`grp.getgrnam`::

        0   gr_name     the name of the group
        1   gr_passwd   the (encrypted) group password; often empty
        2   gr_gid      the numerical group ID
        3   gr_mem      all the group member's user names
    """
    if not group_exists(group):
        return False

    try:
        # Try group as a gid first
        return list(grp.getgrgid(int(group)))
    except (ValueError, KeyError):
        return list(grp.getgrnam(group))


class SingleUser:
    """
    Wrap useradd / usermod / userdel for a single user account.
    """

    def __init__(self, user: dict[str, Any], module: AnsibleModule) -> None:
        """
        Store the AnsibleModule reference and unpack the per-user options.
        """
        self.module = module

        self.comment = user.get("comment")
        self.create_home = user.get("create_home", True)
        self.expires = user.get("expires", None)
        self.force = user.get("force", False)
        self.group = user.get("group", None)
        self.groups = ",".join(user.get("groups", []))
        self.home = user.get("home")
        self.move_home = user.get("move_home", False)
        self.password = user.get("password", None)
        self.password_lock = user.get("password_lock", True)
        self.remove = user.get("remove", False)
        self.shell = user.get("shell", None)
        self.state = user.get("state")
        self.uid = user.get("uid", None)
        self.umask = user.get("umask", None)
        self.update_password = user.get("update_password", "always")
        self.username = user.get("username")

        self.__shadow_file = "/etc/shadow"
        self.__login_defs = "/etc/login.defs"
        self.__date_format = "%Y-%m-%d"

    def __exec(
        self, commands: list[str], check_rc: bool = False
    ) -> tuple[int, str, str]:
        """
        Run ``commands`` through the module command runner and log the
        output when the return code is non-zero.
        """
        rc, out, err = self.module.run_command(commands, check_rc=check_rc)

        if rc != 0:
            self.module.log("------------------------------------------")
            self.module.log(msg=f"  rc : '{rc}'")
            self.module.log(msg=f"  out: '{out}'")
            self.module.log(msg=f"  err: '{err}'")
            self.module.log("------------------------------------------")

        return rc, out, err

    def user_exists(self) -> bool:
        """
        Return ``True`` when a passwd entry for the user exists.
        """
        try:
            pwd.getpwnam(self.username)
            return True
        except KeyError:
            return False

    def get_pwd_info(self) -> list | bool:
        """
        Return the passwd entry as a list, or ``False`` if the user does
        not exist.

        The list follows the layout of :func:`pwd.getpwnam`::

            0   pw_name     Login name
            1   pw_passwd   Optional encrypted password
            2   pw_uid      Numerical user ID
            3   pw_gid      Numerical group ID
            4   pw_gecos    User name or comment field
            5   pw_dir      User home directory
            6   pw_shell    User command interpreter
        """
        if not self.user_exists():
            return False

        return list(pwd.getpwnam(self.username))

    def user_info(self) -> list | bool:
        """
        Return the passwd entry with the real password hash filled in.

        On shadow systems ``pw_passwd`` only contains a placeholder
        (``x``); the actual hash is read from ``/etc/shadow``.
        """
        if not self.user_exists():
            return False

        info = self.get_pwd_info()

        if len(info[1]) == 1 or len(info[1]) == 0:
            # update password field with the user password
            info[1] = self.user_password()[0]

        return info

    def user_password(self) -> tuple[str, str]:
        """
        Return the encrypted password and the expiration date from
        ``/etc/shadow`` for the user.
        """
        if not self.user_exists():
            return "", ""

        return self.parse_shadow_file()

    def parse_shadow_file(self) -> tuple[str, str]:
        """
        Read the user's entry from ``/etc/shadow`` and return the password
        hash and the account expiration date.

        -> https://www.cyberciti.biz/faq/understanding-etcshadow-file/
            0 : username
            1 : password
            2 : Last password change (lastchanged)
            3 : The minimum number of days required between password changes
            4 : The maximum number of days the password is valid
            5 : The number of days before password is to expire that user is warned
            6 : The number of days after password expires that account is disabled
            7 : The date of expiration of the account, expressed as the number of days since Jan 1, 1970.
        """
        passwd = ""
        expires = ""

        if os.path.exists(self.__shadow_file) and os.access(
            self.__shadow_file, os.R_OK
        ):
            with open(self.__shadow_file, "r") as f:
                for line in f:
                    if line.startswith(f"{self.username}:"):
                        shadow_info = line.split(":")
                        passwd = shadow_info[1]
                        expires = shadow_info[7] or "-1"

        return passwd, expires

    def create_user(self) -> tuple[int, str, str]:
        """
        Create the account with ``useradd`` and return ``(rc, out, err)``.
        """
        useradd_bin = self.module.get_bin_path("useradd", True)

        args = [useradd_bin]

        if self.uid is not None:
            args += ["-u", str(self.uid)]

        if self.group is not None:
            if not group_exists(self.group):
                return (1, "", f"Group {self.group} does not exist")

            args += ["-g", self.group]

        elif group_exists(self.username):
            # use the -N option (no user group) if a group already
            # exists with the same name as the user to prevent
            # errors from useradd trying to create a group when
            # USERGROUPS_ENAB is set in /etc/login.defs.
            args.append("-N")

        if self.groups:
            args += ["-G", ",".join(self.get_groups_set())]

        if self.comment is not None:
            args += ["-c", self.comment]

        if self.home:
            # If the specified path to the user home contains parent directories that
            # do not exist and create_home is True first create the parent directory
            # since useradd cannot create it.
            if self.create_home:
                parent = os.path.dirname(self.home)
                if not os.path.isdir(parent):
                    self.create_homedir(self.home)

            args += ["-d", self.home]

        if self.shell:
            args += ["-s", self.shell]

        if self.expires:
            args.append("-e")
            if self.expires < time.gmtime(0):
                args.append("")
            else:
                args.append(time.strftime(self.__date_format, self.expires))

        if self.password:
            password = f"!{self.password}" if self.password_lock else self.password
            args += ["-p", password]

        if self.create_home:
            args.append("-m")

            if self.umask:
                args += ["-K", f"UMASK={self.umask}"]
        else:
            args.append("-M")

        args.append(self.username)

        self.module.log(msg=f" - args {args}")

        return self.__exec(args)

    def remove_user(self) -> tuple[int, str, str]:
        """
        Remove the account with ``userdel`` and return ``(rc, out, err)``.
        """
        userdel_bin = self.module.get_bin_path("userdel", True)

        args = [userdel_bin]

        if self.force:
            args.append("-f")

        if self.remove:
            args.append("-r")

        args.append(self.username)

        self.module.log(msg=f" - args {args}")

        return self.__exec(args)

    def modify_user(self) -> tuple[int | None, str | None, str]:
        """
        Reconcile an existing account with the desired configuration using
        ``usermod``.

        Returns ``(rc, out, err)``. ``rc`` is ``None`` when nothing needed
        to be changed.
        """
        (
            user_name,
            user_pass,
            user_uid,
            user_gid,
            user_comment,
            user_home,
            user_shell,
        ) = self.user_info()

        usermod_bin = self.module.get_bin_path("usermod", True)

        args = [usermod_bin]
        result_msg: list[str] = []

        if self.uid and user_uid != int(self.uid):
            args += ["-u", self.uid]
            result_msg.append("change uid.")

        if self.group:
            if not group_exists(self.group):
                return (1, "", f"Group {self.group} does not exist")

            group_gid = group_info(self.group)[2]
            if user_gid != group_gid:
                args += ["-g", self.group]
                result_msg.append("change primary group.")

        group_args, group_msg = self._supplementary_group_args()
        args += group_args
        if group_msg:
            result_msg.append(group_msg)

        if self.comment and user_comment != self.comment:
            args += ["-c", self.comment]
            result_msg.append("change user comment.")

        if self.home and user_home != self.home:
            args += ["-d", self.home]
            result_msg.append("change user home.")

            if self.move_home:
                parent = os.path.dirname(self.home)
                if not os.path.isdir(parent):
                    self.create_homedir(parent)

                args.append("-m")
                result_msg.append("move user home.")

        if self.shell and user_shell != self.shell:
            args += ["-s", self.shell]
            result_msg.append("change login shell.")

        expire_args, expire_msg = self._expiration_args()
        args += expire_args
        if expire_msg:
            result_msg.append(expire_msg)

        # Lock if currently unlocked, unlock only if locked
        if self.password_lock and not user_pass.startswith("!"):
            args.append("-L")
            result_msg.append("lock the user account")

        elif not self.password_lock and user_pass.startswith("!"):
            # usermod will refuse to unlock a user with no password, module shows 'changed' regardless
            args.append("-U")
            result_msg.append("unlock the user account")

        if (
            self.update_password == "always"
            and self.password
            and user_pass.lstrip("!") != self.password.lstrip("!")
        ):
            # Remove options that are mutually exclusive with -p
            args = [c for c in args if c not in ("-U", "-L")]
            password = f"!{self.password}" if self.password_lock else self.password
            args += ["-p", password]
            result_msg.append("change password.")

        rc: int | None = None
        out: str | None = ""
        err = ""

        # skip if no usermod changes to be made
        if len(args) > 1:
            args.append(self.username)

            self.module.log(msg=f" - args {args}")

            (rc, out, err) = self.__exec(args)

        if not (rc is None or rc == 0):
            # ERROR
            return (rc, out, err)

        out = "\n".join(result_msg) if not out else None

        return (rc, out, err)

    def _supplementary_group_args(self) -> tuple[list[str], str | None]:
        """
        Build the ``usermod`` arguments to reconcile the user's
        supplementary group membership with the requested groups.

        Returns ``(args, msg)`` where ``args`` may be empty when no change
        is needed.
        """
        current_groups = self.user_group_membership(exclude_primary=True)

        if not self.groups:
            # No supplementary groups requested: only act if the user still
            # belongs to some that need to be removed.
            if current_groups:
                return (["-G", ""], "change supplementary groups.")
            return ([], None)

        groups = self.get_groups_set(remove_existing=False)

        if set(current_groups).symmetric_difference(groups):
            return (["-G", ",".join(groups)], "change supplementary groups.")

        return ([], None)

    def _expiration_args(self) -> tuple[list[str], str | None]:
        """
        Build the ``usermod`` arguments for the account expiration date.

        Returns ``(args, msg)`` where ``args`` may be empty when the
        current expiration already matches the requested one.
        """
        if not self.expires:
            return ([], None)

        current_expires = int(self.user_password()[1])

        if self.expires < time.gmtime(0):
            if current_expires >= 0:
                return (["-e", ""], None)
            return ([], None)

        # Convert days since Epoch to seconds since Epoch as struct_time
        current_expire_date = time.gmtime(current_expires * 86400)

        # Current expires is negative or we compare year, month, and day only
        if current_expires < 0 or current_expire_date[:3] != self.expires[:3]:
            expiration_date = time.strftime(self.__date_format, self.expires)
            return (
                ["-e", expiration_date],
                f"change account expiration date to {expiration_date}.",
            )

        return ([], None)

    def get_groups_set(self, remove_existing: bool = True) -> set[str]:
        """
        Return the set of supplementary groups for the user.

        Groups that do not exist are skipped with a warning instead of
        raising, so a single missing group does not abort the whole run.
        """
        if not self.groups:
            return set()

        info = self.user_info()

        groups = {x.strip() for x in self.groups.split(",") if x}

        for g in groups.copy():
            if not group_exists(g):
                self.module.warn(f"group '{g}' does not exist and will be skipped")
                groups.discard(g)
                continue

            if info and remove_existing and group_info(g)[2] == info[3]:
                groups.discard(g)

        return groups

    def user_group_membership(self, exclude_primary: bool = True) -> list[str]:
        """
        Return the list of supplementary groups the user belongs to.

        When ``exclude_primary`` is ``False`` the primary group is included.
        """
        user_name, _, uid, gid, _, _, _ = self.get_pwd_info()

        all_groups = grp.getgrall()
        user_groups = [g.gr_name for g in all_groups if self.username in g.gr_mem]
        user_primary_group = [g.gr_name for g in all_groups if gid == g.gr_gid]

        if not exclude_primary:
            user_groups += user_primary_group

        return user_groups

    def create_homedir(self, path: str) -> None:
        """
        Create ``path`` as a home directory by copying ``/etc/skel`` and
        apply the UMASK configured in ``/etc/login.defs``.
        """
        if os.path.exists(path):
            return

        skeleton = "/etc/skel"

        if os.path.exists(skeleton):
            try:
                shutil.copytree(skeleton, path, symlinks=True)
            except OSError as e:
                self.module.exit_json(failed=True, msg=f"{to_native(e)}")
        else:
            try:
                os.makedirs(path)
            except OSError as e:
                self.module.exit_json(failed=True, msg=f"{to_native(e)}")

        # get umask from /etc/login.defs and set correct home mode
        if os.path.exists(self.__login_defs):
            pattern = re.compile(r"^UMASK\s+(\d+)$", re.MULTILINE)

            with open(self.__login_defs, "r") as f:
                content = f.readlines()

            matches = list(filter(pattern.match, content))

            if matches:
                result = pattern.search(matches[0])

                if result:
                    umask = int(result.group(1), 8)
                    mode = 0o777 & ~umask

                    try:
                        os.chmod(path, mode)
                    except OSError as e:
                        self.module.exit_json(failed=True, msg=f"{to_native(e)}")

    def chown_homedir(
        self, uid: int, gid: int, path: str, mode: str | None = None
    ) -> None:
        """
        Recursively change ownership of ``path`` to ``uid``/``gid`` and
        optionally set ``mode`` on the top-level directory.
        """
        self.module.log(msg=f"chown_homedir({uid}, {gid}, {path}, {mode})")

        if mode:
            os.chmod(path, int(mode, base=8))

        try:
            os.chown(path, uid, gid)

            for root, dirs, files in os.walk(path):
                for d in dirs:
                    os.chown(os.path.join(root, d), uid, gid)
                for f in files:
                    os.chown(os.path.join(root, f), uid, gid)

        except OSError as e:
            self.module.exit_json(failed=True, msg=f"{to_native(e)}")


class UsersHelper:
    """
    Shared helpers for the authorized_keys, ssh_keys and sudoers handlers.
    """

    def __init__(self, module: AnsibleModule) -> None:
        """
        Initialize Variables
        """
        self.module = module

        self.changed = False

    def user_info(self) -> None:
        """
        Populate ``user_name``, ``user_home``, ``uid`` and ``gid`` from the
        associated :class:`SingleUser`.
        """
        self.user_name, _, uid, gid, _, self.user_home, _ = self.user_data.user_info()

        if self.user_name == "root":
            uid = 0
            gid = 0

        self.uid = str(uid)
        self.gid = str(gid)

    def create_directory(
        self,
        path: str,
        uid: str | None = None,
        gid: str | None = None,
        mode: str = "0700",
    ) -> None:
        """
        Create ``path`` (idempotently) and, when ``uid`` and ``gid`` are
        given, apply ownership and ``mode``.
        """
        try:
            os.makedirs(path, exist_ok=True)
        except FileExistsError:
            pass

        if uid and gid:
            self.set_rights(path, self.uid, self.gid, mode)

    def verify_files(self, file_name: str, data: str | list[str]) -> bool:
        """
        Return True when the on-disk file already matches the desired data.
        """
        _old_checksum = ""

        def combine_list(d: list[str]) -> str:
            return "|".join(sorted(d))

        data_is_list = isinstance(data, list)

        if data_is_list:
            data = combine_list(data)

        _new_checksum = self.checksum(data)

        # read file to generate checksum
        if os.path.isfile(file_name):
            with open(file_name, "r") as d:
                if data_is_list:
                    lines = [line.rstrip() for line in d]
                    _old_data = combine_list(lines)
                    _old_checksum = self.checksum(_old_data)
                else:
                    _old_data = d.read()
                    _old_checksum = self.checksum(_old_data)

        return _new_checksum == _old_checksum

    def save_file(
        self,
        file_name: str,
        data: str | list[str],
        uid: str | None = None,
        gid: str | None = None,
        mode: str = "0600",
    ) -> None:
        """
        Write ``data`` to ``file_name`` and, when ``uid`` and ``gid`` are
        given, apply ownership and ``mode``.
        """
        data_is_list = isinstance(data, list)

        with open(file_name, "w") as fp:
            if data_is_list:
                fp.write("\n".join(str(item) for item in data))
            else:
                fp.write(data)

        if uid and gid:
            self.set_rights(file_name, uid, gid, mode)

    def checksum(self, plaintext: str | dict) -> str:
        """
        Return the SHA-256 hex digest of ``plaintext`` (dicts are
        serialized as sorted JSON first).
        """
        if isinstance(plaintext, dict):
            password_bytes = json.dumps(plaintext, sort_keys=True).encode("utf-8")
        else:
            password_bytes = plaintext.encode("utf-8")

        password_hash = hashlib.sha256(password_bytes)
        return password_hash.hexdigest()

    def set_rights(
        self,
        path: str,
        owner: str | None = None,
        group: str | None = None,
        mode: str | None = None,
    ) -> None:
        """
        Apply ``mode`` and ownership to ``path``.

        ``owner`` / ``group`` may be names or numeric ids; unknown names
        fall back to their numeric interpretation, missing values to 0.
        """
        if mode is not None:
            os.chmod(path, int(mode, base=8))

        if owner is not None:
            try:
                owner = pwd.getpwnam(owner).pw_uid
            except KeyError:
                owner = int(owner)
        else:
            owner = 0

        if group is not None:
            try:
                group = grp.getgrnam(group).gr_gid
            except KeyError:
                group = int(group)
        else:
            group = 0

        os.chown(path, int(owner), int(group))

    def is_base64(self, sb: str) -> str:
        """
        Decode a base64 encoded value, returning the original input when
        it is not valid base64.
        """
        try:
            data = base64.b64decode(sb, validate=True).decode("utf-8")
        except binascii.Error:
            data = sb

        return data


class AuthorizedKeys(UsersHelper):
    """
    Manage the authorized_keys file for a user.
    """

    def __init__(self, module: AnsibleModule) -> None:
        """
        Initialize Variables
        """
        UsersHelper.__init__(self, module)

        self.authorized_keys: list[str] = []
        self.user_data: SingleUser | None = None

    def user(self, user: SingleUser, auth_keys: list[str] = []) -> None:
        """
        Bind this handler to ``user`` and the authorized keys to deploy.
        """
        self.authorized_keys = auth_keys
        self.user_data = user

    def save(self, path: str | None = None) -> dict:
        """
        Write the authorized_keys file.

        When ``path`` is given the keys are stored centrally as
        ``<path>/<username>``, otherwise as ``$HOME/.ssh/authorized_keys``.
        """
        self.user_info()

        if self.authorized_keys and len(self.authorized_keys) > 0:
            _uid = None
            _gid = None
            self.module.log(msg=f"  - {self.authorized_keys}")

            if not path:
                path = os.path.join(self.user_home, ".ssh")
                _authorized_key_directory_mode = "0700"
                _uid = self.uid
                _gid = self.gid
                _authorized_key_file = os.path.join(path, "authorized_keys")
            else:
                _authorized_key_directory_mode = "0755"
                _authorized_key_file = os.path.join(path, self.user_name)

            self.create_directory(
                path, uid=_uid, gid=_gid, mode=_authorized_key_directory_mode
            )

            if not self.verify_files(_authorized_key_file, self.authorized_keys):
                # changed keys
                self.save_file(
                    file_name=_authorized_key_file,
                    data=self.authorized_keys,
                    uid=_uid,
                    gid=_gid,
                    mode="0600",
                )

                self.changed = True

        return dict(changed=self.changed)

    def remove(self, path: str | None = None) -> None:
        """
        Remove a centrally stored authorized_keys file (``<path>/<username>``).
        """
        self.user_info()

        if path:
            _authorized_key_file = os.path.join(path, self.user_name)
            if os.path.isfile(_authorized_key_file):
                # remove old keyfile
                os.remove(_authorized_key_file)


class SshKeys(UsersHelper):
    """
    Deploy static ssh key files into a user's ~/.ssh directory.
    """

    def __init__(self, module: AnsibleModule) -> None:
        """
        Initialize Variables
        """
        UsersHelper.__init__(self, module)

        self.ssh_keys: dict[str, str] = {}
        self.user_data: SingleUser | None = None

    def user(self, user: SingleUser, ssh_keys: dict[str, str] = {}) -> None:
        """
        Bind this handler to ``user`` and the ssh key files to deploy.
        """
        self.ssh_keys = ssh_keys
        self.user_data = user

    def save(self) -> dict:
        """
        Write all configured ssh key files into ``$HOME/.ssh``.

        Values may be plain text or base64 encoded.
        """
        self.user_info()

        path = os.path.join(self.user_home, ".ssh")

        self.create_directory(path, self.uid, self.gid, mode="0700")

        if isinstance(self.ssh_keys, dict):
            for key, value in self.ssh_keys.items():
                ssh_key_file = os.path.join(path, key)
                ssh_key_value = self.is_base64(value)

                if not self.verify_files(ssh_key_file, ssh_key_value):
                    self.save_file(ssh_key_file, ssh_key_value)

                    self.changed = True

                self.set_rights(
                    ssh_key_file, owner=self.uid, group=self.gid, mode="0600"
                )
        else:
            self.module.log(msg=f"wrong ssh_keys format for user {self.user_name}")

        return dict(changed=self.changed)


class Sudoers(UsersHelper):
    """
    Manage a single sudoers.d rule for a user or group.
    """

    def __init__(self, module: AnsibleModule) -> None:
        """
        Initialize Variables
        """
        UsersHelper.__init__(self, module)

        self.user_data: SingleUser | None = None
        self.nopassword = False
        self.runas: str | None = None
        self.sudoers_path = "/etc/sudoers.d"
        self.file_name: str | None = None
        self.commands: str | list[str] = []

    def user(self, user: SingleUser, sudo_data: dict) -> None:
        """
        Bind this handler to ``user`` and unpack the sudo rule definition.
        """
        self.user_data = user

        self.nopassword = sudo_data.get("nopassword", False)
        self.runas = sudo_data.get("runas", None)
        self.group = sudo_data.get("group", None)
        self.sudoers_path = sudo_data.get("sudoers_path", "/etc/sudoers.d")
        self.commands = sudo_data.get("commands", [])

        self.sudo_data = sudo_data

    def create_sudoers(self) -> dict:
        """
        Create and validate the sudoers.d rule for the user.

        When ``nopassword`` is not set the rule is removed instead. An
        invalid rule (rejected by ``visudo``) is deleted again and reported
        as failed.
        """
        if not os.path.isdir(self.sudoers_path):
            return dict(
                failed=True,
                msg=f"directory {self.sudoers_path} not exists.",
            )

        self.user_info()
        self.file_name = os.path.join(self.sudoers_path, self.user_name)

        if self.nopassword:
            if isinstance(self.commands, str):
                commands = [self.commands]
            else:
                commands = self.commands

            self.commands = commands

            if len(self.sudo_data) == 0:
                return dict(changed=False, failed=False)

            content = self.content()

            if not self.verify_files(self.file_name, content):
                # changed rule
                self.save_file(file_name=self.file_name, data=content, mode="0440")

                # validate created sudoers rule
                valid, msg = self.validate(self.file_name)

                if not valid:
                    self.module.log(msg=f"  ERROR {msg}")
                    self.delete_sudoers()

                    return dict(failed=True, msg=msg)

                self.changed = True

            return dict(changed=self.changed)
        else:
            return self.delete_sudoers()

    def delete_sudoers(self) -> dict:
        """
        Remove the sudoers.d rule for the user, if present.
        """
        self.user_info()
        self.file_name = os.path.join(self.sudoers_path, self.user_name)

        if os.path.isdir(self.sudoers_path) and os.path.isfile(self.file_name):
            os.remove(self.file_name)

            return dict(changed=True, failed=False)
        else:
            return dict(changed=False, failed=False)

    def content(self) -> str:
        """
        Render the sudoers rule line for the user (or group).
        """
        nopasswd_str = ""
        runas_str = ""

        if self.group:
            owner = f"%{self.group}"
        elif self.user_name:
            owner = self.user_name

        commands_str = ", ".join(self.commands)

        if self.nopassword:
            nopasswd_str = "NOPASSWD:"

        if self.runas:
            runas_str = f"({self.runas})"

        return f"{owner} ALL={runas_str}{nopasswd_str} {commands_str}\n"

    def validate(self, file_name: str) -> tuple[bool, str]:
        """
        Validate the sudoers rule in ``file_name`` using ``visudo -c``.

        Returns ``(valid, msg)``.
        """
        result = True
        msg = "created sudoers rule are valid"

        visudo_path = self.module.get_bin_path("visudo", required="required")

        if visudo_path is None:
            return (result, msg)

        check_command = [visudo_path, "-c", "-f", file_name]
        rc, stdout, stderr = self.module.run_command(check_command)

        if rc != 0:
            result = False
            msg = f"Failed to validate sudoers rule:\n{stdout}\n{stderr}"

        return (result, msg)


class MultiUsers:
    """
    Main entry point: process the list of user definitions.
    """

    def __init__(self, module: AnsibleModule) -> None:
        """
        Initialize all needed Variables
        """
        self.module = module

        self.users = module.params.get("users")
        self.output = module.params.get("output")

    def run(self) -> dict:
        """
        Process every user definition and aggregate the per-user results
        into the module return value.
        """
        result: dict[str, dict] = {}

        auth_keys = AuthorizedKeys(self.module)
        ssh_keys = SshKeys(self.module)
        sudoers = Sudoers(self.module)

        for u in self.users:
            res: dict[str, Any] = {}

            _username = u.get("username")
            _state = u.get("state")
            _home = u.get("home", os.path.join("/home", _username))

            _authorized_keys = u.get("authorized_keys", [])
            _ssh_keys = u.get("ssh_keys", {})
            _sudo = u.get("sudo", {})

            _authorized_key_directory = u.get("authorized_key_directory", None)

            # 'lock' is handled like 'present' but forces the account to be locked.
            _password_lock = u.get("password_lock", True)
            if _state == "lock":
                _password_lock = True

            m = dict(
                authorized_keys=_authorized_keys,
                comment=u.get("comment"),
                create_home=u.get("create_home", True),
                expires=u.get("expires"),
                force=u.get("force", False),
                group=u.get("group", None),
                groups=u.get("groups", []),
                home=_home,
                move_home=u.get("move_home", False),
                password=u.get("password"),
                password_lock=_password_lock,
                remove=u.get("remove", False),
                shell=u.get("shell", "/bin/bash"),
                ssh_keys=_ssh_keys,
                state=_state,
                uid=u.get("uid", None),
                umask=u.get("umask"),
                update_password=u.get("update_password", "always"),
                username=_username,
            )

            user = SingleUser(m, self.module)

            (invalid, msg) = validate_password_hash(user.password)

            if invalid:
                res.update(
                    {
                        "failed": True,
                        "msg": msg,
                    }
                )
            else:
                user_exists = user.user_exists()

                if _state == "absent":
                    if user_exists:
                        if _authorized_keys:
                            auth_keys.user(user, _authorized_keys)
                            authorized_keys_state = auth_keys.remove(
                                _authorized_key_directory
                            )

                            res.update({"authorized_key": authorized_keys_state})

                        if _sudo:
                            sudoers.user(user, _sudo)
                            sudo_state = sudoers.delete_sudoers()

                            res.update({"sudo": sudo_state})

                        (rc, out, err) = user.remove_user()

                        if rc != 0:
                            res.update({"failed": True, "msg": err, "rc": rc})
                        else:
                            res.update(
                                {
                                    "changed": True,
                                    "msg": "user removed",
                                }
                            )

                            if self.output == "full":
                                res.update(
                                    {
                                        "force": user.force,
                                        "remove": user.remove,
                                    }
                                )
                    else:
                        res.update({"changed": False})

                else:
                    # 'present' and 'lock' share the same create/modify logic.
                    if not user_exists:
                        # Check to see if the provided home path contains parent directories
                        # that do not exist.
                        path_needs_parents = False
                        if user.home and user.create_home:
                            parent = os.path.dirname(user.home)
                            if not os.path.isdir(parent):
                                path_needs_parents = True

                        (rc, out, err) = user.create_user()

                        if rc == 0:
                            res.update(
                                {
                                    "changed": True,
                                    "msg": "User successful created",
                                }
                            )

                        # If the home path had parent directories that needed to be created,
                        # make sure file permissions are correct in the created home directory.
                        if path_needs_parents:
                            info = user.user_info()

                            if info is not False:
                                user.chown_homedir(info[2], info[3], user.home, "0750")

                        if self.output == "full":
                            res.update({"create_home": user.create_home})
                    else:
                        # modify user
                        (rc, out, err) = user.modify_user()

                        if rc is None:
                            res.update({"changed": False})
                        else:
                            res.update({"changed": True})

                            if out:
                                res.update({"msg": out})

                    if rc is not None and rc != 0:
                        res.update(
                            {
                                "failed": True,
                                "msg": err,
                                "rc": rc,
                            }
                        )

                    if self.output == "full":
                        if user.password is not None:
                            res["password"] = "NOT_LOGGING_PASSWORD"

                    if _authorized_keys:
                        auth_keys.user(user, _authorized_keys)
                        authorized_keys_state = auth_keys.save(
                            _authorized_key_directory
                        )

                        res.update({"authorized_key": authorized_keys_state})

                    if _ssh_keys:
                        ssh_keys.user(user, _ssh_keys)
                        ssh_keys_state = ssh_keys.save()

                        res.update({"ssh_keys": ssh_keys_state})

                    # sudoers file
                    sudoers.user(user, _sudo)

                    sudo_state = None

                    if _sudo:
                        sudo_state = sudoers.create_sudoers()
                    else:
                        sudo_state = sudoers.delete_sudoers()

                    # Merge the sudo result into the user result WITHOUT
                    # discarding an already recorded user-level change or
                    # failure (user creation must stay 'changed=True' even
                    # when the sudo step reports no change).
                    res["changed"] = res.get("changed", False) or sudo_state.get(
                        "changed", False
                    )
                    res["failed"] = res.get("failed", False) or sudo_state.get(
                        "failed", False
                    )

                    if sudo_state:
                        res.update({"sudo": sudo_state})

            result[_username] = res

        result_changed = {k: v for k, v in result.items() if v.get("changed")}
        result_failed = {k: v for k, v in result.items() if v.get("failed")}

        # find all changed and define our variable
        changed = len(result_changed) > 0
        # find all failed and define our variable
        failed = len(result_failed) > 0

        final_result = dict(failed=failed, changed=changed)

        if changed:
            final_result.update({"result_changed": result_changed})

        if failed:
            final_result.update({"result_failed": result_failed})

        if self.output == "full":
            final_result.update({"output": result})

        return final_result


# ---------------------------------------------------------------------------------------
# Module execution.
#


def main():
    """
    Build the AnsibleModule, run :class:`MultiUsers` and return the result.
    """
    module = AnsibleModule(
        argument_spec=dict(
            users=dict(required=True, type="list"),
            output=dict(type="str", default="compact", choices=["compact", "full"]),
        ),
        supports_check_mode=False,
    )

    u = MultiUsers(module)
    result = u.run()

    module.exit_json(**result)


# import module snippets
if __name__ == "__main__":
    main()
