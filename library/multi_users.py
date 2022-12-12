#!/usr/bin/env python3

# -*- coding: utf-8 -*-

# (c) 2022, Bodo Schulz <bodo@boone-schulz.de>
# BSD 2-clause (see LICENSE or https://opensource.org/licenses/BSD-2-Clause)

from __future__ import absolute_import, division, print_function
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_bytes, to_native
from ansible.module_utils import distro

import json
import hashlib
import time
import shutil
import re
import pwd
import os
import math
import grp
import errno
import base64
import binascii

DOCUMENTATION = """
"""

EXAMPLES = """
"""

# ---------------------------------------------------------------------------------------


try:
    import spwd
    HAVE_SPWD = True
except ImportError:
    HAVE_SPWD = False


_HASH_RE = re.compile(r'[^a-zA-Z0-9./=]')


class SingleUser():
    """
    """
    # platform = 'Generic'
    # distribution = None  # type: str | None
    # PASSWORDFILE = '/etc/passwd'
    SHADOWFILE = '/etc/shadow'  # type: str | None
    SHADOWFILE_EXPIRE_INDEX = 7
    LOGIN_DEFS = '/etc/login.defs'
    DATE_FORMAT = '%Y-%m-%d'

    def __init__(self, user, module):
        """
        """
        self.module = module

        # self.module.log(msg=f"  user: '{user}'")

        self.append = user.get("append", False)
        self.comment = user.get("comment")
        self.create_home = user.get("create_home", True)
        self.expires = user.get("expires", None)
        self.force = user.get("force", False)
        self.group = user.get("group", None)
        self.groups = ",".join(user.get("groups", []))
        self.home = user.get("home")
        self.move_home = user.get("move_home", False)
        self.password = user.get("password", None)
        self.password_lock = user.get("password_lock", False)
        self.remove = user.get("remove", False)
        self.seuser = user.get("seuser", None)
        self.shell = user.get("shell", None)
        self.skeleton = user.get("skeleton", None)
        self.state = user.get("state")
        self.system = user.get("system", False)
        self.uid = user.get("uid", None)
        self.umask = user.get("umask", None)
        self.update_password = user.get("update_password", 'always')
        self.username = user.get("username")

    def check_password_encrypted(self):
        """
        """
        msg = None
        maybe_invalid = True

        if not self.password:
            return (False, "no password given.")

        else:
            maybe_invalid = False

            # Allow setting certain passwords in order to disable the account
            if self.password in set(['*', '!', '*************']):
                maybe_invalid = False
            else:
                # : for delimiter, * for disable user, ! for lock user
                # these characters are invalid in the password
                if any(char in self.password for char in ':*!'):
                    maybe_invalid = True
                if '$' not in self.password:
                    maybe_invalid = True
                else:
                    fields = self.password.split("$")
                    if len(fields) >= 3:
                        # contains character outside the crypto constraint
                        if bool(_HASH_RE.search(fields[-1])):
                            maybe_invalid = True
                        # md5
                        if fields[1] == '1' and len(fields[-1]) != 22:
                            maybe_invalid = True
                        # sha256
                        if fields[1] == '5' and len(fields[-1]) != 43:
                            maybe_invalid = True
                        # sha512
                        if fields[1] == '6' and len(fields[-1]) != 86:
                            maybe_invalid = True
                    else:
                        maybe_invalid = True

            if maybe_invalid:
                msg = "The input password appears not to have been hashed.\nThe 'password' argument must be encrypted for this module to work properly."

        return (maybe_invalid, msg)

    def execute_command(self, cmd, use_unsafe_shell=False, data=None, obey_checkmode=True):
        """
        """
        # self.module.log(f"execute_command({cmd}, {use_unsafe_shell}, {data}, {obey_checkmode}")

        if self.module.check_mode and obey_checkmode:
            self.module.debug(f"In check mode, would have run: '{cmd}'")
            return (0, '', '')
        else:
            # cast all args to strings ansible-modules-core/issues/4397
            cmd = [str(x) for x in cmd]
            return self.module.run_command(cmd, use_unsafe_shell=use_unsafe_shell, data=data)

    def user_exists(self):
        """
        """
        try:
            if pwd.getpwnam(self.username):
                return True
        except KeyError:
            return False

    def get_pwd_info(self):
        """
        """
        if not self.user_exists():
            return False

        return list(pwd.getpwnam(self.username))

    def user_info(self):
        """
        """
        if not self.user_exists():
            return False

        info = self.get_pwd_info()
        if len(info[1]) == 1 or len(info[1]) == 0:
            info[1] = self.user_password()[0]

        return info

    def user_password(self):
        """
        """
        passwd = ''
        expires = ''
        if HAVE_SPWD:
            try:
                passwd = spwd.getspnam(self.username)[1]
                expires = spwd.getspnam(self.username)[7]
                return passwd, expires
            except KeyError:
                return passwd, expires
            except OSError as e:
                # Python 3.6 raises PermissionError instead of KeyError
                # Due to absence of PermissionError in python2.7 need to check
                # errno
                if e.errno in (errno.EACCES, errno.EPERM, errno.ENOENT):
                    return passwd, expires
                raise

        if not self.user_exists():
            return passwd, expires

        elif self.SHADOWFILE:
            passwd, expires = self.parse_shadow_file()

        return passwd, expires

    def parse_shadow_file(self):
        """
        """
        passwd = ''
        expires = ''
        if os.path.exists(self.SHADOWFILE) and os.access(self.SHADOWFILE, os.R_OK):
            with open(self.SHADOWFILE, 'r') as f:
                for line in f:
                    if line.startswith(f"{self.username}:"):
                        passwd = line.split(':')[1]
                        expires = line.split(':')[self.SHADOWFILE_EXPIRE_INDEX] or -1

        return passwd, expires

    def create_user(self):
        """
        """
        command_name = 'useradd'

        cmd = [self.module.get_bin_path(command_name, True)]

        if self.uid is not None:
            cmd.append('-u')
            cmd.append(self.uid)

            if self.non_unique:
                cmd.append('-o')

        if self.seuser is not None:
            cmd.append('-Z')
            cmd.append(self.seuser)

        if self.group is not None:
            if not self.group_exists(self.group):
                msg = f"Group {self.group} does not exist"
                return (1, "", msg)

            cmd.append('-g')
            cmd.append(self.group)

        elif self.group_exists(self.username):
            # use the -N option (no user group) if a group already
            # exists with the same name as the user to prevent
            # errors from useradd trying to create a group when
            # USERGROUPS_ENAB is set in /etc/login.defs.
            if os.path.exists('/etc/redhat-release'):
                dist = distro.version()
                major_release = int(dist.split('.')[0])
                if major_release <= 5:
                    cmd.append('-n')
                else:
                    cmd.append('-N')

            elif os.path.exists('/etc/SuSE-release'):
                # -N did not exist in useradd before SLE 11 and did not
                # automatically create a group
                dist = distro.version()
                major_release = int(dist.split('.')[0])
                if major_release >= 12:
                    cmd.append('-N')
            else:
                cmd.append('-N')

        if self.groups is not None and len(self.groups):
            groups = self.get_groups_set()

            cmd.append('-G')
            cmd.append(','.join(groups))

        if self.comment is not None:
            cmd.append('-c')
            cmd.append(self.comment)

        if self.home is not None:
            # If the specified path to the user home contains parent directories that
            # do not exist and create_home is True first create the parent directory
            # since useradd cannot create it.
            if self.create_home:
                parent = os.path.dirname(self.home)
                if not os.path.isdir(parent):
                    self.create_homedir(self.home)

            cmd.append('-d')
            cmd.append(self.home)

        if self.shell is not None:
            cmd.append('-s')
            cmd.append(self.shell)

        if self.expires is not None:
            cmd.append('-e')
            if self.expires < time.gmtime(0):
                cmd.append('')
            else:
                cmd.append(time.strftime(self.DATE_FORMAT, self.expires))

        if self.password is not None:
            cmd.append('-p')
            if self.password_lock:
                cmd.append(f"!{self.password}")
            else:
                cmd.append(self.password)

        if self.create_home:
            cmd.append('-m')

            if self.skeleton is not None:
                cmd.append('-k')
                cmd.append(self.skeleton)

            if self.umask is not None:
                cmd.append('-K')
                cmd.append('UMASK=' + self.umask)
        else:
            cmd.append('-M')

        if self.system:
            cmd.append('-r')

        cmd.append(self.username)
        (rc, out, err) = self.execute_command(cmd)

        if rc != 0:
            return (rc, out, err)

        if self.groups is None or len(self.groups) == 0:
            return (rc, out, err)

        return (rc, out, err)

    def remove_user(self):
        command_name = 'userdel'

        cmd = [self.module.get_bin_path(command_name, True)]
        if self.force:
            cmd.append('-f')
        if self.remove:
            cmd.append('-r')
        cmd.append(self.username)

        return self.execute_command(cmd)

    def modify_user(self):
        """
        """
        command_name = 'usermod'

        cmd = [self.module.get_bin_path(command_name, True)]
        info = self.user_info()
        has_append = self._check_usermod_append()

        if self.uid is not None and info[2] != int(self.uid):
            cmd.append('-u')
            cmd.append(self.uid)

            if self.non_unique:
                cmd.append('-o')

        if self.group is not None:
            if not self.group_exists(self.group):
                msg = f"Group {self.group} does not exist"
                return (1, "", msg)

            ginfo = self.group_info(self.group)
            if info[3] != ginfo[2]:
                cmd.append('-g')
                cmd.append(self.group)

        if self.groups is not None:
            # get a list of all groups for the user, including the primary
            current_groups = self.user_group_membership(exclude_primary=False)
            groups_need_mod = False
            groups = []

            if self.groups == '':
                if current_groups and not self.append:
                    groups_need_mod = True
            else:
                groups = self.get_groups_set(remove_existing=False)
                group_diff = set(current_groups).symmetric_difference(groups)

                if group_diff:
                    if self.append:
                        for g in groups:
                            if g in group_diff:
                                if has_append:
                                    cmd.append('-a')
                                groups_need_mod = True
                                break
                    else:
                        groups_need_mod = True

            if groups_need_mod:

                if self.append and not has_append:
                    cmd.append('-A')
                    cmd.append(','.join(group_diff))
                else:
                    cmd.append('-G')
                    cmd.append(','.join(groups))

        if self.comment is not None and info[4] != self.comment:
            cmd.append('-c')
            cmd.append(self.comment)

        if self.home is not None and info[5] != self.home:
            cmd.append('-d')
            cmd.append(self.home)
            if self.move_home:
                cmd.append('-m')

        if self.shell is not None and info[6] != self.shell:
            cmd.append('-s')
            cmd.append(self.shell)

        if self.expires is not None:

            current_expires = int(self.user_password()[1])

            if self.expires < time.gmtime(0):
                if current_expires >= 0:
                    cmd.append('-e')
                    cmd.append('')
            else:
                # Convert days since Epoch to seconds since Epoch as struct_time
                current_expire_date = time.gmtime(current_expires * 86400)

                # Current expires is negative or we compare year, month, and day only
                if current_expires < 0 or current_expire_date[:3] != self.expires[:3]:
                    cmd.append('-e')
                    cmd.append(time.strftime(self.DATE_FORMAT, self.expires))

        # Lock if no password or unlocked, unlock only if locked
        if self.password_lock and not info[1].startswith('!'):
            cmd.append('-L')

        elif self.password_lock is False and info[1].startswith('!'):
            # usermod will refuse to unlock a user with no password, module shows 'changed' regardless
            cmd.append('-U')

        if self.update_password == 'always' and self.password is not None and info[1].lstrip('!') != self.password.lstrip('!'):
            # Remove options that are mutually exclusive with -p
            cmd = [c for c in cmd if c not in ['-U', '-L']]
            cmd.append('-p')
            if self.password_lock:
                # Lock the account and set the hash in a single command
                cmd.append(f"!{self.password}")
            else:
                cmd.append(self.password)

        (rc, out, err) = (None, '', '')

        # skip if no usermod changes to be made
        if len(cmd) > 1:
            cmd.append(self.username)
            (rc, out, err) = self.execute_command(cmd)

        if not (rc is None or rc == 0):
            return (rc, out, err)

        return (rc, out, err)

    def group_exists(self, group):
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

    def _check_usermod_append(self):
        """
        """
        # check if this version of usermod can append groups
        command_name = 'usermod'

        usermod_path = self.module.get_bin_path(command_name, True)

        # for some reason, usermod --help cannot be used by non root
        # on RH/Fedora, due to lack of execute bit for others
        if not os.access(usermod_path, os.X_OK):
            return False

        cmd = [usermod_path, '--help']
        (rc, data1, data2) = self.execute_command(cmd, obey_checkmode=False)
        helpout = data1 + data2

        # check if --append exists
        lines = to_native(helpout).split('\n')
        for line in lines:
            if line.strip().startswith('-a, --append'):
                return True

        return False

    def group_info(self, group):
        """
        """
        if not self.group_exists(group):
            return False

        try:
            # Try group as a gid first
            return list(grp.getgrgid(int(group)))
        except (ValueError, KeyError):
            return list(grp.getgrnam(group))

    def get_groups_set(self, remove_existing=True):
        """
        """
        if self.groups is None:
            return None
        info = self.user_info()

        groups = set(x.strip() for x in self.groups.split(',') if x)

        for g in groups.copy():
            if not self.group_exists(g):
                msg = f"Group {self.group} does not exist"
                return (1, "", msg)

            if info and remove_existing and self.group_info(g)[2] == info[3]:
                groups.remove(g)

        return groups

    def user_group_membership(self, exclude_primary=True):
        '''
            Return a list of groups the user belongs to
        '''
        groups = []
        info = self.get_pwd_info()

        for group in grp.getgrall():
            """
            """
            if self.username in group.gr_mem:
                # Exclude the user's primary group by default
                if not exclude_primary:
                    groups.append(group[0])
                else:
                    if info[3] != group.gr_gid:
                        groups.append(group[0])

        return groups

    def create_homedir(self, path):
        """
        """
        if not os.path.exists(path):
            if self.skeleton is not None:
                skeleton = self.skeleton
            else:
                skeleton = '/etc/skel'

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
            if os.path.exists(self.LOGIN_DEFS):
                with open(self.LOGIN_DEFS, 'r') as f:
                    for line in f:
                        m = re.match(r'^UMASK\s+(\d+)$', line)
                        if m:
                            umask = int(m.group(1), 8)
                            mode = 0o777 & ~umask
                            try:
                                os.chmod(path, mode)
                            except OSError as e:
                                self.module.exit_json(failed=True, msg=f"{to_native(e)}")

    def chown_homedir(self, uid, gid, path):
        try:
            os.chown(path, uid, gid)
            for root, dirs, files in os.walk(path):
                for d in dirs:
                    os.chown(os.path.join(root, d), uid, gid)
                for f in files:
                    os.chown(os.path.join(root, f), uid, gid)
        except OSError as e:
            self.module.exit_json(failed=True, msg=f"{to_native(e)}")


class UsersHelper():
    module = None

    def __init__(self, module):
        """
          Initialize Variables
        """
        self.module = module

        self.changed = False

    def user_info(self):
        """
        """
        self.user_name, _, uid, gid, _, self.user_home, _ = self.user_data.user_info()

        if self.user_name == "root":
            uid = 0
            gid = 0

        self.uid = str(uid)
        self.gid = str(gid)

        # self.module.log(msg=f"    - user_name: {self.user_name}, uid: {self.uid}, gid: {self.gid}, home: {self.user_home}")

    def create_directory(self, path, mode="0700"):
        """
        """
        try:
            os.makedirs(path, exist_ok=True)
        except FileExistsError:
            pass

        self.set_rights(path, self.uid, self.gid, mode)

    def remove_directory(self, path):
        """
        """
        # self.module.log(msg=f"remove directory {path}")

        for root, dirs, files in os.walk(path, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))

    def verify_files(self, file_name, data):
        """
        """
        _old_data = ""
        _old_checksum = ""

        def combine_list(d):
            return "|".join(sorted(d))

        data_is_list = isinstance(data, list)

        if data_is_list:
            data = combine_list(data)

        _new_checksum = self.checksum(data)

        """
          read file to generate checksum
        """
        if os.path.isfile(file_name):

            with open(file_name, 'r') as d:
                if data_is_list:
                    lines = [line.rstrip() for line in d]
                    _old_data = combine_list(lines)
                    _old_checksum = self.checksum(_old_data)
                else:
                    _old_data = d.read()
                    _old_checksum = self.checksum(_old_data)

        result = (_new_checksum == _old_checksum)

        return result

    def save_file(self, file_name, data, mode="0600"):
        """
        """
        # self.module.log(msg=f"save_file(self, {file_name}, data, {mode})")
        # self.module.log(msg=f"  - {type(data)}")

        data_is_list = isinstance(data, list)

        with open(file_name, 'w') as fp:
            if data_is_list:
                fp.write("\n".join(str(item) for item in data))
            else:
                fp.write(data)

        self.set_rights(file_name, self.uid, self.gid, mode)

        pass

    def checksum(self, plaintext):
        """
        """
        if isinstance(plaintext, dict):
            password_bytes = json.dumps(plaintext, sort_keys=True).encode('utf-8')
        else:
            password_bytes = plaintext.encode('utf-8')

        password_hash = hashlib.sha256(password_bytes)
        return password_hash.hexdigest()

    def set_rights(self, path, owner = None, group = None, mode = None):
        """
        """
        # self.module.log(msg=f"set_rights(self, {path}, {owner} {group}, {mode})")

        if mode is not None:
            os.chmod(path, int(mode, base=8))

        if owner is not None:
            try:
                owner = pwd.getpwnam(owner).pw_uid
            except KeyError:
                owner = int(owner)
                pass
        else:
            owner = 0

        if group is not None:
            try:
                group = grp.getgrnam(group).gr_gid
            except KeyError:
                group = int(group)
                pass
        else:
            group = 0

        os.chown(path, int(owner), int(group))

    def is_base64(self, sb):
        """
        """
        try:
            data = base64.b64decode(sb, validate=True).decode('utf-8')
        except binascii.Error:
            # self.module.log(msg=f"ERROR  {e}")
            data = sb

        return data


class AuthorizedKeys(UsersHelper):
    """
    """
    module = None

    def __init__(self, module):
        """
          Initialize Variables
        """
        UsersHelper.__init__(self, module)

        self.authorized_keys = []
        self.user_data = None

    def user(self, user, auth_keys = []):
        """
        """
        self.authorized_keys = auth_keys
        self.user_data = user

    def save(self, path = None):
        """
        """
        self.user_info()

        if self.authorized_keys and len(self.authorized_keys) > 0:
            """
            """
            if not path:
                path = os.path.join(self.user_home, ".ssh")
                _authorized_key_directory_mode = "0700"
                _authorized_key_file = os.path.join(path, "authorized_keys")
            else:
                _authorized_key_directory_mode = "0750"
                _authorized_key_file = os.path.join(path, self.user_name)

            # self.module.log(msg=f"    - key file: {_authorized_key_file}")

            self.create_directory(path, _authorized_key_directory_mode)

            if not self.verify_files(_authorized_key_file, self.authorized_keys):
                # changed keys
                self.save_file(file_name=_authorized_key_file, data=self.authorized_keys, mode="0600")

                self.changed = True

        return dict(
            changed=self.changed
        )

    def remove(self, path = None):
        """
        """
        self.user_info()

        if path:
            """
            """
            _authorized_key_file = os.path.join(path, self.user_name)
            if os.path.isfile(_authorized_key_file):
                """
                  remove old  keyfile
                """
                os.remove(_authorized_key_file)


class SshKeys(UsersHelper):
    """
    """
    module = None

    def __init__(self, module):
        """
          Initialize Variables
        """
        UsersHelper.__init__(self, module)

        self.ssh_keys = {}
        self.user_data = None

    def user(self, user, ssh_keys = {}):
        """
        """
        self.ssh_keys = ssh_keys
        self.user_data = user

    def save(self):
        """
        """
        self.user_info()

        path = os.path.join(self.user_home, ".ssh")

        self.create_directory(path, "0700")

        if isinstance(self.ssh_keys, dict):
            for key, value in self.ssh_keys.items():
                ssh_key_file = os.path.join(path, key)
                ssh_key_value = self.is_base64(value)

                if not self.verify_files(ssh_key_file, ssh_key_value):
                    self.save_file(ssh_key_file, ssh_key_value)

                    self.change = True
        else:
            self.module.log(msg=f"wrong ssh_keys format for user {self.user_name}")

        return dict(
            changed=self.changed
        )


class Sudoers(UsersHelper):
    """
    """
    module = None

    def __init__(self, module):
        """
          Initialize Variables
        """
        UsersHelper.__init__(self, module)

        self.user_data = None
        self.nopassword = False
        self.runas = None
        self.sudoers_path = '/etc/sudoers.d'
        self.file_name = None
        self.commands = []


    def user(self, user, sudo_data):
        """
        """
        self.user_data = user

        #self.user_info()

        #self.user = self.user_name
        self.nopassword = sudo_data.get('nopassword', False)
        self.runas = sudo_data.get('runas', None)
        self.group = sudo_data.get('group', None)
        self.sudoers_path = sudo_data.get('sudoers_path', '/etc/sudoers.d')
        # self.file_name = os.path.join(self.sudoers_path, self.user_name)
        self.commands = sudo_data.get('commands')

        self.sudo_data = sudo_data

    def create_sudoers(self):
        """
        """
        if not os.path.isdir(self.sudoers_path):
            return dict(
                failed = True,
                msg = f"directory {self.sudoers_path} not exists.",
            )

        self.user_info()
        self.file_name = os.path.join(self.sudoers_path, self.user_name)

        if isinstance(self.commands, str):
            commands = [self.commands]
        else:
            commands = self.commands

        self.commands = commands

        self.module.log(msg=f"  sudoers file {self.file_name}")
        self.module.log(msg=f"  sudoers data {self.sudo_data} {len(self.sudo_data)}")

        if len(self.sudo_data) == 0:
            return dict(
                changed = False,
                failed = False
            )

        content = self.content()

        self.module.log(msg=f"  content {content}")

        if not self.verify_files(self.file_name, content):
            # changed keys
            self.save_file(file_name=self.file_name, data=content, mode="0755")

            # validate created sudoers rule
            valid, msg = self.validate(self.file_name)
            # self.module.log(msg=f"  valid {valid}")

            if not valid:
                self.module.log(msg=f"  ERROR {msg}")
                self.delete_sudoers()

                return dict(
                    failed = True,
                    msg = msg
                )

            self.changed = True

        return dict(
            changed=self.changed
        )

    def delete_sudoers(self):
        """
        """
        self.user_info()
        self.file_name = os.path.join(self.sudoers_path, self.user_name)

        if os.path.isdir(self.sudoers_path) and os.path.isfile(self.file_name):
            os.remove(self.file_name)

            return dict(
                changed = True,
                failed = False
            )


    def content(self):
        nopasswd_str = ""
        runas_str = ""

        if self.group:
            owner = f"%{self.group}"
        elif self.user_name:
            owner = self.user_name

        commands_str = ', '.join(self.commands)

        if self.nopassword:
            nopasswd_str = 'NOPASSWD:'

        if self.runas:
            runas_str = f"({self.runas})"

        return f"{owner} ALL={runas_str}{nopasswd_str} {commands_str}\n"

    def validate(self, file_name):
        """
        """
        result = True
        msg = "created sudoers rule are valid"

        visudo_path = self.module.get_bin_path('visudo', required='required')

        if visudo_path is None:
            return

        check_command = [visudo_path, '-c', '-f', file_name]
        rc, stdout, stderr = self.module.run_command(check_command)

        if rc != 0:
            result = False
            msg = f"Failed to validate sudoers rule:\n{stdout}\n{stderr}" # '.format(stdout=stdout))
            # raise Exception('Failed to validate sudoers rule:\n{stdout}'.format(stdout=stdout))

        return (result, msg)

class MultiUsers():
    """
      Main Class to implement the Icinga2 API Client
    """
    module = None

    def __init__(self, module):
        """
          Initialize all needed Variables
        """
        self.module = module

        self.users = module.params.get("users")
        self.output = module.params.get("output")

    def run(self):
        """
        """
        result = {}

        auth_keys = AuthorizedKeys(self.module)
        ssh_keys = SshKeys(self.module)
        sudoers = Sudoers(self.module)

        for u in self.users:
            self.module.log(msg="-----------------------------------------------------------")
            self.module.log(msg=f"  - {u}")

            res = {}

            _username = u.get("username")
            _state = u.get("state")
            _home = u.get("home")

            _authorized_keys = u.get("authorized_keys", [])
            _ssh_keys = u.get("ssh_keys", {})
            _sudo = u.get("sudo", {})

            # self.module.log(msg=f"    sudo: {_sudo}")

            _authorized_key_directory = u.get("authorized_key_directory", None)

            m = dict(
                authorized_keys = _authorized_keys,
                comment = u.get("comment"),
                create_home = u.get("create_home", True),
                expires = u.get("expires"),
                force = u.get('force', False),
                group = u.get("group", None),
                groups = u.get("groups", []),
                home = _home,
                # local = u.get('local', False),
                password = u.get("password"),
                password_expire_max = u.get("password_expire_max"),
                password_expire_min = u.get("password_expire_min"),
                password_lock = u.get("password_lock"),
                remove = u.get('remove', False),
                shell = u.get("shell", "/bin/bash"),
                ssh_keys = _ssh_keys,
                state = _state,
                uid = u.get("uid", None),
                umask = u.get("umask"),
                update_password = u.get("update_password", 'always'),
                username = _username,
            )

            user = SingleUser(m, self.module)

            (maybe_invalid, msg) = user.check_password_encrypted()

            if maybe_invalid:
                res.update({
                    "failed": True,
                    "msg": msg,
                })
            else:
                user_exists = user.user_exists()

                if _state == 'absent':
                    """
                    """
                    if user_exists:
                        """
                        """
                        if self.module.check_mode:
                            res.update({
                                "check_mode": True,
                                "msg": "check mode"
                            })

                        if _authorized_keys:
                            auth_keys.user(user, _authorized_keys)
                            authorized_keys_state = auth_keys.remove(_authorized_key_directory)

                            res.update({
                                "authorized_key": authorized_keys_state
                            })

                        if _sudo:
                            sudoers.user(user, _sudo)
                            sudo_state = sudoers.delete_sudoers()

                            res.update({
                                "sudo": sudo_state
                            })

                        (rc, out, err) = user.remove_user()

                        if rc != 0:
                            res.update({
                                "failed": True,
                                "msg": err,
                                "rc": rc
                            })
                        else:
                            res.update({
                                "changed": True,
                                "msg": "user removed",
                            })

                            if self.output == "full":
                                res.update({
                                    "force": user.force,
                                    "remove": user.remove,
                                })

                    else:
                        res.update({
                            "changed": False
                        })

                elif _state == 'present':
                    """
                    """
                    if not user_exists:
                        """
                        """
                        if self.module.check_mode:
                            res.update({
                                "check_mode": True,
                                "msg": "check mode"
                            })
                            # self.module.exit_json(changed=True)

                        # Check to see if the provided home path contains parent directories
                        # that do not exist.
                        path_needs_parents = False
                        if user.home and user.create_home:
                            parent = os.path.dirname(user.home)
                            if not os.path.isdir(parent):
                                path_needs_parents = True

                        (rc, out, err) = user.create_user()

                        if rc == 0:
                            res.update({
                                "changed": True,
                                "msg": "User successful created",
                            })

                        # If the home path had parent directories that needed to be created,
                        # make sure file permissions are correct in the created home directory.
                        if path_needs_parents:
                            info = user.user_info()

                            if info is not False:
                                user.chown_homedir(info[2], info[3], user.home)

                        if self.output == "full":
                            if self.module.check_mode:
                                res.update({
                                    "system": user.name
                                })
                            else:
                                res.update({
                                    "system": user.system,
                                    "create_home": user.create_home
                                })

                    else:
                        # modify user (note: this function is check mode aware)
                        # self.module.log(msg="    - modify user")
                        (rc, out, err) = user.modify_user()

                        if rc is None:
                            res.update({
                                "changed": False
                            })

                    if rc is not None and rc != 0:
                        res.update({
                            "failed": True,
                            "msg": err,
                            "rc": rc,
                        })

                    if self.output == "full":
                        if user.password is not None:
                            res['password'] = 'NOT_LOGGING_PASSWORD'

                    if _authorized_keys:
                        auth_keys.user(user, _authorized_keys)
                        authorized_keys_state = auth_keys.save(_authorized_key_directory)

                        res.update({
                            # "changed": authorized_keys_state,
                            "authorized_key": authorized_keys_state
                        })

                    if _ssh_keys:
                        ssh_keys.user(user, _ssh_keys)
                        ssh_keys_state = ssh_keys.save()

                        res.update({
                            # "changed": ssh_keys_state,
                            "ssh_keys": ssh_keys_state
                        })

                    # sudoers file
                    sudoers.user(user, _sudo)

                    sudo_state = None
                    sudo_changed = None
                    sudo_failed = None

                    if _sudo:
                        self.module.log(msg="create sudoers")
                        sudo_state = sudoers.create_sudoers()

                        sudo_changed = sudo_state.get("changed", False)
                        sudo_failed = sudo_state.get("failed", False)

                        res.update({
                            "changed": sudo_changed,
                            "failed": sudo_failed,
                        })
                    else:
                        sudo_state = sudoers.delete_sudoers()

                    if sudo_state:
                        res.update({
                            "sudo": sudo_state
                        })

            result[_username] = res

            self.module.log(msg="-----------------------------------------------------------")

        # self.module.log(msg="-----------------------------------------------------------")
        # self.module.log(msg=f"{result}")
        # self.module.log(msg="-----------------------------------------------------------")

        result_changed = {k: v for k, v in result.items() if v.get('changed')}
        result_failed  = {k: v for k, v in result.items() if v.get('failed')}

        # find all changed and define our variable
        changed = (len(result_changed) > 0)
        # find all failed and define our variable
        failed = (len(result_failed) > 0)

        final_result = dict(
            failed = failed,
            changed = changed
        )

        if changed:
            final_result.update({
                "result_changed": result_changed
            })

        if failed:
            final_result.update({
                "result_failed": result_failed
            })

        if self.output == "full":
            final_result.update({
                "output": result
            })

        return final_result


# ---------------------------------------------------------------------------------------
# Module execution.
#

def main():
    """
    """
    module = AnsibleModule(
        argument_spec=dict(
            users = dict(
                required = True,
                type = "list"
            ),
            output = dict(
                type = 'str',
                default = 'compact',
                choices = ['compact', 'full']
            )
        ),
        supports_check_mode=False,
    )

    u = MultiUsers(module)
    result = u.run()

    module.log(msg=f"= result : '{result}'")

    module.exit_json(**result)


# import module snippets
if __name__ == '__main__':
    main()
