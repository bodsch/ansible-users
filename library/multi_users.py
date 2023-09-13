#!/usr/bin/env python3

# -*- coding: utf-8 -*-

# (c) 2022, Bodo Schulz <bodo@boone-schulz.de>
# BSD 2-clause (see LICENSE or https://opensource.org/licenses/BSD-2-Clause)

from __future__ import absolute_import, division, print_function
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible.module_utils import distro

import json
import hashlib
import time
import shutil
import re
import pwd
import os
# import math
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


# _HASH_RE = re.compile(r'[^a-zA-Z0-9./=]')


class SingleUser():
    """
    """

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
        self.password_lock = user.get("password_lock", True)
        self.password_expire_max = user.get('password_expire_max', None)
        self.password_expire_min = user.get('password_expire_min', None)
        self.remove = user.get("remove", False)
        self.seuser = user.get("seuser", None)
        self.shell = user.get("shell", None)
        self.skeleton = user.get("skeleton", None)
        self.state = user.get("state")
        self.system = user.get("system", False)
        self.uid = user.get("uid", None)
        self.non_unique = user.get("non_unique", None)
        self.umask = user.get("umask", None)
        self.update_password = user.get("update_password", 'always')
        self.username = user.get("username")

        self.__shadow_file = '/etc/shadow'
        self.__login_defs = '/etc/login.defs'
        self.__date_format = '%Y-%m-%d'

    def check_password_encrypted(self):
        """
        """
        # self.module.log(msg=f"check_password_encrypted()")
        msg = None
        maybe_invalid = True
        is_invalid = True
        invalid_msg = None

        if not self.password:
            return (False, "no password given.")

        else:
            maybe_invalid = False

            # Allow setting certain passwords in order to disable the account
            if self.password in set(['*', '!', '*************']):
                maybe_invalid = False
                is_invalid = False
            else:
                # : for delimiter, * for disable user, ! for lock user
                # these characters are invalid in the password
                if any(char in self.password for char in ':*!'):
                    maybe_invalid = True

                if '$' not in self.password:
                    maybe_invalid = True

                else:
                    """
                       format: '$id$salt$hashed'
                        $1$  is MD5
                        $2a$ is Blowfish
                        $2y$ is Blowfish
                        $5$  is SHA-256
                        $6$  is SHA-512
                    """
                    _, algorithm, salt, pwd_hash = self.password.split("$")

                    if algorithm and salt and pwd_hash:
                        """
                            invalid aka broken algorithm are 'MD5' and will be not supported
                        """
                        if algorithm == '1':
                            is_invalid = True
                            invalid_msg = "The password entered seems to have been hashed, but with the outdated MD5 algorithm!\n"
                            invalid_msg += "This algorithm is no longer supported!\n"
                            invalid_msg += "Please create a new password with a modern hash algorithm (SHA-256, SHA-512, Blowfish)."
                        else:
                            is_invalid = False

                            # sha256
                            if algorithm == '5' and len(pwd_hash) != 43:
                                maybe_invalid = True

                            # sha512
                            if algorithm == '6' and len(pwd_hash) != 86:
                                maybe_invalid = True

                            _hash_re = re.compile(r'[^a-zA-Z0-9./=]')
                            # contains character outside the crypto constraint
                            if bool(_hash_re.search(pwd_hash)):
                                maybe_invalid = True

                    else:
                        maybe_invalid = True

            if maybe_invalid:
                msg = "The input password appears not to have been hashed.\nThe 'password' argument must be encrypted for this module to work properly."

            if is_invalid:
                maybe_invalid = True
                msg = invalid_msg

        # self.module.log(msg=f" = invalid: {maybe_invalid} , '{msg}'")

        return (maybe_invalid, msg)

    def __exec(self, commands, check_rc=False, obey_checkmode=True):
        """
          execute shell program
        """
        if self.module.check_mode and obey_checkmode:
            self.module.debug(f"In check mode, would have run: '{commands}'")
            return 0, 'check mode', ''

        rc, out, err = self.module.run_command(commands, check_rc=check_rc)

        if rc != 0:
            self.module.log("------------------------------------------")
            self.module.log(msg=f"  rc : '{rc}'")
            self.module.log(msg=f"  out: '{out}'")
            self.module.log(msg=f"  err: '{err}'")
            self.module.log("------------------------------------------")
        return rc, out, err

    def user_exists(self):
        """
            check if user exists
        """
        try:
            if pwd.getpwnam(self.username):
                return True
        except KeyError:
            return False

    def get_pwd_info(self):
        """
            return all user information as list
            or False if username not exists
        """
        if not self.user_exists():
            return False

        """
            0   pw_name     Login name
            1   pw_passwd   Optional encrypted password
            2   pw_uid      Numerical user ID
            3   pw_gid      Numerical group ID
            4   pw_gecos    User name or comment field
            5   pw_dir      User home directory
            6   pw_shell    User command interpreter
        """
        return list(pwd.getpwnam(self.username))

    def user_info(self):
        """
        """
        if not self.user_exists():
            return False

        info = self.get_pwd_info()

        if len(info[1]) == 1 or len(info[1]) == 0:
            """
                update password field with the user password
            """
            info[1] = self.user_password()[0]

        return info

    def user_password(self):
        """
        """
        passwd = ''
        expires = ''

        if not self.user_exists():
            return passwd, expires

        if HAVE_SPWD:
            try:
                """
                    0   sp_namp     Login name
                    1   sp_pwdp     Encrypted password
                    2   sp_lstchg   Date of last change
                    3   sp_min      Minimal number of days between changes
                    4   sp_max      Maximum number of days between changes
                    5   sp_warn     Number of days before password expires to warn user about it
                    6   sp_inact    Number of days after password expires until account is disabled
                    7   sp_expire   Number of days since 1970-01-01 when account expires
                    8   sp_flag     Reserved
                """
                shadow_info = spwd.getspnam(self.username)
                passwd = shadow_info.sp_pwdp
                expires = shadow_info.sp_expire

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

        else:
            passwd, expires = self.parse_shadow_file()

        return passwd, expires

    def parse_shadow_file(self):
        """
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
        passwd = ''
        expires = ''

        if os.path.exists(self.__shadow_file) and os.access(self.__shadow_file, os.R_OK):

            with open(self.__shadow_file, 'r') as f:
                for line in f:
                    if line.startswith(f"{self.username}:"):
                        shadow_info = line.split(':')
                        passwd = shadow_info[1]
                        expires = shadow_info[7] or -1

        return passwd, expires

    def create_user(self):
        """
        """
        useradd_bin = self.module.get_bin_path('useradd', True)

        args = []
        args.append(useradd_bin)

        if self.uid is not None:
            args.append('-u')
            args.append(str(self.uid))

            if self.non_unique:
                args.append('-o')

        if self.seuser is not None:
            args.append('-Z')
            args.append(self.seuser)

        if self.group is not None:
            if not self.group_exists(self.group):
                msg = f"Group {self.group} does not exist"
                return (1, "", msg)

            args.append('-g')
            args.append(self.group)

        elif self.group_exists(self.username):
            # use the -N option (no user group) if a group already
            # exists with the same name as the user to prevent
            # errors from useradd trying to create a group when
            # USERGROUPS_ENAB is set in /etc/login.defs.
            if os.path.exists('/etc/redhat-release'):
                dist = distro.version()
                major_release = int(dist.split('.')[0])
                if major_release <= 5:
                    args.append('-n')
                else:
                    args.append('-N')

            elif os.path.exists('/etc/SuSE-release'):
                # -N did not exist in useradd before SLE 11 and did not
                # automatically create a group
                dist = distro.version()
                major_release = int(dist.split('.')[0])
                if major_release >= 12:
                    args.append('-N')
            else:
                args.append('-N')

        if self.groups is not None and len(self.groups):
            groups = self.get_groups_set()

            args.append('-G')
            args.append(','.join(groups))

        if self.comment is not None:
            args.append('-c')
            args.append(self.comment)

        if self.home:
            # self.module.log(msg=f"    - home")
            # If the specified path to the user home contains parent directories that
            # do not exist and create_home is True first create the parent directory
            # since useradd cannot create it.

            if self.create_home:
                """
                """
                # self.module.log(msg=f"    - create_home")

                parent = os.path.dirname(self.home)
                # self.module.log(msg=f"      parent {parent}")
                if not os.path.isdir(parent):
                    self.create_homedir(self.home)

            args.append('-d')
            args.append(self.home)

        if self.shell:
            args.append('-s')
            args.append(self.shell)

        if self.expires:
            args.append('-e')
            if self.expires < time.gmtime(0):
                args.append('')
            else:
                args.append(time.strftime(self.__date_format, self.expires))

        if self.password:
            _password = self.password
            args.append('-p')
            if self.password_lock:
                _password = f"!{self.password}"
            args.append(_password)

        if self.create_home:
            args.append('-m')

            if self.skeleton:
                args.append('-k')
                args.append(self.skeleton)

            if self.umask:
                args.append('-K')
                args.append('UMASK=' + self.umask)
        else:
            args.append('-M')

        if self.system:
            args.append('-r')

        args.append(self.username)

        self.module.log(msg=f" - args {args}")

        (rc, out, err) = self.__exec(args)

        if rc != 0:
            return (rc, out, err)

        if self.groups is None or len(self.groups) == 0:
            return (rc, out, err)

        return (rc, out, err)

    def remove_user(self):
        """
        """
        userdel_bin = self.module.get_bin_path('userdel', True)

        args = []
        args.append(userdel_bin)

        if self.force:
            args.append('-f')

        if self.remove:
            args.append('-r')

        args.append(self.username)

        self.module.log(msg=f" - args {args}")

        return self.__exec(args)

    def modify_user(self):
        """
        """
        # self.module.log(msg=f"modify_user()")

        """
            0   pw_name     Login name
            1   pw_passwd   Optional encrypted password
            2   pw_uid      Numerical user ID
            3   pw_gid      Numerical group ID
            4   pw_gecos    User name or comment field
            5   pw_dir      User home directory
            6   pw_shell    User command interpreter
        """
        user_name, user_pass, user_uid, user_gid, user_comment, user_home, user_shell = self.user_info()
        has_append = self.__usermod_has_append()

        result_msg = []

        # self.module.log(msg=f"user_name  {user_name}")
        # self.module.log(msg=f"has_append {has_append}")

        usermod_bin = self.module.get_bin_path('usermod', True)

        args = []
        args.append(usermod_bin)

        if self.uid and user_uid != int(self.uid):
            args.append('-u')
            args.append(self.uid)

            result_msg.append("change uid.")

            if self.non_unique:
                args.append('-o')

        if self.group:
            if not self.group_exists(self.group):
                msg = f"Group {self.group} does not exist"
                return (1, "", msg)

            """
                0   gr_name     the name of the group
                1   gr_passwd   the (encrypted) group password; often empty
                2   gr_gid      the numerical group ID
                3   gr_mem      all the group member’s user names
            """
            group_name, group_password, group_gid, group_members = self.group_info(self.group)
            if user_gid != group_gid:
                args.append('-g')
                args.append(self.group)
                result_msg.append("change primary group.")

        if isinstance(self.groups, str):
            # get a list of all groups for the user, including the primary
            current_groups = self.user_group_membership(exclude_primary=True)
            groups_need_mod = False
            groups = []

            # self.module.log(msg=f"current_groups : '{current_groups}'")
            # self.module.log(msg=f"self.groups    : '{self.groups}'")

            if len(self.groups) == 0:
                if current_groups and not self.append:
                    groups_need_mod = True
            else:
                groups = self.get_groups_set(remove_existing=False)
                group_diff = set(current_groups).symmetric_difference(groups)

                # self.module.log(msg=f"groups     : '{groups}'")
                # self.module.log(msg=f"group_diff : '{group_diff}'")

                if group_diff:
                    if self.append:
                        for g in groups:
                            if g in group_diff:
                                if has_append:
                                    args.append('-a')
                                groups_need_mod = True
                                break
                    else:
                        groups_need_mod = True

            # self.module.log(msg=f"groups_need_mod : '{groups_need_mod}'")

            if groups_need_mod:
                if self.append and not has_append:
                    args.append('-A')
                    args.append(','.join(group_diff))
                else:
                    args.append('-G')
                    args.append(','.join(groups))

                result_msg.append("change supplementary groups.")

        if self.comment and user_comment != self.comment:
            args.append('-c')
            args.append(self.comment)

            result_msg.append("change user comment.")

        if self.home and user_home != self.home:
            args.append('-d')
            args.append(self.home)
            result_msg.append("change user home.")

            if self.move_home:
                """
                """
                parent = os.path.dirname(self.home)
                if not os.path.isdir(parent):
                    self.create_homedir(parent)

                args.append('-m')
                result_msg.append("move user home.")

        if self.shell and user_shell != self.shell:
            args.append('-s')
            args.append(self.shell)
            result_msg.append("change login shell.")

        if self.expires:
            """
            """
            current_expires = int(self.user_password()[1])

            if self.expires < time.gmtime(0):
                if current_expires >= 0:
                    args.append('-e')
                    args.append('')
            else:
                # Convert days since Epoch to seconds since Epoch as struct_time
                current_expire_date = time.gmtime(current_expires * 86400)

                # Current expires is negative or we compare year, month, and day only
                if current_expires < 0 or current_expire_date[:3] != self.expires[:3]:
                    expiration_date = time.strftime(self.__date_format, self.expires)
                    args.append('-e')
                    args.append(expiration_date)

                    result_msg.append(f"change account expiration date to {expiration_date}.")

        # Lock if no password or unlocked, unlock only if locked
        if self.password_lock and not user_pass.startswith('!'):
            args.append('-L')
            result_msg.append("lock the user account")

        elif not self.password_lock and user_pass.startswith('!'):
            # usermod will refuse to unlock a user with no password, module shows 'changed' regardless
            args.append('-U')
            result_msg.append("unlock the user account")

        if self.update_password == 'always' and self.password and user_pass.lstrip('!') != self.password.lstrip('!'):
            # Remove options that are mutually exclusive with -p
            args = [c for c in args if c not in ['-U', '-L']]
            args.append('-p')
            password = self.password

            if self.password_lock:
                # Lock the account and set the hash in a single command
                password = f"!{self.password}"

            args.append(password)
            result_msg.append("change password.")

        (rc, out, err) = (None, '', '')

        # skip if no usermod changes to be made
        if len(args) > 1:
            args.append(self.username)

            self.module.log(msg=f" - args {args}")

            (rc, out, err) = self.__exec(args)

        if not (rc is None or rc == 0):
            """
                ERROR
            """
            return (rc, out, err)

        if len(out) == 0:
            out = "\n".join(result_msg)
        else:
            out = None

        return (rc, out, err)

    def group_exists(self, group):
        """
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

    def __usermod_has_append(self):
        """
            check if this version of usermod can append groups
        """
        result = False

        usermod_bin = self.module.get_bin_path('usermod', True)

        args = []
        args.append(usermod_bin)

        # for some reason, usermod --help cannot be used by non root
        # on RH/Fedora, due to lack of execute bit for others
        if not os.access(usermod_bin, os.X_OK):
            return result

        args.append("--help")

        (rc, data1, data2) = self.__exec(args, obey_checkmode=False)
        helpout = data1 + data2

        pattern = re.compile(r'.*(-a, --append).*', re.MULTILINE)
        _match = re.search(pattern, helpout)

        if _match:
            result = True

        return result

    def group_info(self, group):
        """
        """
        if not self.group_exists(group):
            return False

        try:
            # Try group as a gid first
            return list(grp.getgrgid(int(group)))
        except (ValueError, KeyError):
            """
                0   gr_name     the name of the group
                1   gr_passwd   the (encrypted) group password; often empty
                2   gr_gid      the numerical group ID
                3   gr_mem      all the group member’s user names
            """
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
        """
            Return a list of groups the user belongs to
        """
        user_name, _, uid, gid, _, _, _ = self.get_pwd_info()

        all_groups = grp.getgrall()
        user_groups = [g.gr_name for g in all_groups if self.username in g.gr_mem]
        user_primary_group = [g.gr_name for g in all_groups if gid == g.gr_gid]

        if not exclude_primary:
            user_groups += user_primary_group

        return user_groups

    def create_homedir(self, path):
        """
        """
        # self.module.log(msg=f"create_homedir({path})")
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

            content = []

            pattern = re.compile(r'^UMASK\s+(\d+)$', re.MULTILINE)

            # get umask from /etc/login.defs and set correct home mode
            if os.path.exists(self.__login_defs):

                with open(self.__login_defs, 'r') as f:
                    content = f.readlines()

                _list = list(filter(pattern.match, content))[0]
                result = re.search(pattern, _list)

                if result:
                    umask = int(result.group(1), 8)
                    mode = 0o777 & ~umask

                    try:
                        os.chmod(path, mode)
                    except OSError as e:
                        self.module.exit_json(failed=True, msg=f"{to_native(e)}")

    def chown_homedir(self, uid, gid, path, mode=None):
        """
        """
        self.module.log(msg=f"chown_homedir({uid}, {gid}, {path}, {mode})")

        if mode:
            os.chmod(path, int(mode, base=8))

        try:
            os.chown(path, uid, gid)

            # TODO
            # chmod 0750 for $HOME

            for root, dirs, files in os.walk(path):
                for d in dirs:
                    os.chown(os.path.join(root, d), uid, gid)
                for f in files:
                    os.chown(os.path.join(root, f), uid, gid)

        except OSError as e:
            self.module.exit_json(failed=True, msg=f"{to_native(e)}")

    def set_password_expire(self):
        """
        """
        min_needs_change = self.password_expire_min is not None
        max_needs_change = self.password_expire_max is not None

        if HAVE_SPWD:
            try:
                shadow_info = spwd.getspnam(self.name)
            except KeyError:
                return (None, '', '')
            except OSError as e:
                # Python 3.6 raises PermissionError instead of KeyError
                # Due to absence of PermissionError in python2.7 need to check
                # errno
                if e.errno in (errno.EACCES, errno.EPERM, errno.ENOENT):
                    return (None, '', '')
                raise

            min_needs_change &= self.password_expire_min != shadow_info.sp_min
            max_needs_change &= self.password_expire_max != shadow_info.sp_max

        if not (min_needs_change or max_needs_change):
            return (None, '', '')  # target state already reached

        chage_bin = self.module.get_bin_path('chage', True)
        args = []
        args.append(chage_bin)

        if min_needs_change:
            args.append("-m")
            args.append(self.password_expire_min)

        if max_needs_change:
            args.append("-M")
            args.append(self.password_expire_max)

        args.append(self.name)

        self.module.log(msg=f" - args {args}")

        (rc, out, err) = self.__exec(args)

        return (rc, out, err)


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

    def create_directory(self, path, uid=None, gid=None, mode="0700"):
        """
        """
        self.module.log(msg=f"create_directory(self, {path}, {uid} {gid}, {mode})")

        try:
            os.makedirs(path, exist_ok=True)
        except FileExistsError:
            pass

        if uid and gid:
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

    def save_file(self, file_name, data, uid=None, gid=None, mode="0600"):
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

        if uid and gid:
            self.set_rights(file_name, uid, gid, mode)

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
        self.module.log(msg=f"set_rights(self, {path}, {owner} {group}, {mode})")

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
        self.module.log(msg=f"save(self, {path})")

        self.user_info()

        if self.authorized_keys and len(self.authorized_keys) > 0:
            """
            """
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

            self.module.log(msg=f"    - key file: {_authorized_key_file}")

            self.create_directory(path, uid=_uid, gid=_gid, mode=_authorized_key_directory_mode)

            if not self.verify_files(_authorized_key_file, self.authorized_keys):
                # changed keys
                self.save_file(file_name=_authorized_key_file, data=self.authorized_keys, uid=_uid, gid=_gid, mode="0600")

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

        self.create_directory(path, mode="0700")

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

        # self.user_info()

        # self.user = self.user_name
        self.nopassword = sudo_data.get('nopassword', False)
        self.runas = sudo_data.get('runas', None)
        self.group = sudo_data.get('group', None)
        self.sudoers_path = sudo_data.get('sudoers_path', '/etc/sudoers.d')
        # self.file_name = os.path.join(self.sudoers_path, self.user_name)
        self.commands = sudo_data.get('commands', [])

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

        if self.nopassword:
            """
            """
            if isinstance(self.commands, str):
                commands = [self.commands]
            else:
                commands = self.commands

            self.commands = commands

            # self.module.log(msg=f"  sudoers file {self.file_name}")
            # self.module.log(msg=f"  sudoers data {self.sudo_data} {len(self.sudo_data)}")

            if len(self.sudo_data) == 0:
                return dict(
                    changed = False,
                    failed = False
                )

            content = self.content()

            self.module.log(msg=f"  content {content}")

            if not self.verify_files(self.file_name, content):
                # changed keys
                self.save_file(file_name=self.file_name, data=content, mode="0440")

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
        else:
            return self.delete_sudoers()

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
        else:
            return dict(
                changed = False,
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
            msg = f"Failed to validate sudoers rule:\n{stdout}\n{stderr}"  # '.format(stdout=stdout))
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
            # self.module.log(msg="-----------------------------------------------------------")
            # self.module.log(msg=f"  - {u}")
            res = {}

            _username = u.get("username")
            _state = u.get("state")
            _home = u.get("home", os.path.join("/home", _username))

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
                move_home = u.get("move_home", False),
                password = u.get("password"),
                # password_expire_max = u.get("password_expire_max"),
                # password_expire_min = u.get("password_expire_min"),
                password_lock = u.get("password_lock", True),
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
                                user.chown_homedir(info[2], info[3], user.home, "0750")

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
                        else:
                            res.update({
                                "changed": True
                            })

                            if out:
                                res.update({
                                    "msg": out
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
                        # self.module.log(msg="create sudoers")
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

            # self.module.log(msg="-----------------------------------------------------------")

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
