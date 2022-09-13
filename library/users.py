#!/usr/bin/env python3

# -*- coding: utf-8 -*-

# (c) 2020, Bodo Schulz <bodo@boone-schulz.de>
# BSD 2-clause (see LICENSE or https://opensource.org/licenses/BSD-2-Clause)

from __future__ import absolute_import, division, print_function

DOCUMENTATION = """
"""

EXAMPLES = """
"""

# ---------------------------------------------------------------------------------------


import calendar
import errno
import grp
import math
import os
import pty
import pwd
import re
import select
import shutil
import socket
import subprocess
import time
import warnings

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule



try:
    import spwd
    HAVE_SPWD = True
except ImportError:
    HAVE_SPWD = False


_HASH_RE = re.compile(r'[^a-zA-Z0-9./=]')


class SingleUser():
    """
    """
    platform = 'Generic'
    distribution = None  # type: str | None
    PASSWORDFILE = '/etc/passwd'
    SHADOWFILE = '/etc/shadow'  # type: str | None
    SHADOWFILE_EXPIRE_INDEX = 7
    LOGIN_DEFS = '/etc/login.defs'
    DATE_FORMAT = '%Y-%m-%d'

    def __init__(self, module):
        """
        """
        self.state = module.get("state")
        self.username = module.get("username")
        self.password = module.get("password")
        self.home = module.get("home")
        self.create_home = module.get("create_home")
        self.comment = module.get("comment")
        self.local   = module.get("local", False)


    def check_password_encrypted(self):
        """
        """
        if self.password:
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
                return "The input password appears not to have been hashed.\nThe 'password' argument must be encrypted for this module to work properly."


    def execute_command(self, cmd, use_unsafe_shell=False, data=None, obey_checkmode=True):
        if self.module.check_mode and obey_checkmode:
            self.module.debug('In check mode, would have run: "%s"' % cmd)
            return (0, '', '')
        else:
            # cast all args to strings ansible-modules-core/issues/4397
            cmd = [str(x) for x in cmd]
            return self.module.run_command(cmd, use_unsafe_shell=use_unsafe_shell, data=data)

    def user_exists(self):
        # The pwd module does not distinguish between local and directory accounts.
        # It's output cannot be used to determine whether or not an account exists locally.
        # It returns True if the account exists locally or in the directory, so instead
        # look in the local PASSWORD file for an existing account.
        if self.local:
            if not os.path.exists(self.PASSWORDFILE):
                return dict(
                    failed = True,
                    msg = f"'local: true' specified but unable to find local account file {self.PASSWORDFILE} to parse."
                )

            exists = False
            name_test = f'{self.username}:'

            with open(self.PASSWORDFILE, 'rb') as f:
                reversed_lines = f.readlines()[::-1]
                for line in reversed_lines:
                    if line.startswith(to_bytes(name_test)):
                        exists = True
                        break

            if not exists:
                msg = "'local: true' specified and user '{name}' was not found in {file}. \
                       The local user account may already exist if the local account database exists \
                       somewhere other than {file}.".format(file=self.PASSWORDFILE, name=self.username)

            return exists

        else:
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
                passwd = spwd.getspnam(self.name)[1]
                expires = spwd.getspnam(self.name)[7]
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
                    if line.startswith('%s:' % self.name):
                        passwd = line.split(':')[1]
                        expires = line.split(':')[self.SHADOWFILE_EXPIRE_INDEX] or -1
        return passwd, expires


    def create_user(self):
        """
        """
        if self.local:
            command_name = 'luseradd'
            lgroupmod_cmd = self.module.get_bin_path('lgroupmod', True)
            lchage_cmd = self.module.get_bin_path('lchage', True)
        else:
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
                self.module.fail_json(msg="Group %s does not exist" % self.group)
            cmd.append('-g')
            cmd.append(self.group)
        elif self.group_exists(self.name):
            # use the -N option (no user group) if a group already
            # exists with the same name as the user to prevent
            # errors from useradd trying to create a group when
            # USERGROUPS_ENAB is set in /etc/login.defs.
            if os.path.exists('/etc/redhat-release'):
                dist = distro.version()
                major_release = int(dist.split('.')[0])
                if major_release <= 5 or self.local:
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
            if not self.local:
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

        if self.expires is not None and not self.local:
            cmd.append('-e')
            if self.expires < time.gmtime(0):
                cmd.append('')
            else:
                cmd.append(time.strftime(self.DATE_FORMAT, self.expires))

        if self.password is not None:
            cmd.append('-p')
            if self.password_lock:
                cmd.append('!%s' % self.password)
            else:
                cmd.append(self.password)

        if self.create_home:
            if not self.local:
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

        cmd.append(self.name)
        (rc, out, err) = self.execute_command(cmd)
        if not self.local or rc != 0:
            return (rc, out, err)

        if self.expires is not None:
            if self.expires < time.gmtime(0):
                lexpires = -1
            else:
                # Convert seconds since Epoch to days since Epoch
                lexpires = int(math.floor(self.module.params['expires'])) // 86400
            (rc, _out, _err) = self.execute_command([lchage_cmd, '-E', to_native(lexpires), self.name])
            out += _out
            err += _err
            if rc != 0:
                return (rc, out, err)

        if self.groups is None or len(self.groups) == 0:
            return (rc, out, err)

        for add_group in groups:
            (rc, _out, _err) = self.execute_command([lgroupmod_cmd, '-M', self.name, add_group])
            out += _out
            err += _err
            if rc != 0:
                return (rc, out, err)
        return (rc, out, err)

    def remove_user(self):
        if self.local:
            command_name = 'luserdel'
        else:
            command_name = 'userdel'

        cmd = [self.module.get_bin_path(command_name, True)]
        if self.force and not self.local:
            cmd.append('-f')
        if self.remove:
            cmd.append('-r')
        cmd.append(self.name)

        return self.execute_command(cmd)

    def modify_user(self):
        """
        """
        if self.local:
            command_name = 'lusermod'
            lgroupmod_cmd = self.module.get_bin_path('lgroupmod', True)
            lgroupmod_add = set()
            lgroupmod_del = set()
            lchage_cmd = self.module.get_bin_path('lchage', True)
            lexpires = None
        else:
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
                self.module.fail_json(msg="Group %s does not exist" % self.group)
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
                if self.local:
                    if self.append:
                        lgroupmod_add = set(groups).difference(current_groups)
                        lgroupmod_del = set()
                    else:
                        lgroupmod_add = set(groups).difference(current_groups)
                        lgroupmod_del = set(current_groups).difference(groups)
                else:
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
                    if self.local:
                        lexpires = -1
                    else:
                        cmd.append('-e')
                        cmd.append('')
            else:
                # Convert days since Epoch to seconds since Epoch as struct_time
                current_expire_date = time.gmtime(current_expires * 86400)

                # Current expires is negative or we compare year, month, and day only
                if current_expires < 0 or current_expire_date[:3] != self.expires[:3]:
                    if self.local:
                        # Convert seconds since Epoch to days since Epoch
                        lexpires = int(math.floor(self.module.params['expires'])) // 86400
                    else:
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
                cmd.append('!%s' % self.password)
            else:
                cmd.append(self.password)

        (rc, out, err) = (None, '', '')

        # skip if no usermod changes to be made
        if len(cmd) > 1:
            cmd.append(self.name)
            (rc, out, err) = self.execute_command(cmd)

        if not self.local or not (rc is None or rc == 0):
            return (rc, out, err)

        if lexpires is not None:
            (rc, _out, _err) = self.execute_command([lchage_cmd, '-E', to_native(lexpires), self.name])
            out += _out
            err += _err
            if rc != 0:
                return (rc, out, err)

        if len(lgroupmod_add) == 0 and len(lgroupmod_del) == 0:
            return (rc, out, err)

        for add_group in lgroupmod_add:
            (rc, _out, _err) = self.execute_command([lgroupmod_cmd, '-M', self.name, add_group])
            out += _out
            err += _err
            if rc != 0:
                return (rc, out, err)

        for del_group in lgroupmod_del:
            (rc, _out, _err) = self.execute_command([lgroupmod_cmd, '-m', self.name, del_group])
            out += _out
            err += _err
            if rc != 0:
                return (rc, out, err)
        return (rc, out, err)


class Users():
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

        # self.state = module.params.get("state")
        # self.username = module.params.get("username")
        # self.password = module.params.get("password")
        # self.home = module.params.get("home")
        # self.create_home = module.params.get("create_home")
        # self.comment = module.params.get("comment")




    def run(self):
        """
        """
        for u in self.users:

            _state = u.get("user_state")
            _home = u.get("home")

            m = dict(
                state = _state,
                username = u.get("username"),
                password = u.get("password"),
                home = _home,
                comment = u.get("comment"),
            )

            user = SingleUser(m)
            user.check_password_encrypted()

            if _state == 'absent':
                """
                """
                if user.user_exists():
                    if module.check_mode:
                        module.exit_json(changed=True)
                    (rc, out, err) = user.remove_user()

                    if rc != 0:
                        module.fail_json(name=user.name, msg=err, rc=rc)

                    result['force'] = user.force
                    result['remove'] = user.remove

            elif _state == 'present':
                """
                """
                if not user.user_exists():
                    """
                    """
                    if module.check_mode:
                        module.exit_json(changed=True)

                    # Check to see if the provided home path contains parent directories
                    # that do not exist.
                    path_needs_parents = False
                    if user.home and user.create_home:
                        parent = os.path.dirname(user.home)
                        if not os.path.isdir(parent):
                            path_needs_parents = True

                    (rc, out, err) = user.create_user()

                    # If the home path had parent directories that needed to be created,
                    # make sure file permissions are correct in the created home directory.
                    if path_needs_parents:
                        info = user.user_info()

                        if info is not False:
                            user.chown_homedir(info[2], info[3], user.home)

                    if module.check_mode:
                        result['system'] = user.name
                    else:
                        result['system'] = user.system
                        result['create_home'] = user.create_home
                else:
                    # modify user (note: this function is check mode aware)
                    (rc, out, err) = user.modify_user()
                    result['append'] = user.append
                    result['move_home'] = user.move_home

                if rc is not None and rc != 0:
                    module.fail_json(name=user.name, msg=err, rc=rc)

                if user.password is not None:
                    result['password'] = 'NOT_LOGGING_PASSWORD'


        return dict(
          failed = True,
          msg = "development .."
        )





# ---------------------------------------------------------------------------------------
# Module execution.
#

def main():
    ''' ... '''
    module = AnsibleModule(
        argument_spec=dict(
            users = dict(
                required = True,
                type = "list"
            )

            # state = dict(
            #     required=True,
            #     choices= ["absent", "present"],
            #     default = "present",
            # ),
            # username = dict(
            #     required=False,
            #     type='str'
            # ),
            # password = dict(
            #     required=False,
            #     no_log=True,
            #     type='str'
            # ),
            # home = dict(
            #     required=False,
            #     type='str'
            # ),
            # create_home = dict(
            #     required=False,
            #     type='bool'
            # ),
            # comment = dict(
            #     required=False,
            #     type='str'
            # ),
            # groups = dict(
            #     required=False,
            #     type='list'
            # ),
            # update_password = dict(
            #     required=False,
            #     type='bool'
            # ),
            # uid = dict(
            #     required=False,
            #     type='str'
            # ),
            # shell = dict(
            #     required=False,
            #     type='str'
            # ),
            # ssh_keys = dict(
            #     required=False,
            #     type='list'
            # ),
            # ssh_keys_directory = dict(
            #     required=False,
            #     type='path'
            # ),
            # ssh_private_key = dict(
            #     required=False,
            #     type='str'
            # ),
        ),
        supports_check_mode=False,
    )

    u = Users(module)
    result = u.run()

    module.log(msg=f"= result : '{result}'")

    module.exit_json(**result)


# import module snippets
if __name__ == '__main__':
    main()
