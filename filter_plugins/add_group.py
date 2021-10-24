# python 3 headers, required if submitting to Ansible
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.utils.display import Display

display = Display()


class FilterModule(object):
    """
        Ansible file jinja2 tests
    """
    def filters(self):
        return {
            'add_primary_group': self.add_primary,
            'user_state': self.user_state
        }

    def add_primary(self, users, groups):
        groups = groups['results']

        for u in users:
            username = u.get('username')
            user_state = u.get('user_state')

            display.vv("  - user : {0} / {1}".format(username, user_state))

            if(user_state == 'absent'):
                continue

            for g in groups:
                try:
                    primary_group = g.get('ansible_facts').get('getent_group').get(username)
                    if(primary_group):
                        display.vv("  - g : {0}".format(primary_group[1]))
                        u['primary_group'] = primary_group[1]
                except Exception:
                    pass

        display.vvv("return {0}".format(users))

        return users

    def user_state(self, users, state="absent"):
        """

        """
        result = []

        for u in users:
            if(u.get('user_state', "absent") == 'absent'):
                result.append(u)

        return result
