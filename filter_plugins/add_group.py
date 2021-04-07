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
        }

    def add_primary(self, users, groups):
        # display.vv("users : ({}) - {}".format(type(users), users))
        # display.vv("groups: ({}) - {}".format(type(groups), groups))

        groups = groups['results']

        # users_count = len(users)
        # groups_count = len(groups)

        # display.vv("found: {} entries in {}".format(users_count, users))
        # display.vv("found: {} entries in {}".format(groups_count, groups))

        for u in users:
            username = u.get('username')
            # display.vv("  - user : {}".format(username))
            for g in groups:
                primary_group = g.get('ansible_facts').get('getent_group').get(username)
                if(primary_group):
                    # display.vv("  - g : {}".format(primary_group[1]))
                    u['primary_group'] = primary_group[1]

        display.vv("return {}".format(users))

        return users
