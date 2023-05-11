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
            'user_state': self.user_state,
            'validate_state': self.validate_state
        }

    def add_primary(self, users, groups):
        """
        """
        groups = groups['results']

        for u in users:
            username = u.get('username')
            user_state = u.get('state')
            display.v(f"  - user : {username} / {user_state}")

            if user_state == 'absent':
                continue

            for g in groups:
                try:
                    primary_group = g.get('ansible_facts').get('getent_group').get(username)
                    if primary_group:
                        display.v(f"  - g : {primary_group[1]}")
                        u['primary_group'] = primary_group[1]
                except Exception:
                    pass

        display.v(f"return {users}")

        return users

    def user_state(self, users, state="absent"):
        """
        """
        result = []

        for u in users:
            if u.get('state', "absent") == state:
                result.append(u)

        return result

    def validate_state(self, data):
        """
        """
        result = []

        for u in data:
            display.v(f"{u}")

            username = u.get("username", None)
            user_state = u.get("state", None)

            display.v(f"  - user : {username} / {user_state}")

            if user_state not in ["present", "absent", "lock"]:
                result.append(username)

        return result
