# -*- coding: utf-8 -*-

# (c) 2022, Bodo Schulz <bodo@boone-schulz.de>
# BSD 2-clause (see LICENSE or https://opensource.org/licenses/BSD-2-Clause)

"""
    Jinja2 filters used by the ``ansible-users`` role.

    Both filters operate on the ``users`` list - a list of user definition
    dictionaries, each carrying at least a ``username`` and a ``state`` key:

    - ``validate_state`` returns the usernames whose ``state`` is missing or
      invalid, so the role can fail early with a helpful message.
    - ``user_state`` returns only the users matching a given ``state``.

    Example (see ``tasks/prepare.yaml``)::

        non_valid_users: "{{ users | validate_state }}"
        absent_users:    "{{ users | user_state(state='absent') }}"
"""

from __future__ import annotations

from ansible.utils.display import Display

display = Display()

# The account states understood by the multi_users module.
VALID_STATES = ("present", "absent", "lock")


class FilterModule:
    """
        Jinja2 filters for the ansible-users role.
    """

    def filters(self) -> dict[str, object]:
        """
            Return the mapping of filter names to their implementation.
        """
        return {
            "user_state": self.user_state,
            "validate_state": self.validate_state,
        }

    def user_state(self, users: list[dict[str, object]], state: str = "absent") -> list[dict[str, object]]:
        """
            Return all user definitions whose ``state`` matches ``state``.

            Users without an explicit ``state`` are treated as ``absent``.

            :param users: the list of user definition dictionaries.
            :param state: the account state to filter for (default ``absent``).
            :returns: the subset of ``users`` whose state equals ``state``.
        """
        return [u for u in users if u.get("state", "absent") == state]

    def validate_state(self, users: list[dict[str, object]]) -> list[str]:
        """
            Return the names of all users with a missing or invalid ``state``.

            A valid state is one of ``present``, ``absent`` or ``lock``. The
            returned list is empty when every user is valid; the role uses it
            to assert a correct configuration before creating any account.

            :param users: the list of user definition dictionaries.
            :returns: the usernames whose ``state`` is not valid.
        """
        invalid: list[str] = []

        for u in users:
            username = str(u.get("username", ""))
            user_state = u.get("state")

            display.vvv(f"  - user : {username} / {user_state}")

            if user_state not in VALID_STATES:
                invalid.append(username)

        return invalid
