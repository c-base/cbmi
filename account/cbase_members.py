#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Example configuration:

CBASE_LDAP_URL = 'ldap://lea.cbrp3.c-base.org:389/'
CBASE_BASE_DN = 'ou=crew,dc=c-base,dc=org'
"""

import copy
import logging

from django.conf import settings

import ldap

from account.password_encryption import get_ldap_password

LOGGER = logging.getLogger(__name__)


def retrieve_member(request):
    """
    Gets a MemberValues object by its user name bound to a request object.
    :param request:
    :return: A MemberValues object
    """
    ldap_password = get_ldap_password(request)
    request_session = dict(request.session)

    LOGGER.info("session: %s", request_session)
    LOGGER.info("cookies: %s", request.COOKIES)

    return MemberValues(request.user.username, ldap_password)


class MemberValues(object):
    """
    Dictionary-like abstraction of the c-base member attributes.
    """

    def __init__(self, username, password):
        """
        Initializes a MemberValues object with all necessary parameters to
        synchronize with an LDAP server.

        :param username:
        :param password:
        """
        self._username = username
        self._password = password
        self._old = self._get_user_values()

        # Make a complete copy of the old values so we can later check
        # which
        self._new = copy.deepcopy(self._old)

    def get(self, key, default=None):
        """
        Gets a member attribute value by key.
        :param key:
        :param default:
        :return:
        """
        value_list = self._new.get(key, default)
        if value_list:
            value = value_list[0]
        else:
            value = default

        if value is not None:
            value = value.decode()

        # Decode
        if value == 'TRUE':
            return True
        elif value == 'FALSE':
            return False
        else:
            return value

    def set(self, key, value):
        """
        Sets a member attribute value for a key replacing the old value
        :param key:
        :param value:
        :return:
        """
        if value is None:
            self._new[key] = [None]
            return

        converted_value = value
        if isinstance(value, bool):
            if value:
                converted_value = 'TRUE'
            else:
                converted_value = 'FALSE'

        self._new[key] = [converted_value.encode('latin-1')]

    def save(self):
        """
        Save the values back to the LDAP server.
        """
        user_dn = "uid=%s,ou=crew,dc=c-base,dc=org" % self._username

        session = ldap.initialize(settings.CBASE_LDAP_URL)
        session.simple_bind_s(user_dn, self._password)

        mod_attrs = []
        action = None
        for new_key, new_value in self._new.items():
            # Replace is the default.
            action = ldap.MOD_REPLACE
            if new_key not in self._old.keys():
                action = ldap.MOD_ADD
                mod_attrs.append((action, '%s' % new_key, new_value))
                continue
            if self._old.get(new_key, [None])[0] is not None \
                    and new_value == [None]:
                action = ldap.MOD_DELETE
                mod_attrs.append((action, '%s' % new_key, []))
                # Set the attribute and wait for the LDAP server to complete.
                continue
            if self._old.get(new_key, [None])[0] != new_value[0]:
                action = ldap.MOD_REPLACE
                mod_attrs.append((action, '%s' % new_key, new_value))
                continue

        LOGGER.debug("action: %s modattrs: %s", action, mod_attrs)
        result = session.modify_s(user_dn, mod_attrs)
        LOGGER.debug("result is: %s", result)
        session.unbind_s()
        return result  # does not harm any1

    def change_password(self, new_password):
        """
        Change the password of the member.
        You do not need to call save() after calling change_password().
        """
        session = ldap.initialize(settings.CBASE_LDAP_URL)
        user_dn = self._get_bind_dn()
        session.simple_bind_s(user_dn, self._password)
        session.passwd_s(user_dn, self._password, new_password)
        session.unbind_s()

    def to_dict(self):
        """
        Converts a MembersValue object to a dict representation.
        :return:
        """
        result = {}
        for key, _ in self._new.items():
            result[key] = self.get(key)
        return result

    def _get_bind_dn(self, username=None):
        """
        Adds the uid=userid, to the base dn and returns that.
        """
        if not username:
            bind_dn = 'uid=%s,' % self._username
        else:
            bind_dn = 'uid=%s,' % username
        bind_dn += settings.CBASE_BASE_DN
        return bind_dn

    def _get_user_values(self):
        """
        Get an attribute from the ldap storage.
        """
        # Create a new LDAP bind (aka connection or session)
        session = ldap.initialize(settings.CBASE_LDAP_URL)
        session.simple_bind_s(self._get_bind_dn(), self._password)

        # Set the attribute and wait for the LDAP server to complete.
        search_scope = ldap.SCOPE_SUBTREE

        # retrieve all attributes
        retrieve_attributes = None
        search_filter = "uid=%s" % self._username

        base_dn = settings.CBASE_BASE_DN
        result = session.search_s(
            base_dn,
            search_scope,
            search_filter,
            retrieve_attributes
        )

        # TODO: latin1
        LOGGER.info("result is: %s", result)
        # TODO: if len(result)==0
        session.unbind_s()
        return result[0][1]

    def admin_change_password(self, username, new_password):
        """
        Change the password of the member.
        You do not need to call save() after calling change_password().
        """
        session = ldap.initialize(settings.CBASE_LDAP_URL)
        user_dn = self._get_bind_dn()
        session.simple_bind_s(user_dn, self._password)
        session.passwd_s(self._get_bind_dn(username), None, new_password)
        session.unbind_s()

    def get_number_of_members(self):
        """
        Returns the total number of c-base members with active user accounts.
        """
        return len(self.list_users())

    def list_users(self):
        """
        Returns a list of strings with all usernames in the group 'crew'.
        The list is sorted alphabetically.
        """
        session = ldap.initialize(settings.CBASE_LDAP_URL)
        user_dn = self._get_bind_dn()
        session.simple_bind_s(user_dn, self._password)
        try:
            result_id = session.search(
                settings.CBASE_BASE_DN,
                ldap.SCOPE_SUBTREE,
                "memberOf=cn=crew,ou=groups,dc=c-base,dc=org",
                None
            )
            result_set = []
            while True:
                result_type, result_data = session.result(result_id, 0)
                if not result_data:
                    break
                if result_type == ldap.RES_SEARCH_ENTRY:
                    result_set.append(result_data)

            # list comprehension to get a list of user tupels in the
            # format ("nickname", "nickname (real name)")
            userlist = [(
                x[0][1]['uid'][0].decode(),
                '%s (%s, %s)' % (
                    x[0][1]['uid'][0].decode(),
                    x[0][1]['cn'][0].decode(),
                    x[0][1]['uidNumber'][0].decode()
                )
            ) for x in result_set]
            return sorted(userlist)
        except Exception:
            LOGGER.exception('list_users failed')
            return []


def get_ldap_admins():
    session = ldap.initialize(settings.CBASE_LDAP_URL)
    session.search('cn=ldap_admins,ou=groups,dc=c-base,dc=org', ldap.SCOPE_BASE)
    result = session.result()
    return [x.decode().split(',')[0].split('=')[1] for x in result[1][0][1].get('member')]
