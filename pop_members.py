#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""Synchronize all members from LDAP and populate the database

This script fetches all active members from the LDAP database and populates the
Django database with all discovered members, and groups.

https://github.com/c-base/cbmi/issues/22

Usage:
    # python manage.py shell
    from pop_members import *
    populate_members()
"""

import ldap
from django_auth_ldap.backend import LDAPBackend
from cbmi import settings

# some config vars
ldap_server = settings.AUTH_LDAP_SERVER_URI
ldap_baseDN = 'ou=crew,dc=c-base,dc=org'
ldap_search_scope = ldap.SCOPE_SUBTREE
ldap_retrieve_attrs = None
ldap_search_filter = 'memberOf=cn=crew,ou=groups,dc=c-base,dc=org'

def connect():
    """connect to ldap server and return connection object"""
    l = ldap.initialize(ldap_server)
    l.protocol_version = ldap.VERSION3
    return l

def query_members(l):
    """query for all members and return the raw result data-structure"""
    ldap_result_id = l.search(ldap_baseDN, ldap_search_scope, ldap_search_filter, ldap_retrieve_attrs)
    result_set = []
    while 1:
        result_type, result_data = l.result(ldap_result_id, 0)
        if result_data == []:
            break
        else:
            result_set.append(result_data)
    return result_set

def all_members():
    """fetch result data-structure and return striped uid's"""
    connection = connect()
    results = query_members(connection)
    members = set()
    for r in results:
        uid = r[0][1]['uid'][0]
        members.add(uid)
    return members

def populate_members():
    """fetch all members, sort them and populate the Django database"""
    for m in sorted(all_members()):
        member = LDAPBackend().populate_user(m.decode())
        if member:
            print('Populated: %s' % member)
        else:
            print('Not found: %s' % m)
