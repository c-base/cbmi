"""
This file demonstrates writing tests using the unittest module. These will pass
when you run "manage.py test".

Replace this with more appropriate tests for your application.
"""

from django.test import TestCase
from account.views import encrypt_ldap_password, decrypt_ldap_password

class CbmiTest(TestCase):
    """
    Test for the cbmi apps.
    """
    TEST_LDAP_PASSWD = 'correcthorsebatterystaple'

    def encrypt_it(self):
        return encrypt_ldap_password(self.TEST_LDAP_PASSWD)

    def test_encrypt_ldap_password(self):
        message, key = self.encrypt_it()
        print 'key:', key
        print 'message:', message


    def test_decrypt_ldap_password(self):
        message, key = self.encrypt_it()
        decrypted = decrypt_ldap_password(message, key)
        self.assertEqual(self.TEST_LDAP_PASSWD, decrypted)