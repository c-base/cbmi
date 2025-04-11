"""
This file demonstrates writing tests using the unittest module. These will pass
when you run "manage.py test".

Replace this with more appropriate tests for your application.
"""
import base64
import pytest

from django.test import TestCase
from account.password_encryption import encrypt_ldap_password, \
    decrypt_ldap_password


class PasswordEncryptionTest(TestCase):
    """
    Test for the cbmi apps.
    """
    TEST_LDAP_PASSWD = 'correcthorsebatterystaple'

    def encrypt_it(self):
        return encrypt_ldap_password(self.TEST_LDAP_PASSWD)

    def test_encrypt_ldap_password(self):
        message, key = self.encrypt_it()
        print('key:', key)
        print('message:', message)

    def test_decrypt_ldap_password(self):
        message, key = self.encrypt_it()
        decrypted = decrypt_ldap_password(message, key)
        self.assertEqual(self.TEST_LDAP_PASSWD, decrypted)

@pytest.mark.parametrize("password", [
    "simplePassword123",
    "pässwörd_mit_üöäß",
    "",
    " " * 10,
    "🔐✨🚀",
])
def test_encrypt_decrypt_roundtrip(password):
    encrypted, key = encrypt_ldap_password(password)

    encrypted_bytes = base64.b64decode(encrypted)
    key_bytes = base64.b64decode(key)

    assert isinstance(encrypted, str)
    assert isinstance(key, str)
    assert len(key_bytes) == 16  # 128-bit AES

    decrypted = decrypt_ldap_password(encrypted, key)
    assert decrypted == password


def test_decryption_with_wrong_key_should_fail():
    password = "correctPassword"
    encrypted, key = encrypt_ldap_password(password)

    wrong_key_bytes = base64.b64decode(key)
    wrong_key_bytes = bytearray(wrong_key_bytes)
    wrong_key_bytes[0] ^= 0xFF  # Flip first bit
    wrong_key = base64.b64encode(bytes(wrong_key_bytes)).decode()

    with pytest.raises(Exception):
        decrypt_ldap_password(encrypted, wrong_key)

