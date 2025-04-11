#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

ENCRYPTED_LDAP_PASSWORD = 'encrypted_ldap_password'


def encrypt_ldap_password(cleartext_pw):
    """
    Encrypts the cleartext_pw with a randomly generated key.

    Returns the key and the encrypted message containing the password.
    The key is supposed to be stored into the 'session_key' cookie field we can
    later use it to decrypt the password and connect to the LDAP server with it.
    """
    key = os.urandom(16)  # 128-bit AES key
    iv = os.urandom(16)   # 128-bit IV

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(cleartext_pw.encode()) + encryptor.finalize()

    message = iv + ciphertext
    return base64.b64encode(message).decode(), base64.b64encode(key).decode()


def decrypt_ldap_password(message, key):
    """
    Takes an encrypted, base64 encoded password and the base64 encoded key.
    Returns the cleartext password.
    """
    decoded_message = base64.b64decode(message)
    decoded_key = base64.b64decode(key)

    iv = decoded_message[:16]
    ciphertext = decoded_message[16:]

    cipher = Cipher(algorithms.AES(decoded_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    cleartext_pw = decryptor.update(ciphertext) + decryptor.finalize()
    return cleartext_pw.decode()


def store_ldap_password(request, password):
    """
    Stores the password in an encrypted session storage and returns the key.
    """
    encrypted_pw, key = encrypt_ldap_password(password)
    request.session[ENCRYPTED_LDAP_PASSWORD] = encrypted_pw
    request.session.save()
    return key


def get_ldap_password(request):
    cookies = request.COOKIES
    key = cookies.get('sessionkey', None)
    if not key:
        raise Exception('sessionkey not found in cookies.')
    return decrypt_ldap_password(request.session[ENCRYPTED_LDAP_PASSWORD], key)
