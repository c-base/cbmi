#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64

from Crypto import Random
from Crypto.Cipher import AES

ENCRYPTED_LDAP_PASSWORD = 'encrypted_ldap_password'

def encrypt_ldap_password(cleartext_pw):
    """
    Encrypts the cleartext_pw with a randomly generated key.

    Returns the key and the encrypted message containing the password.
    The key is supposed to be stored into the 'session_key' cookie field we can
    later use it to decrypt the password and connect to the LDAP server with it.
    """
    # 16 bytes of key => AES-128
    random = Random.new()
    key = random.read(16)

    # initialization vector
    iv = random.read(16)

    # do the encryption
    aes = AES.new(key, AES.MODE_CFB, iv)
    message = iv + aes.encrypt(cleartext_pw)
    return base64.b64encode(message), base64.b64encode(key)

def decrypt_ldap_password(message, key):
    """
    Takes an encrypted, base64 encoded password and the base64 encoded key.
    Returns the cleartext password.
    """
    decoded_message = base64.b64decode(message)
    decoded_key = base64.b64decode(key)

    # first 16 bytes of the message are the initialization vector
    iv = decoded_message[:16]

    # the rest is the encrypted password
    ciphertext = decoded_message[16:]

    # decrypt it
    aes = AES.new(decoded_key, AES.MODE_CFB, iv)
    cleartext_pw = aes.decrypt(ciphertext)
    return cleartext_pw

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