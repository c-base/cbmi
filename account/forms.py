#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re

from django import forms
from django.utils.translation import ugettext as _


class LoginForm(forms.Form):
    username = forms.CharField(max_length=255)
    password = forms.CharField(max_length=255, widget=forms.PasswordInput)


class GastroPinField(forms.CharField):
    def validate(self, value):
        """
        Check if the value is all numeric and 4 - 6 chars long.
        """
        match = re.match(r'^\d{4,6}$', value)
        if not match:
            raise forms.ValidationError(_('PIN must be 4 to 6 digits.'))


class GastroPinForm(forms.Form):
    gastropin = GastroPinField()


class WlanPresenceForm(forms.Form):
    # Boolean fields must never be required.
    presence = forms.BooleanField(required=False,
            help_text=_('Enable WiFi presence?'))


class PaswordForm(forms.Form):
    password1 = forms.CharField(max_length=255, widget=forms.PasswordInput,
        help_text=_('New password'))
    password2 = forms.CharField(max_length=255, widget=forms.PasswordInput,
        help_text=_('Repeat password'))


class RFIDForm(forms.Form):
    rfid = forms.CharField(max_length=255, help_text=_('Your RFID'))


class NRF24Form(forms.Form):
    nrf24 = forms.CharField(max_length=255,
        help_text=_('Your NRF24 identification'))
