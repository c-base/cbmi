#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re

from django import forms
from django.contrib.auth import authenticate
from django.utils.translation import ugettext as _

class UsernameField(forms.CharField):
    """
    The username field makes sure that usernames are always entered in lower-case.
    If we do not convert the username to lower-case, Django will create more than
    one user object in the database. If we then try to login again, the Django auth
    subsystem will do an query that looks like this: username__iexact="username". The
    result is an error, because iexact returns the objects for "username" and "Username".
    """
    
    def to_python(self, value):
        value = super(UsernameField, self).to_python(value)
        value = value.lower()
        return value
    

class LoginForm(forms.Form):
    username = UsernameField(max_length=255)
    password = forms.CharField(max_length=255, widget=forms.PasswordInput,
        help_text=_('Cookies must be enabled.'))
        
    def clean(self):
        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')
        user = authenticate(username=username, password=password)
        if not user or not user.is_active:
            raise forms.ValidationError(_('Sorry, that login was invalid. '
                                          'Please try again.'), code='invalid_login')
        return self.cleaned_data

    def login(self, request):
        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')
        user = authenticate(username=username, password=password)
        return user


class GastroPinField(forms.CharField):
    widget = forms.PasswordInput
    def validate(self, value):
        """
        Check if the value is all numeric and 4 - 8 chars long.
        """
        match = re.match(r'^\d{4,8}$', value)
        if not match:
            raise forms.ValidationError(_('PIN must be 4 to 8 digits.'))


class GastroPinForm(forms.Form):
    gastropin1 = GastroPinField(label=_('New Gastro-PIN'))
    gastropin2 = GastroPinField(label=_('Repeat Gastro-PIN'),
        help_text=_('Numerical only, 4 to 8 digits'))

    def clean(self):
        cleaned_data = super(GastroPinForm, self).clean()
        gastropin1 = cleaned_data.get("gastropin1")
        gastropin2 = cleaned_data.get("gastropin2")

        if gastropin1 != gastropin2:
            raise forms.ValidationError(
                _('The PINs entered were not identical.'),
                code='not_identical')
        return cleaned_data


class WlanPresenceForm(forms.Form):
    # Boolean fields must never be required.
    presence = forms.BooleanField(required=False,
            label=_('Enable WiFi presence'))


class PasswordForm(forms.Form):
    old_password = forms.CharField(max_length=255, widget=forms.PasswordInput,
        label=_('Old password'),
        help_text=_('Enter your current password here.'))
    password1 = forms.CharField(max_length=255, widget=forms.PasswordInput,
        label=_('New password'))
    password2 = forms.CharField(max_length=255, widget=forms.PasswordInput,
        label=_('Repeat password'))

    def __init__(self, *args, **kwargs):
        self._request = kwargs.pop('request', None)
        super(PasswordForm, self).__init__(*args, **kwargs)

    def clean(self):
        cleaned_data = super(PasswordForm, self).clean()
        old_password = cleaned_data.get('old_password')
        username = self._request.user.username.lower()
        user = authenticate(username=username, password=old_password)

        if not user or not user.is_active:
            raise forms.ValidationError(_('The old password was incorrect.'),
                    code='old_password_wrong')

        password1 = cleaned_data.get('password1')
        password2 = cleaned_data.get('password2')
        if password1 != password2:
            raise forms.ValidationError(
                _('The new passwords were not identical.'),
                code='not_identical')
        if len(password1) < 6:
            raise forms.ValidationError(
                _('Password must be at least 6 characters long'),
                code='to_short')

        return cleaned_data


class RFIDForm(forms.Form):
    rfid = forms.CharField(max_length=255, label=_('Your RFID'),
        help_text=_('Find out your RFID by holding your RFID tag to the '
                    'reader in the airlock.'))


class SIPPinForm(forms.Form):
    sippin1 = GastroPinField(label=_('Your SIP PIN'))
    sippin2 = GastroPinField(label=_('Repeat SIP PIN'))

    def clean(self):
        cleaned_data = super(SIPPinForm, self).clean()
        sippin1 = cleaned_data.get("sippin1")
        sippin2 = cleaned_data.get("sippin2")
        if sippin1 != sippin2:
            raise forms.ValidationError(
                _('The PINs entered were not identical.'),
                code='not_identical')


class NRF24Form(forms.Form):
    nrf24 = forms.CharField(max_length=255,
        label = _('NRF24-ID'),
        help_text=_("Your r0ket's NRF24 identification"))


class CLabPinForm(forms.Form):
    c_lab_pin1 = GastroPinField(label=_('New indoor PIN'))
    c_lab_pin2 = GastroPinField(label=_('Repeat indoor PIN'),
            help_text=_('Numerical only, 4 to 8 digits'))


class AdminForm(forms.Form):
    password1 = forms.CharField(max_length=255, widget=forms.PasswordInput,
        label=_('New password'))
    password2 = forms.CharField(max_length=255, widget=forms.PasswordInput,
        label=_('Repeat password'))


    def __init__(self, *args, **kwargs):
        self._request = kwargs.pop('request', None)
        self._users = kwargs.pop('users', [])
        choices = [x for x in self._users]
        choices.insert(0, ('', 'Select username ...'))
        super(AdminForm, self).__init__(*args, **kwargs)
        self.fields.insert(0, 'username', forms.ChoiceField(choices=choices,
            help_text=_('Select the username for whom you want to reset the password.')))

    def clean(self):
        cleaned_data = super(AdminForm, self).clean()

        password1 = cleaned_data.get('password1')
        password2 = cleaned_data.get('password2')
        if password1 != password2:
            raise forms.ValidationError(
                _('The new passwords were not identical.'),
                code='not_identical')
        if len(password1) < 6:
            raise forms.ValidationError(
                _('Password must be at least 6 characters long'),
                code='to_short')

        return cleaned_data

    def get_member_choices(self):
        return [(x, x) for x in self._users]
