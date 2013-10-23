#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re

from django import forms
from django.utils.translation import ugettext as _


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
    presence = forms.BooleanField(required=False)