#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import base64
import hashlib

from django.conf import settings
from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response
from django.template.context import RequestContext
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import Group
from django.shortcuts import render
from django.utils.translation import ugettext as _

from forms import GastroPinForm, WlanPresenceForm, LoginForm, PasswordForm, \
    RFIDForm, NRF24Form, SIPPinForm, CLabPinForm
from cbase_members import retrieve_member

def landingpage(request):
    if request.user.is_authenticated():
        return HttpResponseRedirect('/account')
    form = LoginForm()
    is_ceymaster = is_admin = False
    if 'ceymaster' in [g.name for g in request.user.groups.all()]:
        is_ceymaster = True
    if 'ldap_admins' in [g.name for g in request.user.groups.all()]:
        is_admin = True
    groups = Group.objects.all()
    admins = Group.objects.get(name="ldap_admins").user_set.all()

    # values = get_user_values(request.user.username, request.session['ldap_password'])
    #return render_to_response("dashboard.html", locals())
    return render(request, 'base.html', {'form': form, 'admins': admins})

def auth_login(request):
    redirect_to = request.GET.get('next', '') or '/'
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = form.login(request)
            if user is not None:
                if user.is_active:
                    login(request, user)
                    member, created = \
                        User.objects.get_or_create(username=username)
                    if created:
                        member.save()

                    # save password in the session for later use with LDAP
                    request.session['ldap_password'] = password
                    # TODO: Change the

                    response = HttpResponseRedirect(redirect_to)
                    response.set_cookie('sessionkey', 'bla')
                    return response
            else:
                return render(request, 'login.html', {'form': form})
    else:
        form = LoginForm()

    return render_to_response('login.html',
            RequestContext(request, locals()))

@login_required
def home(request):
    member = retrieve_member(request)
    context = {'member': member.to_dict(), 'groups': request.user.groups.all()}
    return render(request, 'home.html', context)

@login_required
def auth_logout(request):
    redirect_to = request.GET.get('next', '') or '/'
    logout(request)
    response = HttpResponseRedirect(redirect_to)
    response.delete_cookie('sessionkey')
    return response

@login_required(redirect_field_name="/" ,login_url="/account/login/")
def groups_list(request, group_name):
    group = get_object_or_404(Group, name=group_name)
    groups = Group.objects.all()
    if 'ceymaster' in [g.name for g in request.user.groups.all()]:
        is_ceymaster = True
    if 'ldap_admins' in [g.name for g in request.user.groups.all()]:
        is_admin = True
    return render_to_response("group_list.html", locals())

@login_required
def sippin(request):
    return set_ldap_field(request, SIPPinForm, [('sippin', 'sippin')],
        'sippin.html')

def set_hash_field(request, form_type, in_field, out_field, hash_func,
        template_name):
    """
    Abstract view for changing LDAP attributes that need to be hashed.
    Takes a function that converts the value into the hashed_value.
    """
    member = retrieve_member(request)
    initial = {}

    if request.method == 'POST':
        form = form_type(request.POST)
        if form.is_valid():
            hashed_value = hash_func(form.cleaned_data[in_field])
            print 'hashed value: ', hashed_value
            member.set(out_field, hashed_value)
            member.save()
            new_form = form_type(initial=initial)
            return render(request, template_name,
                    {'message': _('Your changes have been saved. Thank you!'),
                     'form': new_form, 'member': member.to_dict()})
        else:
            return render(request, template_name,
                    {'form': form, 'member': member.to_dict()})
    else:
        form = form_type(initial=initial)
        return render(request, template_name,
                {'form': form, 'member': member.to_dict()})

@login_required
def gastropin(request):
    def calculate_gastro_hash(pin):
        key = settings.CBASE_GASTRO_KEY
        bla = '%s%s' % (key, pin)
        return hashlib.sha256(bla).hexdigest()

    return set_hash_field(request, GastroPinForm,
        'gastropin1', 'gastroPIN', calculate_gastro_hash, 'gastropin.html')

@login_required
def clabpin(request):
    def calculate_clab_hash(pin):
        salt = os.urandom(12)
        digest = hashlib.sha1(bytearray(pin, 'UTF-8')+salt).digest()
        return '{SSHA}' + base64.b64encode(digest + salt)

    return set_hash_field(request, CLabPinForm, 'c_lab_pin1', 'c-labPIN',
            calculate_clab_hash, 'clabpin.html')

@login_required
def password(request):
    """
    """
    member = retrieve_member(request)

    if request.method == 'POST':
        form = PasswordForm(request.POST, request=request)

        if form.is_valid():
            new_password = form.cleaned_data['password1']
            member.change_password(new_password)
            request.session['ldap_password'] = new_password
            request.session.save()
            new_form = PasswordForm()
            return render(request, 'password.html',
                {'message': _('Your password was changed. Thank you!'),
                 'form': new_form, 'member': member.to_dict()})
        else:
            return render(request, 'password.html',
                {'form': form, 'member': member.to_dict()})
    else:
        form = PasswordForm()
        return render(request, 'password.html',
            {'form': form, 'member': member.to_dict()})

def set_ldap_field(request, form_type, field_names, template_name):
    """
    Abstract view for each of the different forms.

    field_names contains the mapping of the field name in the form to
    """
    member = retrieve_member(request)
    initial = {}

    if request.method == 'POST':
        form = form_type(request.POST)
        if form.is_valid():

            for form_field, ldap_field in field_names:
                member.set(ldap_field, form.cleaned_data[form_field])
                initial[form_field] = member.get(ldap_field)
            member.save()
            new_form = form_type(initial=initial)
            return render(request, template_name,
                    {'message': _('Your changes have been saved. Thank you!'),
                     'form': new_form, 'member': member.to_dict()})
        else:
            return render(request, template_name,
                    {'form': form, 'member': member.to_dict()})
    else:
        for form_field, ldap_field in field_names:
            initial[form_field] = member.get(ldap_field)
        form = form_type(initial=initial)
        return render(request, template_name,
                {'form': form, 'member': member.to_dict()})

@login_required
def wlan_presence(request):
    return set_ldap_field(request, WlanPresenceForm,
            [('presence', 'wlanPresence')], 'wlan_presence.html')

@login_required
def rfid(request):
    return set_ldap_field(request, RFIDForm, [('rfid', 'rfid')], 'rfid.html')

@login_required
def nrf24(request):
    return set_ldap_field(request, NRF24Form, [('nrf24', 'nrf24')], 'nrf24.html')




