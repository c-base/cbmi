#!/usr/bin/env python
# -*- coding: utf-8 -*-

import collections
import hashlib
import os

import requests
from django.conf import settings
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import Group
from django.contrib.auth.models import User
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.shortcuts import render
from django.shortcuts import render
# from django.utils.translation import ugettext as _
from django.utils.translation import gettext as _

import smbpasswd
from account.cbase_members import retrieve_member, MemberValues, get_ldap_admins
from account.forms import GastroPinForm, WlanPresenceForm, LoginForm, \
    PasswordForm, RFIDForm, NRF24Form, SIPPinForm, CLabPinForm, AdminForm, \
    PreferredEmailForm
from account.password_encryption import *


def landingpage(request):
    if request.user.is_authenticated:
        return HttpResponseRedirect('/account')
    login_form = LoginForm()
    try:
        # just in case the group hasn't yet been synced
        # admins = Group.objects.filter(name__in=get_ldap_admins()).user_set.all()
        admins = get_ldap_admins()
    except Exception:
        # else provide an emtpy list
        admins = []

    # https://github.com/c-base/cbmi/issues/20
    # check if nick is still available feature
    check_nickname = request.GET.get('check_nickname', '')
    if check_nickname:
        try:
            user = User.objects.get(username=check_nickname)
            check_nickname = True
        except Exception:
            check_nickname = False

    # output as text if requested
    if request.GET.get('raw', ''):
        return HttpResponse(check_nickname)

    return render(request, 'base.html', locals())


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
                    key = store_ldap_password(request, password)
                    response = HttpResponseRedirect(redirect_to)
                    response.set_cookie('sessionkey', key)
                    return response
    else:
        form = LoginForm()
    return render(request, 'login.html', {'form': form})


@login_required
def home(request):
    member = retrieve_member(request)
    number_of_members = member.get_number_of_members()
    password = get_ldap_password(request)
    username = request.user.username
    url = "https://vorstand.cbrp3.c-base.org/cteward-api/legacy/member/%s" % username
    cteward = None
    try:
        r = requests.get(
            url,
            verify=False,
            auth=(username, password)
        )
        cteward = r.json()
    except Exception:
        pass
    context = {
        'member': member.to_dict(),
        'groups': list(request.user.groups.all().order_by('name')),
        'number_of_members': number_of_members,
        'cteward': cteward,
    }
    return render(request, 'home.html', context)


@login_required
def auth_logout(request):
    request.session.pop(ENCRYPTED_LDAP_PASSWORD)
    redirect_to = request.GET.get('next', '') or '/'
    logout(request)
    response = HttpResponseRedirect(redirect_to)
    response.delete_cookie('sessionkey')
    return response


@login_required(redirect_field_name="/", login_url="/account/login/")
def groups_list(request, group_name):
    group = get_object_or_404(Group, name=group_name)
    groups = Group.objects.all()
    if 'ceymaster' in [g.name for g in request.user.groups.all()]:
        is_ceymaster = True
    if 'ldap_admins' in [g.name for g in request.user.groups.all()]:
        is_admin = True
    return render(request, "group_list.html", locals())


@login_required
def sippin(request):
    return set_ldap_field(
        request,
        SIPPinForm,
        [('sippin', 'sippin')],
        'sippin.html'
    )


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
            member.set(out_field, hashed_value)
            member.save()
            new_form = form_type(initial=initial)
            return render(
                request,
                template_name,
                {
                    'message': _('Your changes have been saved. Thank you!'),
                    'form': new_form,
                    'member': member.to_dict()
                }
            )
        else:
            return render(
                request,
                template_name,
                {
                    'form': form,
                    'member': member.to_dict()
                }
            )
    else:
        form = form_type(initial=initial)
        return render(
            request,
            template_name,
            {
                'form': form,
                'member': member.to_dict()
            }
        )


@login_required
def gastropin(request):
    def calculate_gastro_hash(pin):
        key = settings.CBASE_GASTRO_KEY
        bla = '%s%s' % (key, pin)
        return hashlib.sha256(bla.encode()).hexdigest()

    return set_hash_field(
        request,
        GastroPinForm,
        'gastropin1',
        'gastroPIN',
        calculate_gastro_hash,
        'gastropin.html'
    )


@login_required
def clabpin(request):
    # names = ['cey-c-lab', 'cey-schleuse', 'cey-soundlab']
    # if len(request.user.groups.filter(name__in=names)) < 1:
    #      return render(request, 'access_denied.html')

    def calculate_clab_hash(pin):
        salt = os.urandom(12)
        digest = hashlib.sha1(bytearray(pin, 'UTF-8') + salt).digest()
        pin_hash = '{SSHA}%s' % base64.b64encode(digest + salt).decode()
        return pin_hash

    return set_hash_field(request, CLabPinForm, 'c_lab_pin1', 'c-labPIN',
                          calculate_clab_hash, 'clabpin.html')


@login_required
def password(request):
    """
    View that changes the password on the LDAP server.
    """
    member = retrieve_member(request)

    if request.method == 'POST':
        form = PasswordForm(request.POST, request=request)

        if form.is_valid():
            new_password = form.cleaned_data['password1']

            # change the password for the Wifi
            member.set('sambaLMPassword', smbpasswd.lmhash(new_password))
            member.set('sambaNTPassword', smbpasswd.nthash(new_password))
            member.save()

            # change the LDAP password
            member.change_password(new_password)

            key = store_ldap_password(request, new_password)
            request.session.save()
            new_form = PasswordForm()
            response = render(request, 'password.html',
                              {'message': _(
                                  'Your password was changed. Thank you!'),
                                  'form': new_form, 'member': member.to_dict()})
            response.set_cookie('sessionkey', key)
            return response
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
                if form.cleaned_data[form_field] == '':
                    member.set(ldap_field, None)
                else:
                    member.set(ldap_field, form.cleaned_data[form_field])
                initial[form_field] = member.get(ldap_field)
            member.save()
            new_form = form_type(initial=initial)
            return render(request, template_name,
                          {'message': _(
                              'Your changes have been saved. Thank you!'),
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
    return set_ldap_field(request, NRF24Form, [('nrf24', 'nrf24')],
                          'nrf24.html')


@login_required
def preferred_email(request):
    return set_ldap_field(request, PreferredEmailForm,
                          [('preferred_email', 'preferredEmail')],
                          'preferred_email.html')


@login_required
def admin(request):
    admin_member = retrieve_member(request)
    if len(request.user.groups.filter(name__in=['ldap_admins'])) < 1:
        return render(request, 'access_denied.html')
    users = admin_member.list_users()
    if request.method == 'POST':
        form = AdminForm(request.POST, request=request, users=users)

        if form.is_valid():
            new_password = form.cleaned_data['password1']
            admin_member.admin_change_password(form.cleaned_data['username'],
                                               new_password)

            member = MemberValues(form.cleaned_data['username'], new_password)
            member.set('sambaLMPassword', smbpasswd.lmhash(new_password))
            member.set('sambaNTPassword', smbpasswd.nthash(new_password))
            member.save()

            new_form = AdminForm(request=request, users=users)
            return render(request, 'admin.html',
                          {'message': _(
                              'The password for %s was changed. Thank you!' %
                              form.cleaned_data['username']),
                              'form': new_form})
        else:
            return render(request, 'admin.html',
                          {'form': form})
    else:
        form = AdminForm(request=request, users=users)
        return render(request, 'admin.html',
                      {'form': form})

    # username = cleaned_data.get('username')
    # admin_username = self._request.user.username
    # admin_password = self._request.session['ldap_password']


def hammertime(request):
    return render(request, 'hammertime.html', {})


@login_required
def memberstatus(request):
    # url = baseurl + route_operation_mapping['SessionCreate']['Route']
    # data = json.dumps({'UserLogin': username, 'Password': password})
    password = get_ldap_password(request)
    username = request.user.username

    url = "https://vorstand.c-base.org" \
          "/cteward-api/legacy/member/%s/contributions" % username
    r = requests.get(
        url,
        verify=False,
        auth=(username, password)
    )
    contributions = r.json()
    try:
        years = collections.OrderedDict(
            sorted(contributions['years'].items(), reverse=True))
        contributions['years'] = years.items()
    except:
        pass

    url = "https://vorstand.c-base.org/cteward-api/legacy/member/%s" % username
    r = requests.get(
        url,
        verify=False,
        auth=(username, password)
    )
    cteward = r.json()

    return render(
        request, 'memberstatus.html',
        {
            'contributions': contributions,
            'cteward': cteward
        }
    )
