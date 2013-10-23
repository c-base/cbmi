#!/usr/bin/env python
# -*- coding: utf-8 -*-

import ldap
import copy

from django.shortcuts import render_to_response, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import Group
from django.shortcuts import render
from django.utils.translation import ugettext as _

from forms import GastroPinForm, WlanPresenceForm

def landingpage(request):
    is_ceymaster = is_admin = False
    if 'ceymaster' in [g.name for g in request.user.groups.all()]:
        is_ceymaster = True
    if 'ldap_admins' in [g.name for g in request.user.groups.all()]:
        is_admin = True
    groups = Group.objects.all()
    admins = Group.objects.get(name="ldap_admins").user_set.all()
    if request.user.is_authenticated():
        # values = get_user_values(request.user.username, request.session['ldap_password'])
        return render_to_response("dashboard.html", locals())
    return render_to_response("base.html", locals())


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
def gastropin(request):
    if request.method == 'POST':
        form = GastroPinForm(request.POST)
        if form.is_valid():
            user = request.user
            user_profile = user.get_profile()
            user_profile.gastropin = form.cleaned_data['gastropin']
            user_profile.save()
            return render(request, 'gastropin.html',
                {'message': _('Your Gastro-PIN was changed. Thank you!'),
                 'form:': form})
        else:
            return render(request, 'gastropin.html', {'form:': form})

    else:
        form = GastroPinForm()

    return render(request, 'gastropin.html', {'form': form})

@login_required
def wlan_presence(request):
    uv = UserValues(request.user.username, request.session['ldap_password'])
    print "presence ist: ", uv.get_bool("wlanPresence")

    if request.method == 'POST':
        form = WlanPresenceForm(request.POST)
        if form.is_valid():

            p = 'FALSE'
            if form.cleaned_data['presence'] == True:
                p = 'TRUE'
            uv.set('wlanPresence', p)
            uv.save()
            new_form = WlanPresenceForm(initial={'presence': uv.get_bool("wlanPresence")})
            return render(request, 'wlan_presence.html',
                {'message': _('Your Wifi Presenc has been set. Thank you!'),
                 'form': new_form})
        else:
            return render(request, 'wlan_presence.html', {'form:': form})
    else:
        form = WlanPresenceForm(initial={'presence': uv.get_bool("wlanPresence")})

    return render(request, 'wlan_presence.html', {'form': form})


#def set_wlan_presence(request, value):
#    """
#
#    """
#    set_boolean_value('wlanPresence', value,
#        request.user.username, request.session['ldap_password'])


class UserValues(object):
    """

    """

    def __init__(self, username, password):
        self._username = username
        self._password = password
        self._old = self.get_user_values()
        self._new = copy.deepcopy(self._old)

    def get(self, key, default=None):
        return self._new.get(key, default)[0]

    def set(self, key, value):
        self._new[key] = [value]

    def get_bool(self, key):
        return self.get(key) == 'TRUE'

    def save(self):
        """

        """
        dn = "uid=%s,ou=crew,dc=c-base,dc=org" % self._username
        print 'setting dn=', dn

        # TODO: Use settings for url
        l = ldap.initialize("ldap://lea.cbrp3.c-base.org:389/")
        l.simple_bind_s(dn, self._password)

        mod_attrs = []
        for new_key, new_value in self._new.items():
            # Replace is the default.
            action = ldap.MOD_REPLACE
            if new_key not in self._old.keys():
                action = ldap.MOD_ADD
                mod_attrs.append((action, '%s' % new_key, new_value ))
                continue
            # Set the attribute and wait for the LDAP server to complete.
            if self._old[new_key][0] != new_value[0]:
                action = ldap.MOD_REPLACE
                mod_attrs.append((action, '%s' % new_key, new_value ))
                continue

        print "modattrs: ",mod_attrs
        result = l.modify_s(dn, mod_attrs)
        print "result is: ", result


    def get_user_values(self):
        """

        """

        dn = "ou=crew,dc=c-base,dc=org"
        bind_dn = "uid=%s,ou=crew,dc=c-base,dc=org" % self._username
        print('setting dn=', dn)

        # TODO: Use settings for url
        l = ldap.initialize("ldap://lea.cbrp3.c-base.org:389/")
        l.simple_bind_s(bind_dn, self._password)

        # Set the attribute and wait for the LDAP server to complete.
        searchScope = ldap.SCOPE_SUBTREE
        ## retrieve all attributes - again adjust to your needs - see documentation for more options
        retrieveAttributes = None
        searchFilter = "uid=%s" % self._username

        # get_attrs = [( ldap., 'wlanPresence', set_value )]
        result = l.search_s(dn, searchScope, searchFilter, retrieveAttributes)
        # TODO: latin1
        print "result is: ", result
        # TODO: if len(result)==0
        return result[0][1]
