from account.views import (admin, auth_login, auth_logout, clabpin, gastropin,
                           groups_list, home, memberstatus, nrf24, password,
                           preferred_email, rfid, sippin, wlan_presence)
from django.urls import re_path

urlpatterns = [
    re_path(r'^login/$', auth_login, name="cbase_auth_login"),
    re_path(r'^logout/$', auth_logout, name="auth_logout"),
    re_path(r'^gastropin/$', gastropin, name='gastropin'),
    re_path(r'^wlan_presence/$', wlan_presence, name='wlan_presence'),
    re_path(r'^rfid/$', rfid, name='rfid'),
    re_path(r'^nrf24/$', nrf24, name='nrf24'),
    re_path(r'^password/$', password, name='password'),
    re_path(r'^sippin/$', sippin, name='sippin'),
    re_path(r'^clabpin/$', clabpin, name='clabpin'),
    re_path(r'^preferred_email/$', preferred_email, name='preferred_email'),
    re_path(r'^admin/$', admin, name='admin'),
    re_path(r'^memberstatus/$', memberstatus, name='memberstatus'),
    re_path(r'^$', home, name="home"),
    re_path(r'^groups/(?P<group_name>[^/]+)/', groups_list),
]
