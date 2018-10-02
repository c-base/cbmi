from account.views import (admin, auth_login, auth_logout, clabpin, gastropin,
                           groups_list, home, memberstatus, nrf24, password,
                           preferred_email, rfid, sippin, wlan_presence)
from django.conf.urls import url

urlpatterns = [
    url(r'^login/$', auth_login, name="cbase_auth_login"),
    url(r'^logout/$', auth_logout, name="auth_logout"),
    url(r'^gastropin/$', gastropin, name='gastropin'),
    url(r'^wlan_presence/$', wlan_presence, name='wlan_presence'),
    url(r'^rfid/$', rfid, name='rfid'),
    url(r'^nrf24/$', nrf24, name='nrf24'),
    url(r'^password/$', password, name='password'),
    url(r'^sippin/$', sippin, name='sippin'),
    url(r'^clabpin/$', clabpin, name='clabpin'),
    url(r'^preferred_email/$', preferred_email, name='preferred_email'),
    url(r'^admin/$', admin, name='admin'),
    url(r'^memberstatus/$', memberstatus, name='memberstatus'),
    url(r'^$', home, name="home"),
    url(r'^groups/(?P<group_name>[^/]+)/', groups_list),
]
