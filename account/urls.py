from django.conf.urls import patterns, url


urlpatterns = patterns(
    '',
    url(r'^login/$', 'account.views.auth_login', name="cbase_auth_login"),
    url(r'^logout/$', 'account.views.auth_logout', name="auth_logout"),
    url(r'^gastropin/$', 'account.views.gastropin', name='gastropin'),
    url(r'^wlan_presence/$', 'account.views.wlan_presence', name='wlan_presence'),
    url(r'^rfid/$', 'account.views.rfid', name='rfid'),
    url(r'^nrf24/$', 'account.views.nrf24', name='nrf24'),
    url(r'^password/$', 'account.views.password', name='password'),
    url(r'^sippin/$', 'account.views.sippin', name='sippin'),
    url(r'^$', 'account.views.home', name="home"),
    url(r'^groups/(?P<group_name>[^/]+)/', 'account.views.groups_list'),
)