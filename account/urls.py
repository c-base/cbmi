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
    url(r'^clabpin/$', 'account.views.clabpin', name='clabpin'),
    url(r'^preferred_email/$', 'account.views.preferred_email', name='preferred_email'),
    url(r'^admin/$', 'account.views.admin', name='admin'),
    url(r'^memberstatus/$', 'account.views.memberstatus', name='memberstatus'),
    url(r'^$', 'account.views.home', name="home"),
    url(r'^groups/(?P<group_name>[^/]+)/', 'account.views.groups_list'),
)
