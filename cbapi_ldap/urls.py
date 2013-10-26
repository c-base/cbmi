from django.conf.urls import patterns, url
from jsonrpc import jsonrpc_site
from cbapi_ldap import views

urlpatterns = patterns(
    '',
    url(r'^ldap/browse/$', 'jsonrpc.views.browse', name='jsonrpc_browser'),
    url(r'^ldap/$', jsonrpc_site.dispatch, name='jsonrpc_mountpoint'),
)
