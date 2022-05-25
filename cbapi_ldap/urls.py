from django.conf.urls import url
# from jsonrpc import jsonrpc_site
# from jsonrpc.views import browse
from cbapi_ldap import views


urlpatterns = [
    # url(r'^ldap/browse/$', browse, name='jsonrpc_browser'),
    # url(r'^ldap/$', jsonrpc_site.dispatch, name='jsonrpc_mountpoint'),
]
