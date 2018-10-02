from django.conf.urls import include, url

from django.contrib import admin
from account.views import hammertime, landingpage
admin.autodiscover()

urlpatterns = [

    url(r'^stop/hammertime/$', hammertime, name="hammertime"),
    url(r'^admin/doc/', include('django.contrib.admindocs.urls')),
    url(r'^admin/', admin.site.urls),
    url(r'^cbapi/', include("cbapi_ldap.urls")),

    url(r'account/', include('account.urls')),

    url(r'^$', landingpage, name="landingpage"),

]
