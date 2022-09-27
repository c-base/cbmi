from django.urls import include, re_path

from django.contrib import admin
from account.views import hammertime, landingpage
admin.autodiscover()

urlpatterns = [

    re_path(r'^stop/hammertime/$', hammertime, name="hammertime"),
    re_path(r'^admin/doc/', include('django.contrib.admindocs.urls')),
    re_path(r'^admin/', admin.site.urls),
    re_path(r'^cbapi/', include("cbapi_ldap.urls")),

    re_path(r'account/', include('account.urls')),

    re_path(r'^$', landingpage, name="landingpage"),

]
