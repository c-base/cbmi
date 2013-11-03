from django.conf.urls import patterns, include, url

from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    url(r'^stop/hammertime/$', 'account.views.hammertime', name="hammertime"),
    url(r'^admin/doc/', include('django.contrib.admindocs.urls')),
    url(r'^admin/', include(admin.site.urls)),

    url(r'^cbapi/', include("cbapi_ldap.urls")),

    url(r'account/', include('account.urls')),

    url(r'^$', 'account.views.landingpage', name="landingpage"),

)
