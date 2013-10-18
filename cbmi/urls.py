from django.conf.urls import patterns, include, url

from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    url(r'^admin/doc/', include('django.contrib.admindocs.urls')),
    url(r'^admin/', include(admin.site.urls)),
    url(r'account/', include('account.urls')),
    url(r'^groups/(?P<group_name>[^/]+)/', 'cbmi.views.groups_list'),
    url(r'^$', 'cbmi.views.landingpage')
)
