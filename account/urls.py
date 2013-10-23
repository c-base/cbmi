from django.conf.urls import patterns, url


urlpatterns = patterns(
    '',
    url(r'^login/$', 'account.views.auth_login', name="auth_login"),
    url(r'^logout/$', 'account.views.auth_logout', name="auth_logout"),
)