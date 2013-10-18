from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response
from django.template.context import RequestContext
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.models import User

from account.forms import LoginForm


def auth_login(request):
    redirect_to = request.REQUEST.get('next', '') or '/'
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(username=username, password=password)
            if user is not None:
                if user.is_active:
                    login(request, user)
                    member, created = User.objects.get_or_create(
                        username=username)
                    if created:
                        member.save()
                    return HttpResponseRedirect(redirect_to)
            else:
                print 'user is none'
    else:
        form = LoginForm()
    return render_to_response('login.html',
                              RequestContext(request, locals()))


def auth_logout(request):
    redirect_to = request.REQUEST.get('next', '') or '/'
    logout(request)
    return HttpResponseRedirect(redirect_to)
