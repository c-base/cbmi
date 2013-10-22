from django.shortcuts import render_to_response, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import Group
from django.shortcuts import render
from django.utils.translation import ugettext as _


from forms import GastroPinForm

def landingpage(request):
    is_ceymaster = is_admin = False
    if 'ceymaster' in [g.name for g in request.user.groups.all()]:
        is_ceymaster = True
    if 'ldap_admins' in [g.name for g in request.user.groups.all()]:
        is_admin = True
    groups = Group.objects.all()
    admins = Group.objects.get(name="ldap_admins").user_set.all()
    if request.user.is_authenticated():
        return render_to_response("dashboard.html", locals())
    return render_to_response("base.html", locals())


@login_required(redirect_field_name="/" ,login_url="/account/login/")
def groups_list(request, group_name):
    group = get_object_or_404(Group, name=group_name)
    groups = Group.objects.all()
    if 'ceymaster' in [g.name for g in request.user.groups.all()]:
        is_ceymaster = True
    if 'ldap_admins' in [g.name for g in request.user.groups.all()]:
        is_admin = True
    return render_to_response("group_list.html", locals())

@login_required
def gastropin(request):
    if request.method == 'POST':
        form = GastroPinForm(request.POST)
        if form.is_valid():
            user = request.user
            user_profile = user.get_profile()
            user_profile.gastropin = form.cleaned_data['gastropin']
            user_profile.save()
            return render(request, 'gastropin.html',
                {'message': _('Your Gastro-PIN was changed. Thank you!'),
                 'form:': form})
        else:
            return render(request, 'gastropin.html', {'form:': form})

    else:
        form = GastroPinForm()

    return render(request, 'gastropin.html', {'form': form})
