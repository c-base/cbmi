from django.db import models
from django.contrib.auth.models import User
from django.db.models import signals
from account.signals import create_profile, delete_profile

class UserProfile(models.Model):
    user = models.OneToOneField(User, editable=False)
    uid = models.CharField(verbose_name="User-ID",
                           max_length=8,
                           null=True,
                           default=None)
    sippin = models.CharField(verbose_name="SIP PIN",
                              max_length=255,
                              null=True,
                              blank=True,
                              default=None)
    gastropin = models.CharField(verbose_name="Gastro PIN",
                                 max_length=255,
                                 null=True,
                                 blank=True,
                                 default=None)
    rfid = models.CharField(verbose_name="RFID",
                            max_length=255,
                            null=True,
                            blank=True,
                            default=None)
    macaddress = models.CharField(verbose_name="MAC-Address",
                                  max_length=255,
                                  null=True,
                                  blank=True,
                                  default=None)
    clabpin = models.CharField(verbose_name="c-lab PIN",
                               max_length=255,
                               null=True,
                               blank=True,
                               default=None)
    preferred_email = models.CharField(verbose_name="preferred e-mail address",
                                       max_length=1024,
                                       null=True,
                                       default=None)
    is_member = models.BooleanField(default=False, editable=False)
    is_ldap_admin = models.BooleanField(default=False, editable=False)
    is_circle_member = models.BooleanField(default=False, editable=False)
    is_clab_member = models.BooleanField(default=False, editable=False)
    is_cey_member = models.BooleanField(default=False, editable=False)
    is_ceymaster = models.BooleanField(default=False, editable=False)
    is_soundlab_member = models.BooleanField(default=False, editable=False)

    def __unicode__(self):
        return 'Profile: %s' % self.user.username

User.profile = property(lambda u: UserProfile.objects.get_or_create(user=u)[0])
signals.post_save.connect(create_profile, sender=User)
signals.pre_delete.connect(delete_profile, sender=User)
