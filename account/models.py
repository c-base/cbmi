from django.db import models
from django.contrib.auth.models import User
from django.db.models import signals
from account.signals import create_profile, delete_profile

class UserProfile(models.Model):
    user = models.OneToOneField(User, editable=False)
    uid = models.CharField("User-ID",
                           max_length=8,
                           null=True,
                           default=None)
    sippin = models.CharField("SIP PIN",
                              max_length=255,
                              null=True,
                              blank=True,
                              default=None)
    gastropin = models.CharField("Gastro PIN",
                                 max_length=255,
                                 null=True,
                                 blank=True,
                                 default=None)
    rfid = models.CharField("RFID",
                            max_length=255,
                            null=True,
                            blank=True,
                            default=None)
    macaddress = models.CharField("MAC-Address",
                                  max_length=255,
                                  null=True,
                                  blank=True,
                                  default=None)
    clabpin = models.CharField("c-lab PIN",
                               max_length=255,
                               null=True,
                               blank=True,
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
