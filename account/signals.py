def create_profile(sender, instance, signal, created, **kwargs):
    from account.models import UserProfile

    if created:
        UserProfile(user=instance).save()

def delete_profile(sender, instance, signal, **kwargs):
    from account.models import UserProfile
    UserProfile(user=instance).delete()