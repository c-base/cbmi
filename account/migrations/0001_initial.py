# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='UserProfile',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('uid', models.CharField(default=None, max_length=8, null=True, verbose_name=b'User-ID')),
                ('sippin', models.CharField(default=None, max_length=255, null=True, verbose_name=b'SIP PIN', blank=True)),
                ('gastropin', models.CharField(default=None, max_length=255, null=True, verbose_name=b'Gastro PIN', blank=True)),
                ('rfid', models.CharField(default=None, max_length=255, null=True, verbose_name=b'RFID', blank=True)),
                ('macaddress', models.CharField(default=None, max_length=255, null=True, verbose_name=b'MAC-Address', blank=True)),
                ('clabpin', models.CharField(default=None, max_length=255, null=True, verbose_name=b'c-lab PIN', blank=True)),
                ('preferred_email', models.CharField(default=None, max_length=1024, null=True, verbose_name=b'preferred e-mail address')),
                ('is_member', models.BooleanField(default=False, editable=False)),
                ('is_ldap_admin', models.BooleanField(default=False, editable=False)),
                ('is_circle_member', models.BooleanField(default=False, editable=False)),
                ('is_clab_member', models.BooleanField(default=False, editable=False)),
                ('is_cey_member', models.BooleanField(default=False, editable=False)),
                ('is_ceymaster', models.BooleanField(default=False, editable=False)),
                ('is_soundlab_member', models.BooleanField(default=False, editable=False)),
                ('user', models.OneToOneField(editable=False, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
