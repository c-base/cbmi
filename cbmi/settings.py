# Django settings for cbmi project.
import os

DEBUG = True
TEMPLATE_DEBUG = DEBUG

ADMINS = (
    # ('smile', 'smile@c-base.org')
    # ('Your Name', 'your_email@example.com'),
)

MANAGERS = ADMINS

PROJECT_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASES = {
    'default': {
        # 'ENGINE': 'django.db.backends.mysql',
        # 'NAME': 'cbmi',
        # 'USER': 'cbmi',
        # 'PASSWORD': 'cbmi',
        # 'HOST': '',
        # 'PORT': '',
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(PROJECT_DIR, 'cbmi.db'),
    }
}

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# In a Windows environment this must be set to your system time zone.
TIME_ZONE = 'Europe/Berlin'

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = 'de-de'

SITE_ID = 1

# If you set this to False, Django will make some optimizations so as not
# to load the internationalization machinery.
USE_I18N = True

# If you set this to False, Django will not format dates, numbers and
# calendars according to the current locale.
USE_L10N = True

# If you set this to False, Django will not use timezone-aware datetimes.
USE_TZ = True

# Absolute filesystem path to the directory that will hold user-uploaded files.
# Example: "/home/media/media.lawrence.com/media/"
MEDIA_ROOT = ''

# URL that handles the media served from MEDIA_ROOT. Make sure to use a
# trailing slash.
# Examples: "http://media.lawrence.com/media/", "http://example.com/media/"
MEDIA_URL = ''

# Absolute path to the directory static files should be collected to.
# Don't put anything in this directory yourself; store your static files
# in apps' "static/" subdirectories and in STATICFILES_DIRS.
# Example: "/home/media/media.lawrence.com/static/"
STATIC_ROOT = ''

# URL prefix for static files.
# Example: "http://media.lawrence.com/static/"
STATIC_URL = '/static/'

# Additional locations of static files
STATICFILES_DIRS = (
    # Put strings here, like "/home/html/static" or "C:/www/django/static".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
    '/home/cbmi/cbmi/static',
    '/opt/cbmi/static',
)

# List of finder classes that know how to find static files in
# various locations.
STATICFILES_FINDERS = (
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
    # 'django.contrib.staticfiles.finders.DefaultStorageFinder',
)

DEFAULT_AUTO_FIELD = 'django.db.models.AutoField'

# Make this unique, and don't share it with anybody.
SECRET_KEY = 'vp!#muchjm!fqgi9r1%^xi^t$vb443!e^3b3fyke7b))xk2ml='

# List of callables that know how to import templates from various sources.
TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.Loader',
    'django.template.loaders.app_directories.Loader',
#     'django.template.loaders.eggs.Loader',
)
TEMPLATE_CONTEXT_PROCESSORS = (
    "django.contrib.auth.context_processors.auth",
    "django.core.context_processors.debug",
    "django.core.context_processors.i18n",
    "django.core.context_processors.media",
    "django.core.context_processors.static",
    "django.core.context_processors.tz",
    "django.contrib.messages.context_processors.messages",
    "django.core.context_processors.request"
)

MIDDLEWARE = [
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'cbmi.urls'

# Python dotted path to the WSGI application used by Django's runserver.
WSGI_APPLICATION = 'cbmi.wsgi.application'

TEMPLATE_DIRS = (
    # Put strings here, like "/home/html/django_templates" or "C:/www/django/templates".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
)

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'builtins': [],
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

import ldap
from django_auth_ldap.config import LDAPSearch, GroupOfNamesType

AUTH_LDAP_SERVER_URI = "ldaps://lea.cbrp3.c-base.org"
AUTH_LDAP_USER_DN_TEMPLATE = "uid=%(user)s,ou=crew,dc=c-base,dc=org"
AUTH_LDAP_START_TLS = True
AUTH_LDAP_BIND_AS_AUTHENTICATING_USER = True

AUTH_LDAP_CACHE_GROUPS = True
AUTH_LDAP_GROUP_CACHE_TIMEOUT = 300
AUTH_LDAP_MIRROR_GROUPS = True
AUTH_LDAP_GROUP_SEARCH = LDAPSearch(
    "ou=groups,dc=c-base,dc=org",
    ldap.SCOPE_SUBTREE,
    "(objectClass=groupOfNames)",
)
AUTH_LDAP_REQUIRE_GROUP = "cn=crew,ou=groups,dc=c-base,dc=org"
AUTH_LDAP_GROUP_TYPE = GroupOfNamesType(name_attr="cn")
# AUTH_LDAP_PROFILE_FLAGS_BY_GROUP = {
AUTH_LDAP_USER_FLAGS_BY_GROUP = {
    "is_member": "cn=crew,ou=groups,dc=c-base,dc=org",
    "is_ldap_admin": "cn=ldap_admins,ou=groups,dc=c-base,dc=org",
    "is_circle_member": "cn=circle,ou=groups,dc=c-base,dc=org",
    "is_clab_member": "cn=cey-c-lab,ou=groups,dc=c-base,dc=org",
    "is_cey_member": "cn=cey-schleuse,ou=groups,dc=c-base,dc=org",
    "is_ceymaster": "cn=ceymaster,ou=groups,dc=c-base,dc=org",
}

AUTH_LDAP_USER_ATTR_MAP = {
    "first_name": "givenName",
    "last_name": "sn",
    "email": "mail",
}

AUTH_LDAP_PROFILE_ATTR_MAP = {
    "uid": "uidNumber",
    "home_directory": "homeDirectory",
    "sippin": "sipPIN",
    "gastropin": "gastroPIN",
    "rfid": "rfid",
    "macaddress": "macAddress",
    "clabpin": "c-labPIN",
    "preferred_email": "preferredEmail",
}

AUTHENTICATION_BACKENDS = (
    'django_auth_ldap.backend.LDAPBackend',
    'django.contrib.auth.backends.ModelBackend',
)

AUTH_PROFILE_MODULE = "account.UserProfile"

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.admin',
    'django.contrib.admindocs',
    "crispy_forms",
    "crispy_bootstrap4",
    'account',
)

# A sample logging configuration. The only tangible logging
# performed by this configuration is to send an email to
# the site admins on every HTTP 500 error when DEBUG=False.
# See http://docs.djangoproject.com/en/dev/topics/logging for
# more details on how to customize your logging configuration.
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse'
        }
    },
    'handlers': {
        'mail_admins': {
            'level': 'ERROR',
            'filters': ['require_debug_false'],
            'class': 'django.utils.log.AdminEmailHandler'
        },
        "console": {"class": "logging.StreamHandler"}
    },
    'loggers': {
        'django.request': {
            'handlers': ['mail_admins'],
            'level': 'DEBUG',
            'propagate': True,
        },
        "django_auth_ldap": {"level": "DEBUG", "handlers": ["console"]}
    }
}

CRISPY_TEMPLATE_PACK = "bootstrap4"
CRISPY_FAIL_SILENTLY = False

# c-base specific settings
CBASE_LDAP_URL = 'ldaps://lea.cbrp3.c-base.org:389/'
CBASE_BASE_DN = 'ou=crew,dc=c-base,dc=org'

# Set session cookie timeout to 10 minutes
SESSION_COOKIE_AGE = 600
LOGIN_URL = '/account/login/'
# LOCALE_PATHS =

try:
    from cbmi.local_settings import *
except ImportError as e:
    print('Unable to load local_settings.py:', e)
