
'''
Settings for user management portal.
'''
# Database location
db_location = 'sqlite:///./users.db'

# Legacy passphrase used in hblink.cfg
legacy_passphrase = 'passw0rd'

# Trim passphrases to 8 characters
use_short_passphrase = False

# Title of the Dashboard
title = 'MMDVM User Portal'
# Port to run server
ums_port = 8080
# IP to run server on
ums_host = '127.0.0.1'

url = 'http://localhost:8080'

append_int = 1

shared_secrets = ['test']


burn_int = 5

legacy_passphrase = 'passw0rd'

# Email settings
MAIL_SERVER = 'smtp.gmail.com'
MAIL_PORT = 465
MAIL_USE_SSL = True
MAIL_USE_TLS = False
MAIL_USERNAME = 'app@gmail.com'
MAIL_PASSWORD = 'password'
MAIL_DEFAULT_SENDER = '"' + title + '" <app@gmail.com>'

# UMS settings
secret_key = 'SUPER SECRET LONG KEY'

USER_ENABLE_EMAIL = True
USER_ENABLE_USERNAME = True    # Enable username authentication
USER_REQUIRE_RETYPE_PASSWORD = True    # Simplify register form
USER_ENABLE_CHANGE_USERNAME = False
USER_ENABLE_MULTIPLE_EMAILS = True
USER_ENABLE_CONFIRM_EMAIL = True
USER_ENABLE_REGISTER = True
USER_AUTO_LOGIN_AFTER_CONFIRM = False
USER_SHOW_USERNAME_DOES_NOT_EXIST = True

# Gateway contact info displayed on about page.
contact_name = 'your name'
contact_call = 'N0CALL'
contact_email = 'email@example.org'
contact_website = 'https://hbl.ink'

# Time format for display
time_format = '%H:%M:%S - %m/%d/%y'

