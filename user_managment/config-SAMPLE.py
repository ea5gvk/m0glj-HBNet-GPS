
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


# Gateway contact info displayed on about page.
contact_name = 'your name'
contact_call = 'N0CALL'
contact_email = 'email@example.org'
contact_website = 'https://hbl.ink'

# Time format for display
time_format = '%H:%M:%S - %m/%d/%y'

