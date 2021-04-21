#global authorized_users, other_systems
# The following info will allow others to SMS into your system.
authorized_users = {
    'ABC':{
        'mode':'msg_xfer',
        'user':'test_name',
        'password':'passw0rd'
        }
}

# The following info will allow users to access other systems.
access_systems = {
    'XYZ':{
        'mode':'msg_xfer',
        'user':'test_name',
        'password':'passw0rd'
        },
    'APP':{
        'mode':'app',
        'user':'test_name',
        'password':'passw0rd'
        }
}


