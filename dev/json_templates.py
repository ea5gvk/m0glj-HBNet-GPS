# Types: App, msg_xfer, raw
# Auth: public, private

import json


msg_xfer = {
    'mode':'msg_xfer',
    'system_shortcut':'ABC',
    'server_name':'Test HBlink Network',
    'response_url':'http://localhost:8093/api/',
    'auth_type':'private',
    'credentials': {
        'user':'test_name',
        'password':'passw0rd',
        },
    'data':{
        1:{'source_id':1234,
            'destination_id':3153591,
            'slot':2,
            'msg_type':'unit',
            'msg_format':'motorola',
            'message':'text of the message'
              },
        2:{'source_id':1234,
            'destination_id':3153591,
            'slot':2,
            'msg_type':'unit',
            'msg_format':'motorola',
            'message':'text of the 2nd message'
              }

    }

}

json_object = json.dumps(msg_xfer, indent = 4)
print('-----------------------------------------')
print('msg_xfer')
print(json_object) 
print('-----------------------------------------')

##msg_xfer_public = {
##    'mode':'msg_xfer',
##    'system_shortcut':'ABC',
##    'server_name':'Test HBlink Network',
##    'response_url':'http://localhost:8093/api/',
##    'auth_type':'public',
##    'auth_token':'1234567899',
##    'data':{
##        1:{'source_id':1234,
##            'destination_id':3153591,
##            'slot':2,
##            'msg_type':'unit',
##            'msg_format':'motorola',
##            'message':'text of the message'
##              },
##        2:{'source_id':1234,
##            'destination_id':3153591,
##            'slot':2,
##            'msg_type':'unit',
##            'msg_format':'motorola',
##            'message':'text of the 2nd message'
##              }
##
##    }
##
##}
##
##json_object = json.dumps(msg_xfer_public, indent = 4)
##print('-----------------------------------------')
##print('msg_xfer public')
##print(json_object) 
##print('-----------------------------------------')

app_request = {
    'mode':'app',
    'system_shortcut':'ABC',
    'server_name':'Test HBlink Network',
    'response_url':'http://localhost:8093/api/',
    'auth_token':'1234567899',
    'data':{
            'source_id':1234,
            'slot':2,
            'msg_type':'unit',
            'msg_format':'motorola',
            'message':'text of the message'
            }
}

json_object = json.dumps(app_request, indent = 4)
print('-----------------------------------------')
print('app, request, sent to the APP server')
print(json_object)
print('-----------------------------------------')

app_response = {
    'mode':'app',
    'app_name':'Test HBlink App',
    'app_shortcut':'APP',
    'auth_token':'736a9ced7e7688c951490a7f8e1ebdd4',
    'data':{
        1:{'source_app':'app_name',
            'destination_id':3153591,
            'slot':2,
            'msg_type':'unit',
            'msg_format':'motorola',
            'message':'text of the message'
              },
        2:{'source_id':'app_name',
            'destination_id':3153591,
            'slot':2,
            'msg_type':'unit',
            'msg_format':'motorola',
            'message':'text of the 2nd message'
              }
        }
}

json_object = json.dumps(app_response, indent = 4)
print('-----------------------------------------')
print('app, response, sent to your dashboard')
print(json_object)
print('-----------------------------------------')
raw_msg_xfer = {
    'mode':'raw',
    'system_shortcut':'ABC',
    'response_url':'http://localhost:8093/api/',
    'auth_type':'private',
    'credentials': {
        'user':'test_name',
        'password':'passw0rd',
        },
    'data':{
        1:{'MMDVM Packet 1'},
        2:{'MMDVM Packet 2'}

    }

}
