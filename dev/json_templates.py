# Types: App, msg_xfer, raw
# Auth: public, private

import json


msg_xfer = {
    'mode':'msg_xfer',
    'system_name':'ABC',
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
print('App')
print(json_object) 

app_request = {
    'mode':'app',
    'system_name':'ABC',
    'response_url':'http://localhost:8093/api/',
    'auth_token':'1234567899',
    'data':{
            'source_id':1234,
            'destination_id':3153591,
            'slot':2,
            'msg_type':'unit',
            'msg_format':'motorola',
            'message':'text of the message'
            }
}

json_object = json.dumps(app_request, indent = 4)  
print(json_object)

app_response = {
    'mode':'app',
    'system_name':'APP',
    'auth_token':'1234567899',
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

json_object = json.dumps(app_response, indent = 4)  
print(json_object)

msg_xfer = {
    'mode':'raw',
    'system_name':'ABC',
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
