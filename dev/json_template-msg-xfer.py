# Types: App, s2s_msg
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
print(json_object) 

