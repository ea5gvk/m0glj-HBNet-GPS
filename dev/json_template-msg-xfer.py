# Types: App, s2s_msg

msg_xfer = {
    'mode':'msg_xfer',
    'type':'s2s_msg',
    'response_url':'http://localhost:8093/api/',
    'user':'test_name',
    'password':'passw0rd',
    'data':{'source_id':1234567,
            'destination_id':7654321,
            'slot':2,
            'msg_type':'unit',
            'msg_format':'motorola',
            'message':'text of the message'

    }

}

print(msg_xfer['data']['slot'])
