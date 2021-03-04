import aprslib
import ast, os

def mailbox_write(call, dmr_id, time, message, recipient):
    mail_file = ast.literal_eval(os.popen('cat ../../gps_data_user_mailbox.txt').read())
    mail_file.insert(0, {'call': call, 'dmr_id': dmr_id, 'time': time, 'message':message, 'recipient': recipient})
    with open("../../gps_data_user_mailbox.txt", 'w') as mailbox_file:
            mailbox_file.write(str(mail_file[:100]))
            mailbox_file.close()
    logger.info('User mail saved.')

def aprs_filter(packet):
    #if aprslib.parse(packet) in aprslib.parse(packet):
     #   print(aprslib.parse(packet))
    #else:
    #    pass
    if aprslib.parse(packet)['to'] in user_settings:
            print(aprslib.parse(packet))
            mailbox_write(aprslib.parse(packet)['from'], aprslib.parse(packet)['to'], time.time(), aprslib.parse(packet)['message_text'], recipient)
            
user_settings = ast.literal_eval(os.popen('cat ../../user_settings.txt').read())
recipient = re.sub('-.*','', aprslib.parse(packet)['to'])
AIS = aprslib.IS("N0CALL", host='rotate.aprs.net')
AIS.connect()
# by default `raw` is False, then each line is ran through aprslib.parse()
AIS.consumer(aprs_filter, raw=True)


