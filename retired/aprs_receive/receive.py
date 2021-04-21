###############################################################################
#   GPS/Data - Copyright (C) 2020 Eric Craw, KF7EEL <kf7eel@qsl.net>
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software Foundation,
#   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
###############################################################################

import aprslib
import ast, os
import re
from configparser import ConfigParser
import time
import argparse

def mailbox_write(call, dmr_id, time, message, recipient):
    global mailbox_file
    mail_file = ast.literal_eval(os.popen('cat ' + parser.get('GPS_DATA', 'MAILBOX_FILE')).read())
    mail_file.insert(0, {'call': call, 'dmr_id': dmr_id, 'time': time, 'message':message, 'recipient': recipient})
    with open(parser.get('GPS_DATA', 'MAILBOX_FILE'), 'w') as mailbox_file:
            mailbox_file.write(str(mail_file[:100]))
            mailbox_file.close()
    print('User mail saved.')

def aprs_filter(packet):

    user_settings = ast.literal_eval(os.popen('cat ' + user_settings_file).read())
    if 'addresse' in aprslib.parse(packet):
        #print(aprslib.parse(packet))
        recipient = re.sub('-.*','', aprslib.parse(packet)['addresse'])
        recipient_ssid = re.sub('.*-','', aprslib.parse(packet)['addresse'])
        if recipient == '':
            pass
        else:
            for i in user_settings.items():
                ssid = i[1][1]['ssid']
                if i[1][1]['ssid'] == '':
                    ssid = user_aprs_ssid
                if recipient in i[1][0]['call'] and recipient_ssid in ssid:
                    mailbox_write(re.sub('-.*','', aprslib.parse(packet)['addresse']), aprslib.parse(packet)['from'], time.time(), aprslib.parse(packet)['message_text'], recipient)
                    if 'msgNo' in aprslib.parse(packet):
                        time.sleep(1)
                        AIS.sendall(aprslib.parse(packet)['addresse'] + '>APHBL3,TCPIP*:' + ':' + aprslib.parse(packet)['from'].ljust(9) +':ack'+aprslib.parse(packet)['msgNo'])
                        print('Send ACK')
                        print(aprslib.parse(packet)['addresse'] + '>APHBL3,TCPIP*:' + ':' + aprslib.parse(packet)['from'].ljust(9) +':ack'+aprslib.parse(packet)['msgNo'])

##    else:
##        print(aprslib.parse(packet)['from'])

if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('-c', '--config', action='store', dest='CONFIG_FILE', help='/full/path/to/config.file (usually gps_data.cfg)')
    cli_args = arg_parser.parse_args()
    parser = ConfigParser()
    if not cli_args.CONFIG_FILE:
        print('\n\nMust specify a config file with -c argument.\n\n')
    parser.read(cli_args.CONFIG_FILE)

    aprs_server = parser.get('GPS_DATA', 'APRS_SERVER')
    aprs_port = parser.get('GPS_DATA', 'APRS_PORT')
    aprs_login = parser.get('GPS_DATA', 'APRS_RECEIVE_LOGIN_CALL')
    aprs_passcode = parser.get('GPS_DATA', 'APRS_LOGIN_PASSCODE')
    mailbox_file = parser.get('GPS_DATA', 'MAILBOX_FILE')
    user_settings_file = parser.get('GPS_DATA', 'USER_SETTINGS_FILE')
    user_aprs_ssid = parser.get('GPS_DATA', 'USER_APRS_SSID')

    AIS = aprslib.IS(aprs_login, passwd=int(aprs_passcode), host=aprs_server, port=int(aprs_port))
    user_settings = ast.literal_eval(os.popen('cat ' + user_settings_file).read())
    print('APRS message receive script for GPS/Data Application.\nAuthor: Eric, KF7EEL - kf7eel@qsl.net')
    AIS.set_filter(parser.get('GPS_DATA', 'APRS_FILTER'))
    AIS.connect()
    print('Connecting to APRS-IS')
    AIS.consumer(aprs_filter, raw=True)


