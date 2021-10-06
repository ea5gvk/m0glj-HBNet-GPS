#!/usr/bin/env python3
#
###############################################################################
#   HBLink - Copyright (C) 2020 Cortney T. Buffington, N0MJS <n0mjs@me.com>
#   GPS/Data - Copyright (C) 2020 Eric Craw, KF7EEL <kf7eel@qsl.net>
#   Annotated modifications Copyright (C) 2021 Xavier FRS2013
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

'''
This is a data application. It decodes and reassambles DMR GPS packets and
uploads them to APRS-IS. Also does miscelaneous SMS functions.
'''

# Python modules we need
import sys
from bitarray import bitarray
from time import time, strftime
from importlib import import_module

# Twisted is pretty important, so I keep it separate
from twisted.internet.protocol import Factory, Protocol
from twisted.protocols.basic import NetstringReceiver
from twisted.internet import reactor, task

# Things we import from the main hblink module
from hblink import HBSYSTEM, OPENBRIDGE, systems, hblink_handler, reportFactory, REPORT_OPCODES, mk_aliases, config_reports
from dmr_utils3.utils import bytes_3, int_id, get_alias, bytes_4
from dmr_utils3 import decode, bptc, const
import data_gateway_config
import log
from const import *

# Stuff for socket reporting
import pickle
# REMOVE LATER from datetime import datetime
# The module needs logging, but handlers, etc. are controlled by the parent
import logging
logger = logging.getLogger(__name__)

#### Modules for data gateway ###
# modules from DATA_CONFIG.py
from bitarray import bitarray
from binascii import b2a_hex as ahex
import re
##from binascii import a2b_hex as bhex
import aprslib
import datetime
from bitarray.util import ba2int as ba2num
from bitarray.util import ba2hex as ba2hx
import codecs
#Needed for working with NMEA
import pynmea2

# Used with HTTP POST
from hashlib import sha256
import json, requests


# Modules for executing commands/scripts
import os
##from gps_functions import cmd_list

# Module for maidenhead grids
try:
    import maidenhead as mh
except:
    logger.info('Error importing maidenhead module, make sure it is installed.')
# Module for sending email
try:
    import smtplib
except:
    logger.info('Error importing smtplib module, make sure it is installed.')

#Modules for APRS settings
import ast
from pathlib import Path
# Used for APRS
import threading
# Used for SMS encoding
import libscrc
import random
from bitarray.util import hex2ba as hex2bits
import traceback

#################################


# Does anybody read this stuff? There's a PEP somewhere that says I should do this.
__author__     = 'Cortney T. Buffington, N0MJS, Eric Craw, KF7EEL, kf7eel@qsl.net'
__copyright__  = 'Copyright (c) 2016-2019 Cortney T. Buffington, N0MJS and the K0USY Group, Copyright (c) 2020-2021, Eric Craw, KF7EEL'
__credits__    = 'Colin Durbridge, G4EML, Steve Zingman, N4IRS; Mike Zingman, N4IRR; Jonathan Naylor, G4KLX; Hans Barthen, DL5DI; Torsten Shultze, DG1HT'
__license__    = 'GNU GPLv3'
__maintainer__ = 'Eric Craw, KF7EEL'
__email__      = 'kf7eel@qsl.net'


def ping(CONFIG):
    user_man_url = CONFIG['WEB_SERVICE']['URL']
    shared_secret = str(sha256(CONFIG['WEB_SERVICE']['SHARED_SECRET'].encode()).hexdigest())
    ping_data = {
    'ping': CONFIG['WEB_SERVICE']['THIS_SERVER_NAME'],
    'secret':shared_secret
    }
    json_object = json.dumps(ping_data, indent = 4)
    
    try:
        req = requests.post(user_man_url, data=json_object, headers={'Content-Type': 'application/json'})
##        resp = json.loads(req.text)
##        print(resp)
##        return resp['rules']
    except requests.ConnectionError:
        logger.error('Config server unreachable')
##        return config.build_config(cli_file)


def send_dash_loc(CONFIG, call, lat, lon, time, comment, dmr_id):
    user_man_url = CONFIG['WEB_SERVICE']['URL']
    shared_secret = str(sha256(CONFIG['WEB_SERVICE']['SHARED_SECRET'].encode()).hexdigest())
    loc_data = {
    'dashboard': CONFIG['WEB_SERVICE']['THIS_SERVER_NAME'],
    'secret':shared_secret,
    'call': call,
    'lat' : lat,
    'lon' : lon,
    'comment' : comment,
    'dmr_id' : dmr_id
    }
    json_object = json.dumps(loc_data, indent = 4)
    
    try:
        req = requests.post(user_man_url, data=json_object, headers={'Content-Type': 'application/json'})
##        resp = json.loads(req.text)
##        print(resp)
##        return resp['rules']
    except requests.ConnectionError:
        logger.error('Config server unreachable')

def send_sms_log(CONFIG, snd_call, rcv_call, msg, rcv_id, snd_id, system_name):
    user_man_url = CONFIG['WEB_SERVICE']['URL']
    shared_secret = str(sha256(CONFIG['WEB_SERVICE']['SHARED_SECRET'].encode()).hexdigest())
    sms_data = {
    'log_sms': CONFIG['WEB_SERVICE']['THIS_SERVER_NAME'],
    'secret':shared_secret,
    'snd_call': snd_call,
    'rcv_call': rcv_call,
    'message' : msg,
    'snd_id' : snd_id,
    'rcv_id' : rcv_id,
    'system_name': system_name
    }
    json_object = json.dumps(sms_data, indent = 4)
    
    try:
        req = requests.post(user_man_url, data=json_object, headers={'Content-Type': 'application/json'})
##        resp = json.loads(req.text)
##        print(resp)
##        return resp['rules']
    except requests.ConnectionError:
        logger.error('Config server unreachable')

def send_bb(CONFIG, callsign, dmr_id, bulletin, system_name):
    user_man_url = CONFIG['WEB_SERVICE']['URL']
    shared_secret = str(sha256(CONFIG['WEB_SERVICE']['SHARED_SECRET'].encode()).hexdigest())
    sms_data = {
    'bb_send': CONFIG['WEB_SERVICE']['THIS_SERVER_NAME'],
    'secret':shared_secret,
    'callsign': callsign,
    'dmr_id': dmr_id,
    'bulletin': bulletin,
    'system_name' : system_name
    }
    json_object = json.dumps(sms_data, indent = 4)
    
    try:
        req = requests.post(user_man_url, data=json_object, headers={'Content-Type': 'application/json'})
##        resp = json.loads(req.text)
##        print(resp)
##        return resp['rules']
    except requests.ConnectionError:
        logger.error('Config server unreachable')

        
def send_ss(CONFIG, callsign, message, dmr_id):
    user_man_url = CONFIG['WEB_SERVICE']['URL']
    shared_secret = str(sha256(CONFIG['WEB_SERVICE']['SHARED_SECRET'].encode()).hexdigest())
    sms_data = {
    'ss_update': CONFIG['WEB_SERVICE']['THIS_SERVER_NAME'],
    'secret':shared_secret,
    'callsign': callsign,
    'message' : message,
    'dmr_id' : dmr_id,

    }
    json_object = json.dumps(sms_data, indent = 4)
    
    try:
        req = requests.post(user_man_url, data=json_object, headers={'Content-Type': 'application/json'})
##        resp = json.loads(req.text)
##        print(resp)
##        return resp['rules']
    except requests.ConnectionError:
        logger.error('Config server unreachable')




##################################################################################################

# Headers for GPS by model of radio:
# AT-D878 - Compressed UDP
# MD-380 - Unified Data Transport
hdr_type = ''
btf = -1
ssid = ''
UNIT_MAP = {}
PACKET_MATCH = {}

# From dmr_utils3, modified to decode entire packet. Works for 1/2 rate coded data. 
def decode_full(_data):
    binlc = bitarray(endian='big')   
    binlc.extend([_data[136],_data[121],_data[106],_data[91], _data[76], _data[61], _data[46], _data[31]])
    binlc.extend([_data[152],_data[137],_data[122],_data[107],_data[92], _data[77], _data[62], _data[47], _data[32], _data[17], _data[2]  ])
    binlc.extend([_data[123],_data[108],_data[93], _data[78], _data[63], _data[48], _data[33], _data[18], _data[3],  _data[184],_data[169]])
    binlc.extend([_data[94], _data[79], _data[64], _data[49], _data[34], _data[19], _data[4],  _data[185],_data[170],_data[155],_data[140]])
    binlc.extend([_data[65], _data[50], _data[35], _data[20], _data[5],  _data[186],_data[171],_data[156],_data[141],_data[126],_data[111]])
    binlc.extend([_data[36], _data[21], _data[6],  _data[187],_data[172],_data[157],_data[142],_data[127],_data[112],_data[97], _data[82] ])
    binlc.extend([_data[7],  _data[188],_data[173],_data[158],_data[143],_data[128],_data[113],_data[98], _data[83]])
    #This is the rest of the Full LC data -- the RS1293 FEC that we don't need
    # This is extremely important for SMS and GPS though.
    binlc.extend([_data[68],_data[53],_data[174],_data[159],_data[144],_data[129],_data[114],_data[99],_data[84],_data[69],_data[54],_data[39]])
    binlc.extend([_data[24],_data[145],_data[130],_data[115],_data[100],_data[85],_data[70],_data[55],_data[40],_data[25],_data[10],_data[191]])
    return binlc
   

n_packet_assembly = 0

packet_assembly = ''

final_packet = ''

#Convert DMR packet to binary from MMDVM packet and remove Slot Type and EMB Sync stuff to allow for BPTC 196,96 decoding
def bptc_decode(_data):
        binary_packet = bitarray(decode.to_bits(_data[20:]))
        del binary_packet[98:166]
        return decode_full(binary_packet)
# Placeholder for future header id
def header_ID(_data):
    hex_hdr = str(ahex(bptc_decode(_data)))
    return hex_hdr[2:6]
    # Work in progress, used to determine data format
##    pass

def aprs_send(packet):
    if 'N0CALL' in aprs_callsign:
        logger.info('APRS callsighn set to N0CALL, packet not sent.')
        pass
    else:
        AIS.sendall(packet)
        logger.info('Packet sent to APRS-IS.')

def dashboard_loc_write(call, lat, lon, time, comment, dmr_id):
    if CONFIG['WEB_SERVICE']['REMOTE_CONFIG_ENABLED'] == True:
        send_dash_loc(CONFIG, call, lat, lon, time, comment, dmr_id)
    else:
        dash_entries = ast.literal_eval(os.popen('cat ' + loc_file).read())
        dash_entries.insert(0, {'call': call, 'lat': lat, 'lon': lon, 'time':time, 'comment':comment})
    # Clear old entries
        list_index = 0
        call_count = 0
        new_dash_entries = []
        for i in dash_entries:
            if i['call'] == call:
                if call_count >= 25:
                    pass
                else:
                    new_dash_entries.append(i)
                call_count = call_count + 1

            if call != i['call']:
                new_dash_entries.append(i)
                pass
            list_index = list_index + 1
        with open(loc_file, 'w') as user_loc_file:
                user_loc_file.write(str(new_dash_entries[:500]))
                user_loc_file.close()
    logger.info('User location saved for dashboard')
    #logger.info(dash_entries)
    
def dashboard_bb_write(call, dmr_id, time, bulletin, system_name):
    if CONFIG['WEB_SERVICE']['REMOTE_CONFIG_ENABLED'] == True:
        send_bb(CONFIG, call, dmr_id, bulletin, system_name)
    else:
        #try:
        dash_bb = ast.literal_eval(os.popen('cat ' + bb_file).read())
       # except:
        #    dash_entries = []
        dash_bb.insert(0, {'call': call, 'dmr_id': dmr_id, 'time': time, 'bulletin':bulletin})
        with open(bb_file, 'w') as user_bb_file:
                user_bb_file.write(str(dash_bb[:20]))
                user_bb_file.close()
        logger.info('User bulletin entry saved.')
        #logger.info(dash_bb)

def dashboard_sms_write(snd_call, rcv_call, rcv_dmr_id, snd_dmr_id, sms, time, system_name):
    if CONFIG['WEB_SERVICE']['REMOTE_CONFIG_ENABLED'] == True:
        send_sms_log(CONFIG, snd_call, rcv_call, sms, rcv_dmr_id, snd_dmr_id, system_name)
    else:
        #try:
        dash_sms = ast.literal_eval(os.popen('cat ' + sms_file).read())
       # except:
        #    dash_entries = []
        dash_sms.insert(0, {'snd_call': snd_call, 'rcv_call':rcv_call, 'snd_dmr_id': snd_dmr_id, 'rcv_dmr_id':rcv_dmr_id, 'time': time, 'sms':sms})
        with open(sms_file, 'w') as user_sms_file:
                user_sms_file.write(str(dash_sms[:25]))
                user_sms_file.close()
        logger.info('User SMS entry saved.')


def mailbox_write(call, dmr_id, time, message, recipient):
    #try:
    mail_file = ast.literal_eval(os.popen('cat ' + the_mailbox_file).read())
    mail_file.insert(0, {'call': call, 'dmr_id': dmr_id, 'time': time, 'message':message, 'recipient': recipient})
    with open(the_mailbox_file, 'w') as mailbox_file:
            mailbox_file.write(str(mail_file[:100]))
            mailbox_file.close()
    logger.info('User mail saved.')

def mailbox_delete(dmr_id):
    mail_file = ast.literal_eval(os.popen('cat ' + the_mailbox_file).read())
    call = str(get_alias((dmr_id), subscriber_ids))
    new_data = []
    for message in mail_file:
        if message['recipient'] != call:
            new_data.append(message)
    with open(the_mailbox_file, 'w') as mailbox_file:
            mailbox_file.write(str(new_data[:100]))
            mailbox_file.close()
    logger.info('Mailbox updated. Delete occurred.')


def sos_write(dmr_id, time, message):
    user_settings = ast.literal_eval(os.popen('cat ' + user_settings_file).read())
    try:
        if user_settings[dmr_id][1]['ssid'] == '':
            sos_call = user_settings[dmr_id][0]['call'] + '-' + user_ssid
        else:
            sos_call = user_settings[dmr_id][0]['call'] + '-' + user_settings[dmr_id][1]['ssid']
    except:
        sos_call = str(get_alias((dmr_id), subscriber_ids))
    sos_info = {'call': sos_call, 'dmr_id': dmr_id, 'time': time, 'message':message}
    with open(emergency_sos_file, 'w') as sos_file:
            sos_file.write(str(sos_info))
            sos_file.close()
    logger.info('Saved SOS.')
def send_app_request(url, message, source_id):
    #url = url + '/app'
    #Load current AUTH token list
    auth_file = ast.literal_eval(os.popen('cat ' + auth_token_file).read())
    the_token = str(hashlib.md5(str(time()).encode('utf-8')).hexdigest())
    new_auth_file = auth_file
    new_auth_file.append(the_token)
    # Write new list to file
    with open(auth_token_file, 'w') as auth_token:
        auth_token.write(str(auth_file))
        auth_token.close()
    app_request = {
    'mode':'app',
    'system_shortcut':CONFIG['DATA_CONFIG']['MY_SERVER_SHORTCUT'],
    'server_name':CONFIG['DATA_CONFIG']['SERVER_NAME'],
    'response_url':CONFIG['DATA_CONFIG']['DASHBOARD_URL'] + '/api',
    'auth_token':the_token,
    'data':{
            'source_id':source_id,
            'slot':0,
            'msg_type':'unit',
            'msg_format':'motorola',
            'message':message
            }
    }
    json_object = json.dumps(app_request, indent = 4)
    print(json_object)
    requests.post(url, data=json_object, headers={'Content-Type': 'application/json'})

    
def send_msg_xfer(url, user, password, message, source_id, dest_id):
    url = url + '/api/msg_xfer'
    msg_xfer = {
    'mode':'msg_xfer',
    'system_shortcut':CONFIG['DATA_CONFIG']['MY_SERVER_SHORTCUT'],
    'response_url':CONFIG['DATA_CONFIG']['DASHBOARD_URL'] + '/api',
    'auth_type':'private',
    'credentials': {
        'user':user,
        'password':password,
        },
    'data':{
            1:{'source_id':source_id,
                'destination_id':dest_id,
                'slot':0,
                'msg_type':'unit',
                'msg_format':'motorola',
                'message':message
               }
           }
    }
    json_object = json.dumps(msg_xfer, indent = 4)
    requests.post(url, data=json_object, headers={'Content-Type': 'application/json'})


# Send email via SMTP function
def send_email(to_email, email_subject, email_message):
    global smtp_server
    sender_address = email_sender
    account_password = email_password
    smtp_server = smtplib.SMTP_SSL(smtp_server, int(smtp_port))
    smtp_server.login(sender_address, account_password)
    message = "From: " + aprs_callsign + " D-APRS Gateway\nTo: " + to_email + "\nContent-type: text/html\nSubject: " + email_subject + "\n\n" + '<strong>' + email_subject + '</strong><p>&nbsp;</p><h3>' + email_message + '</h3><p>&nbsp;</p><p>This message was sent to you from a D-APRS gateway operated by <strong>' + aprs_callsign + '</strong>. Do not reply as this gateway is only one way at this time.</p>'
    smtp_server.sendmail(sender_address, to_email, message)
    smtp_server.close()

def generate_apps():
    global access_systems
    #local_apps = ast.literal_eval(os.popen('cat ' + access_systems_file).read())
    public_systems_file = requests.get(CONFIG['DATA_CONFIG']['PUBLIC_APPS_LIST'])
    public_apps = ast.literal_eval(public_systems_file.text)
    access_systems = {}
    #combined = public_apps.items() + local_acess_systems.items()
    if CONFIG['DATA_CONFIG']['USE_PUBLIC_APPS'] == True:
        for i in public_apps.items():
            key = str(i[0])
            access_systems[key] = i[1]
    for i in local_apps.items():
        key = str(i[0])
        access_systems[key] = i[1]
    print(access_systems)
    
    return access_systems

# Thanks for this forum post for this - https://stackoverflow.com/questions/2579535/convert-dd-decimal-degrees-to-dms-degrees-minutes-seconds-in-python

def decdeg2dms(dd):
   is_positive = dd >= 0
   dd = abs(dd)
   minutes,seconds = divmod(dd*3600,60)
   degrees,minutes = divmod(minutes,60)
   degrees = degrees if is_positive else -degrees
   return (degrees,minutes,seconds)

def user_setting_write(dmr_id, setting, value, call_type):
##    try:
    # Open file and load as dict for modification
        logger.info(setting.upper())
        with open(user_settings_file, 'r') as f:
##            if f.read() == '{}':
##                user_dict = {}
            user_dict = ast.literal_eval(f.read())
            logger.info('Current settings: ' + str(user_dict))
            if dmr_id not in user_dict:
                user_dict[dmr_id] = [{'call': str(get_alias((dmr_id), subscriber_ids))}, {'ssid': ''}, {'icon': ''}, {'comment': ''}, {'pin': ''}, {'APRS': False}]
            if setting.upper() == 'ICON':
                user_dict[dmr_id][2]['icon'] = value
            if setting.upper() == 'SSID':
                user_dict[dmr_id][1]['ssid'] = value  
            if setting.upper() == 'COM':
                user_comment = user_dict[dmr_id][3]['comment'] = value[0:35]
            if setting.upper() == 'APRS ON':
                user_dict[dmr_id][5] = {'APRS': True}
                if call_type == 'unit':
                    send_sms(False, dmr_id, 0000, 0000, 'unit', 'APRS MSG TX/RX Enabled')
                if call_type == 'vcsbk':
                    send_sms(False, 9, 0000, 0000, 'group', 'APRS MSG TX/RX Enabled')
            if setting.upper() == 'APRS OFF':
                user_dict[dmr_id][5] = {'APRS': False}
                if call_type == 'unit':
                    send_sms(False, dmr_id, 0000, 0000, 'unit', 'APRS MSG TX/RX Disabled')
                if call_type == 'vcsbk':
                    send_sms(False, 9, 0000, 0000, 'group', 'APRS MSG TX/RX Disabled')
            if setting.upper() == 'PIN':
                #try:
                    #if user_dict[dmr_id]:
                user_dict[dmr_id][4]['pin'] = value
                if call_type == 'unit':
                    send_sms(False, dmr_id, 0000, 0000, 'unit',  'You can now use your pin on the dashboard.')
                if call_type == 'vcsbk':
                    send_sms(False, 9, 0000, 0000, 'group',  'You can now use your pin on the dashboard.')
                    #if not user_dict[dmr_id]:
                    #    user_dict[dmr_id] = [{'call': str(get_alias((dmr_id), subscriber_ids))}, {'ssid': ''}, {'icon': ''}, {'comment': ''}, {'pin': pin}]
                #except:
                #    user_dict[dmr_id].append({'pin': value})
            f.close()
            logger.info('Loaded user settings. Write changes.')
    # Write modified dict to file
        with open(user_settings_file, 'w') as user_dict_file:
            user_dict_file.write(str(user_dict))
            user_dict_file.close()
            logger.info('User setting saved')
            f.close()
            packet_assembly = ''
            
# Process SMS, do something bases on message

def process_sms(_rf_src, sms, call_type, system_name):
    logger.info(call_type)
    parse_sms = sms.split(' ')
    logger.info(parse_sms)
    if '@SS' in parse_sms[0]:
        s = ' '
        post = s.join(parse_sms[1:])
        send_ss(CONFIG, str(get_alias(int_id(_rf_src), subscriber_ids)), post, int_id(_rf_src))
    elif parse_sms[0] == 'ID':
        logger.info(str(get_alias(int_id(_rf_src), subscriber_ids)) + ' - ' + str(int_id(_rf_src)))
        if call_type == 'unit':
            send_sms(False, int_id(_rf_src), 0000, 0000, 'unit', 'Your DMR ID: ' + str(int_id(_rf_src)) + ' - ' + str(get_alias(int_id(_rf_src), subscriber_ids)))
        if call_type == 'vcsbk':
            send_sms(False, 9, 0000, 0000, 'group', 'Your DMR ID: ' + str(int_id(_rf_src)) + ' - ' + str(get_alias(int_id(_rf_src), subscriber_ids)))
    elif parse_sms[0] == 'TEST':
        logger.info('It works!')
        if call_type == 'unit':
            send_sms(False, int_id(_rf_src), 0000, 0000, 'unit',  'It works')
        if call_type == 'vcsbk':
            send_sms(False, 9, 0000, 0000, 'group',  'It works')
    elif '@ICON' in parse_sms[0]:
        user_setting_write(int_id(_rf_src), re.sub(' .*|@','',sms), re.sub('@ICON| ','',sms), call_type)
    elif '@SSID' in parse_sms[0]:
        user_setting_write(int_id(_rf_src), re.sub(' .*|@','',sms), re.sub('@SSID| ','',sms), call_type)
    elif '@COM' in parse_sms[0]:
        user_setting_write(int_id(_rf_src), re.sub(' .*|@','',sms), re.sub('@COM |@COM','',sms), call_type)
    elif '@PIN' in parse_sms[0]:
        user_setting_write(int_id(_rf_src), re.sub(' .*|@','',sms), int(re.sub('@PIN |@PIN','',sms)), call_type)    
    # Write blank entry to cause APRS receive to look for packets for this station.
    elif '@APRS ON' in sms or '@APRS on' in sms:
        user_setting_write(int_id(_rf_src), 'APRS ON', True, call_type)
    elif '@APRS OFF' in sms or '@APRS off' in sms:
        user_setting_write(int_id(_rf_src), 'APRS OFF', False, call_type)
    elif '@BB' in sms:
        dashboard_bb_write(get_alias(int_id(_rf_src), subscriber_ids), int_id(_rf_src), time(), re.sub('@BB|@BB ','',sms), system_name)
    elif '@' in parse_sms[0][1:] and '.' in parse_sms[0]: # and ' E-' in sms:
        s = ' '
        email_message =  s.join(parse_sms[1:])#str(re.sub('.*@|.* E-', '', sms))
        to_email = parse_sms[0]#str(re.sub(' E-.*', '', sms))
        email_subject = 'New message from ' + str(get_alias(int_id(_rf_src), subscriber_ids))
        logger.info('Email to: ' + to_email)
        logger.info('Message: ' + email_message)
        try:
            send_email(to_email, email_subject, email_message)
            logger.info('Email sent.')
        except Exception as error_exception:
            logger.info('Failed to send email.')
            logger.info(error_exception)
            logger.info(str(traceback.extract_tb(error_exception.__traceback__)))
    elif '@SOS' in sms or '@NOTICE' in sms:
        sos_write(int_id(_rf_src), time(), sms)
    elif '@REM SOS' == sms:
        os.remove(emergency_sos_file)
        logger.info('Removing SOS or Notice')
    elif '@' in parse_sms[0][0:1] and 'M-' in parse_sms[1][0:2]:
        message = re.sub('^@|.* M-|','',sms)
        recipient = re.sub('@| M-.*','',sms)
        mailbox_write(get_alias(int_id(_rf_src), subscriber_ids), int_id(_rf_src), time(), message, str(recipient).upper())
    elif '@REM MAIL' == sms:
        mailbox_delete(_rf_src)
    elif '@MH' in parse_sms[0]:
        grid_square = re.sub('@MH ', '', sms)
        if len(grid_square) < 6:
            pass
        else:
            lat = decdeg2dms(mh.to_location(grid_square)[0])
            lon = decdeg2dms(mh.to_location(grid_square)[1])
            
            if lon[0] < 0:
                lon_dir = 'W'
            if lon[0] > 0:
                lon_dir = 'E'
            if lat[0] < 0:
                lat_dir = 'S'
            if lat[0] > 0:
                lat_dir = 'N'
            #logger.info(lat)
            #logger.info(lat_dir)
            aprs_lat = str(str(re.sub('\..*|-', '', str(lat[0]))) + str(re.sub('\..*', '', str(lat[1])) + '.')).zfill(5) + '  ' + lat_dir
            aprs_lon = str(str(re.sub('\..*|-', '', str(lon[0]))) + str(re.sub('\..*', '', str(lon[1])) + '.')).zfill(6) + '  ' + lon_dir
        logger.info('Latitude: ' + str(aprs_lat))
        logger.info('Longitude: ' + str(aprs_lon))
        # 14FRS2013 simplified and moved settings retrieval
        user_settings = ast.literal_eval(os.popen('cat ' + user_settings_file).read())	
        if int_id(_rf_src) not in user_settings:	
            ssid = str(user_ssid)	
            icon_table = '/'	
            icon_icon = '['	
            comment = aprs_comment + ' DMR ID: ' + str(int_id(_rf_src)) 	
        else:	
            if user_settings[int_id(_rf_src)][1]['ssid'] == '':	
                ssid = user_ssid	
            if user_settings[int_id(_rf_src)][3]['comment'] == '':	
                comment = aprs_comment + ' DMR ID: ' + str(int_id(_rf_src))	
            if user_settings[int_id(_rf_src)][2]['icon'] == '':	
                icon_table = '/'	
                icon_icon = '['	
            if user_settings[int_id(_rf_src)][2]['icon'] != '':	
                icon_table = user_settings[int_id(_rf_src)][2]['icon'][0]	
                icon_icon = user_settings[int_id(_rf_src)][2]['icon'][1]	
            if user_settings[int_id(_rf_src)][1]['ssid'] != '':	
                ssid = user_settings[int_id(_rf_src)][1]['ssid']	
            if user_settings[int_id(_rf_src)][3]['comment'] != '':	
                comment = user_settings[int_id(_rf_src)][3]['comment']	
        aprs_loc_packet = str(get_alias(int_id(_rf_src), subscriber_ids)) + '-' + ssid + '>APHBL3,TCPIP*:@' + str(datetime.datetime.utcnow().strftime("%H%M%Sh")) + str(aprs_lat) + icon_table + str(aprs_lon) + icon_icon + '/' + str(comment)
        logger.info(aprs_loc_packet)
        logger.info('User comment: ' + comment)
        logger.info('User SSID: ' + ssid)
        logger.info('User icon: ' + icon_table + icon_icon)
        try:
            aprslib.parse(aprs_loc_packet)
            aprs_send(aprs_loc_packet)
            dashboard_loc_write(str(get_alias(int_id(_rf_src), subscriber_ids)) + '-' + ssid, aprs_lat, aprs_lon, time(), comment, int_id(_rf_src))
            #logger.info('Sent manual position to APRS')
        except Exception as error_exception:
            logger.info('Exception. Not uploaded')
            logger.info(error_exception)
            logger.info(str(traceback.extract_tb(error_exception.__traceback__)))
        packet_assembly = ''
          
    elif '?' in parse_sms[0][0:1]:
        use_api = CONFIG['DATA_CONFIG']['USE_API']
        print(use_api)
        if use_api == True:
            auth_tokens = ast.literal_eval(os.popen('cat ' + auth_token_file).read())
            #access_systems = ast.literal_eval(os.popen('cat ' + access_systems_file).read())
            #authorized_users = ast.literal_eval(os.popen('cat ' + authorized_users_file).read())
            system = parse_sms[0][1:]
            #print(access_systems[system])
            #print(authorized_users)
            # Determin msg_xfer or app
            if access_systems[system]['mode'] == 'msg_xfer':
                s = ' '
                message_to_send = s.join(parse_sms[2:])
                dest_id = int(parse_sms[1])
                source_id = int_id(_rf_src)
                send_msg_xfer(access_systems[system]['url'], access_systems[system]['user'], access_systems[system]['password'], message_to_send, source_id, dest_id)
            if access_systems[system]['mode'] == 'app':
                s = ' '
                message_to_send = s.join(parse_sms[1:])
                source_id = int_id(_rf_src)
                send_app_request(access_systems[system]['url'], message_to_send, source_id)
                
                
        if use_api == False:
            if call_type == 'unit':
                send_sms(False, int_id(_rf_src), 0000, 0000, 'unit', 'API not enabled. Contact server admin.')
            if call_type == 'vcsbk':
                send_sms(False, 9, 0000, 0000, 'group', 'API not enabled. Contact server admin.')

    elif '@' in parse_sms[0][0:1] and 'M-' not in parse_sms[1][0:2] or '@' not in parse_sms[0][1:]:
        #Example SMS text: @ARMDS A-This is a test.
        s = ' '
        aprs_dest = re.sub('@', '', parse_sms[0])#re.sub('@| A-.*','',sms)
        aprs_msg = s.join(parse_sms[1:])#re.sub('^@|.* A-|','',sms)
        logger.info(aprs_msg)
        logger.info('APRS message to ' + aprs_dest.upper() + '. Message: ' + aprs_msg)
        user_settings = ast.literal_eval(os.popen('cat ' + user_settings_file).read())
        if int_id(_rf_src) in user_settings and user_settings[int_id(_rf_src)][1]['ssid'] != '':
            ssid = user_settings[int_id(_rf_src)][1]['ssid']
        else:
            ssid = user_ssid
        try:
            if user_settings[int_id(_rf_src)][5]['APRS'] == True:
                aprs_msg_pkt = str(get_alias(int_id(_rf_src), subscriber_ids)) + '-' + str(ssid) + '>APHBL3,TCPIP*::' + str(aprs_dest).ljust(9).upper() + ':' + aprs_msg[0:73]
                logger.info(aprs_msg_pkt)
                try:
                    aprslib.parse(aprs_msg_pkt)
                    aprs_send(aprs_msg_pkt)
                    #logger.info('Packet sent.')
                except Exception as error_exception:
                    logger.info('Error uploading MSG packet.')
                    logger.info(error_exception)
                    logger.info(str(traceback.extract_tb(error_exception.__traceback__)))
            else:
                if call_type == 'unit':
                    send_sms(False, int_id(_rf_src), 0000, 0000, 'unit',  'APRS Messaging must be enabled. Send command "@APRS ON" or use dashboard to enable.')
                if call_type == 'vcsbk':
                    send_sms(False, 9, 0000, 0000, 'group',  'APRS Messaging must be enabled. Send command "@APRS ON" or use dashboard to enable.')
                
        except Exception as e:
            if call_type == 'unit':
                    send_sms(False, int_id(_rf_src), 0000, 0000, 'unit',  'APRS Messaging must be enabled. Send command "@APRS ON" or use dashboard to enable.')
            if call_type == 'vcsbk':
                send_sms(False, 9, 0000, 0000, 'group',  'APRS Messaging must be enabled. Send command "@APRS ON" or use dashboard to enable.')

##    try:
##        if sms in cmd_list:
##            logger.info('Executing command/script.')
##            os.popen(cmd_list[sms]).read()
##            packet_assembly = ''
##    except Exception as error_exception:
##        logger.info('Exception. Command possibly not in list, or other error.')
##        logger.info(error_exception)
##        logger.info(str(traceback.extract_tb(error_exception.__traceback__)))
##        packet_assembly = ''
    else:
        pass

##### SMS encode #########
############## SMS Que and functions ###########
def create_crc16(fragment_input):
    crc16 = libscrc.gsm16(bytearray.fromhex(fragment_input))
    return fragment_input + re.sub('x', '0', str(hex(crc16 ^ 0xcccc))[-4:])

def create_crc32(fragment_input):
    # Create and append CRC32 to data
    # Create list of hex
    word_list = []
    count_index = 0
    while count_index < len(fragment_input):
        word_list.append((fragment_input[count_index:count_index + 2]))
        count_index = count_index + 2
    # Create string of rearranged word_list to match ETSI 102 361-1 pg 141
    lst_index = 0
    crc_string = ''
    for i in (word_list):
        #print(lst_index)
        if lst_index % 2 == 0:
            crc_string =  crc_string + word_list[lst_index + 1]
            #print(crc_string)
        if lst_index % 2 == 1:
            crc_string = crc_string + word_list[lst_index - 1]
            #print(crc_string)
        lst_index = lst_index + 1
    # Create bytearray of word_list_string
   # print(crc_string)
    word_array = libscrc.posix(bytearray.fromhex(crc_string))
    # XOR to get almost final CRC
    pre_crc = str(hex(word_array ^ 0xffffffff))[2:]
    # Rearrange pre_crc for transmission
    crc = ''
    c = 8
    while c > 0:
        crc = crc + pre_crc[c-2:c]
        c = c - 2
    #crc = crc.zfill(8)
    crc = crc.ljust(8, '0')
    # Return original data and append CRC32
    print('Output: ' + fragment_input + crc)
    return fragment_input + crc

def create_crc16_csbk(fragment_input):
    crc16_csbk = libscrc.gsm16(bytearray.fromhex(fragment_input))
    return fragment_input + re.sub('x', '0', str(hex(crc16_csbk ^ 0xa5a5))[-4:])
def csbk_gen(to_id, from_id):
    csbk_lst = ['BD00801a', 'BD008019', 'BD008018', 'BD008017', 'BD008016']

    send_seq_list = ''
    for block in csbk_lst:
        block = block + to_id + from_id
        block  = create_crc16_csbk(block)
        print(block)
        send_seq_list = send_seq_list + block
        print(send_seq_list)
    return send_seq_list

def mmdvm_encapsulate(dst_id, src_id, peer_id, _seq, _slot, _call_type, _dtype_vseq, _stream_id, _dmr_data):
    signature = 'DMRD'
    # needs to be in bytes
    frame_type = 0x10 #bytes_2(int(10))
    #print((frame_type))
    dest_id = bytes_3(int(dst_id, 16))
    #print(ahex(dest_id))
    source_id = bytes_3(int(src_id, 16))
    via_id = bytes_4(int(peer_id, 16))
    #print(ahex(via_id))
    seq = int(_seq).to_bytes(1, 'big')
    #print(ahex(seq))
    # Binary, 0 for 1, 1 for 2
    slot = bitarray(str(_slot))
    #print(slot)
    # binary, 0 for group, 1 for unit, bin(1)
    call_type = bitarray(str(_call_type))
    #print(call_type)
    #0x00 for voice, 0x01 for voice sync, 0x10 for data 
    #frame_type = int(16).to_bytes(1, 'big')
    frame_type = bitarray('10')
    #print(frame_type)
    # Observed to be always 7, int. Will be 6 for header
    #dtype_vseq = hex(int(_dtype_vseq)).encode()
    if _dtype_vseq == 6:
        dtype_vseq = bitarray('0110')
    if _dtype_vseq == 7:
        dtype_vseq = bitarray('0111')
    if _dtype_vseq == 3:
        dtype_vseq = bitarray('0011')
    # 9 digit integer in hex
    stream_id = bytes_4(_stream_id)
    #print(ahex(stream_id))

    middle_guts = slot + call_type + frame_type + dtype_vseq
    #print(middle_guts)
    dmr_data = str(_dmr_data)[2:-1] #str(re.sub("b'|'", '', str(_dmr_data)))
    complete_packet = signature.encode() + seq + dest_id + source_id + via_id + middle_guts.tobytes() + stream_id + bytes.fromhex((dmr_data)) + bitarray('0000000000101111').tobytes()#bytes.fromhex(dmr_data)
    #print('Complete: ' + str(ahex(complete_packet)))
    return complete_packet


# Break long string into block sequence
def block_sequence(input_string):
    seq_blocks = len(input_string)/24
    n = 0
    block_seq = []
    while n < seq_blocks:
        if n == 0:
            block_seq.append(bytes.fromhex(input_string[:24].ljust(24,'0')))
            n = n + 1
        else:
            block_seq.append(bytes.fromhex(input_string[n*24:n*24+24].ljust(24,'0')))
            n = n + 1
    return block_seq

# Takes list of DMR packets, 12 bytes, then encodes them
def dmr_encode(packet_list, _slot):
    send_seq = []
    for i in packet_list:
        stitched_pkt = bptc.interleave_19696(bptc.encode_19696(i))
        l_slot = bitarray('0111011100')
        r_slot = bitarray('1101110001')
        #Mobile Station
        #sync_data = bitarray('110101011101011111110111011111111101011101010111')
        if _slot == 0:
            # TS1 - F7FDD5DDFD55
            sync_data = bitarray('111101111111110111010101110111011111110101010101')
        if _slot == 1:
            #TS2 - D7557F5FF7F5
            sync_data = bitarray('110101110101010101111111010111111111011111110101')
            
        # Data sync? 110101011101011111110111011111111101011101010111 - D5D7F77FD757
        new_pkt = ahex(stitched_pkt[:98] + l_slot + sync_data + r_slot + stitched_pkt[98:])
        send_seq.append(new_pkt)
    return send_seq


def create_sms_seq(dst_id, src_id, peer_id, _slot, _call_type, dmr_string):
    rand_seq = random.randint(1, 999999)
    block_seq = block_sequence(dmr_string)
    dmr_list = dmr_encode(block_seq, _slot)
    cap_in = 0
    mmdvm_send_seq = []
    for i in dmr_list:
        if use_csbk == True:
            if cap_in < 5:
                the_mmdvm_pkt = mmdvm_encapsulate(dst_id, src_id, peer_id, cap_in, _slot, _call_type, 3, rand_seq, i)
                #print(block_seq[cap_in])
                #print(3)
            if cap_in == 5:
                #print(block_seq[cap_in])
                #print(6)
                the_mmdvm_pkt = mmdvm_encapsulate(dst_id, src_id, peer_id, cap_in, _slot, _call_type, 6, rand_seq, i) #(bytes.fromhex(re.sub("b'|'", '', str(orig_cap[cap_in][20:-4])))))
            if cap_in > 5:
                #print(block_seq[cap_in])
                #print(7)
                the_mmdvm_pkt = mmdvm_encapsulate(dst_id, src_id, peer_id, cap_in, _slot, _call_type, 7, rand_seq, i)#(bytes.fromhex(re.sub("b'|'", '', str(orig_cap[cap_in][20:-4])))))
            mmdvm_send_seq.append(ahex(the_mmdvm_pkt))
            cap_in = cap_in + 1
        if use_csbk == False:
            if cap_in == 0:
                the_mmdvm_pkt = mmdvm_encapsulate(dst_id, src_id, peer_id, cap_in, _slot, _call_type, 6, rand_seq, i) #(bytes.fromhex(re.sub("b'|'", '', str(orig_cap[cap_in][20:-4])))))
            else:
                the_mmdvm_pkt = mmdvm_encapsulate(dst_id, src_id, peer_id, cap_in, _slot, _call_type, 7, rand_seq, i)#(bytes.fromhex(re.sub("b'|'", '', str(orig_cap[cap_in][20:-4])))))
            mmdvm_send_seq.append(ahex(the_mmdvm_pkt))
            cap_in = cap_in + 1
            print(ahex(the_mmdvm_pkt))
            systems[UNIT_MAP[bytes.fromhex(dst_id)][0]].send_system(the_mmdvm_pkt)
            
    with open('/tmp/.hblink_data_que_' + str(CONFIG['DATA_CONFIG']['APRS_LOGIN_CALL']).upper() + '/' + str(random.randint(1000, 9999)) + '.mmdvm_seq', "w") as packet_write_file:
        packet_write_file.write(str(mmdvm_send_seq))

    return mmdvm_send_seq

# Built for max length msg, will improve later
def sms_headers(to_id, from_id):
##    #ETSI 102 361-2 uncompressed ipv4
##    # UDP header, src and dest ports are 4007, 0fa7
##    udp_ports = '0fa70fa7'
##    # Length, of what?
##    udp_length = '00da'
##    # Checksum
##    udp_checksum = '4b37'
##
##    # IPV4
##    #IPV4 version and header length, always 45
##    ipv4_v_l = '45'
##    #Type of service, always 00
##    ipv4_svc = '00'
##    #length, always 00ee
##    ipv4_len = '00ee'
##    #ID always 000d
##    ipv4_id = '000d'
##    #Flags and offset always0
##    ipv4_flag_off = '0000'
##    #TTL and Protocol always 4011, no matter what
##    ipv4_ttl_proto = '4011'
    #ipv4 = '450000ee000d0000401100000c' + from_id + '0c' + to_id
    ipv4 = '450000ee00000000401100000c' + from_id + '0c' + to_id
    count_index = 0
    hdr_lst = []
    while count_index < len(ipv4):
        hdr_lst.append((ipv4[count_index:count_index + 4]))
        count_index = count_index + 4
    sum = 0
    for i in hdr_lst:
        sum = sum + int(i, 16)
    flipped = ''
    for i in str(bin(sum))[2:]:
        if i == '1':
            flipped = flipped + '0'
        if i == '0':
            flipped = flipped + '1'
    ipv4_chk_sum = str(hex(int(flipped, 2)))[2:]
    # UDP checksum is optional per ETSI, zero for now as Anytone is not affected.
    header = ipv4[:20] + ipv4_chk_sum + ipv4[24:] + '0fa70fa700da000000d0a00081040d000a'
    return header

def format_sms(msg, to_id, from_id):
    msg_bytes = str.encode(msg)
    encoded = "".join([str('00' + x) for x in re.findall('..',bytes.hex(msg_bytes))] )
    final = encoded
    while len(final) < 400:
        final = final + '002e'
    final = final + '0000000000000000000000'
    headers = sms_headers(to_id, from_id)
    return headers + final

def gen_header(to_id, from_id, call_type):
    if call_type == 1:
        seq_header = '024A' + to_id + from_id + '9550'
    if call_type == 0:
        seq_header = '824A' + to_id + from_id + '9550'
    return seq_header

def send_sms(csbk, to_id, from_id, peer_id, call_type, msg):
    global use_csbk
    use_csbk = csbk
    to_id = str(hex(to_id))[2:].zfill(6)
    from_id = str(hex(from_id))[2:].zfill(6)
    peer_id = str(hex(peer_id))[2:].zfill(8)
    if call_type == 'unit':
        call_type = 1
        # Try to find slot from UNIT_MAP
        try:
            #Slot 2
            if UNIT_MAP[bytes.fromhex(to_id)][2] == 2:
                slot = 1
            # Slot 1
            if UNIT_MAP[bytes.fromhex(to_id)][2] == 1:
                slot = 0
        except Exception as e:
            logger.info(e)
            # Change to config value later
            slot = 1
    if call_type == 'group':
        call_type = 0
        # Send all Group data to TS 2, need to fix later.
        slot = 1
    if csbk == 'yes':
        use_csbk = True
        create_sms_seq(to_id, from_id, peer_id, int(slot), new_call_type, csbk_gen(to_id, from_id) + create_crc16(gen_header(to_id, from_id, new_call_type)) + create_crc32(format_sms(msg, to_id, from_id)))
    else:
        create_sms_seq(to_id, from_id, peer_id, int(slot), call_type, create_crc16(gen_header(to_id, from_id, call_type)) + create_crc32(format_sms(str(msg), to_id, from_id)))

def data_que_check():
    l=task.LoopingCall(data_que_send)
    l.start(1)
def data_que_send():
    #logger.info('Check SMS que')
    try:
        #logger.info(UNIT_MAP)
        for packet_file in os.listdir('/tmp/.hblink_data_que_' + str(CONFIG['DATA_CONFIG']['APRS_LOGIN_CALL']).upper() + '/'):
            logger.info('Sending SMS')
            logger.info(os.listdir('/tmp/.hblink_data_que_' + str(CONFIG['DATA_CONFIG']['APRS_LOGIN_CALL']).upper() + '/'))
            snd_seq = ast.literal_eval(os.popen('cat /tmp/.hblink_data_que_' + str(CONFIG['DATA_CONFIG']['APRS_LOGIN_CALL']).upper() + '/' + packet_file).read())
            for data in snd_seq:
                # Get dest id
                dst_id = bytes.fromhex(str(data[10:16])[2:-1])
                call_type = hex2bits(data)[121:122]
                # Handle UNIT calls
                if call_type[0] == True:
                # If destination ID in map, route call only there
                    if dst_id in UNIT_MAP:
                        data_target = UNIT_MAP[dst_id][0]
                        reactor.callFromThread(systems[data_target].send_system,bytes.fromhex(re.sub("b'|'", '', str(data))))
                        logger.info('Sending data to ' + str(data[10:16])[2:-1] + ' on system ' + data_target)
                    # Flood all systems
                    elif dst_id not in UNIT_MAP:
                        for i in UNIT:
                            reactor.callFromThread(systems[i].send_system,bytes.fromhex(re.sub("b'|'", '', str(data))))
                            logger.info('Sending data to ' + str(data[10:16])[2:-1] + ' on system ' + i)
                # Handle group calls
                elif call_type[0] == False:
                    for i in BRIDGES.items():
                        for d in i[1]:
                            if dst_id == d['TGID']:
                                data_target = d['SYSTEM']
                                reactor.callFromThread(systems[data_target].send_system,bytes.fromhex(re.sub("b'|'", '', str(data))))
                                logger.info('Sending data to ' + str(data[10:16])[2:-1] + ' on system ' + data_target)
      
            os.system('rm /tmp/.hblink_data_que_' + str(CONFIG['DATA_CONFIG']['APRS_LOGIN_CALL']).upper() + '/' + packet_file)

                    #routerHBP.send_peer('MASTER-2', bytes.fromhex(re.sub("b'|'", '', str(data))))
    ##            os.system('rm /tmp/.hblink_data_que/' + packet_file)
    except Exception as e:
        logger.info(e)

# the APRS RX process
def aprs_rx(aprs_rx_login, aprs_passcode, aprs_server, aprs_port, aprs_filter, user_ssid):
    global AIS
    AIS = aprslib.IS(aprs_rx_login, passwd=int(aprs_passcode), host=aprs_server, port=int(aprs_port))
    user_settings = ast.literal_eval(os.popen('cat ' + user_settings_file).read())
    AIS.set_filter(aprs_filter)#parser.get('DATA_CONFIG', 'APRS_FILTER'))
    try:
        if 'N0CALL' in aprs_callsign:
            logger.info()
            logger.info('APRS callsighn set to N0CALL, not connecting to APRS-IS')
            logger.info()
            pass
        else:
            AIS.connect()
            print('Connecting to APRS-IS')
            if int(CONFIG['DATA_CONFIG']['IGATE_BEACON_TIME']) == 0:
                   logger.info('APRS beacon disabled')
            if int(CONFIG['DATA_CONFIG']['IGATE_BEACON_TIME']) != 0:
                aprs_beacon=task.LoopingCall(aprs_beacon_send)
                aprs_beacon.start(int(CONFIG['DATA_CONFIG']['IGATE_BEACON_TIME'])*60)
            AIS.consumer(aprs_process, raw=True, immortal=False)
    except Exception as e:
        logger.info(e)

##### DMR data function ####
def data_received(self, _peer_id, _rf_src, _dst_id, _seq, _slot, _call_type, _frame_type, _dtype_vseq, _stream_id, _data):
    # Capture data headers
    global n_packet_assembly, hdr_type
    #logger.info(_dtype_vseq)
    #logger.info(_call_type)
    #logger.info(_frame_type)
    logger.info(strftime('%H:%M:%S - %m/%d/%y'))
    #logger.info('Special debug for developement:')
    logger.info(ahex(bptc_decode(_data)))
    #logger.info(_rf_src)
    #logger.info((ba2num(bptc_decode(_data)[8:12])))
################################################################3###### CHNGED #########
##    if int_id(_dst_id) == data_id:
    #logger.info(type(_seq))
    if type(_seq) is bytes:
        pckt_seq = int.from_bytes(_seq, 'big')
    else:
        pckt_seq = _seq
    # Try to classify header
    # UDT header has DPF of 0101, which is 5.
    # If 5 is at position 3, then this should be a UDT header for MD-380 type radios.
    # Coordinates are usually in the very next block after the header, we will discard the rest.
    #logger.info(ahex(bptc_decode(_data)[0:10]))
    if _call_type == call_type and header_ID(_data)[3] == '5' and ba2num(bptc_decode(_data)[69:72]) == 0 and ba2num(bptc_decode(_data)[8:12]) == 0 or (_call_type == 'vcsbk' and header_ID(_data)[3] == '5' and ba2num(bptc_decode(_data)[69:72]) == 0 and ba2num(bptc_decode(_data)[8:12]) == 0):
        global udt_block
        logger.info('MD-380 type UDT header detected. Very next packet should be location.')
        hdr_type = '380'
    if _dtype_vseq == 6 and hdr_type == '380' or _dtype_vseq == 'group' and hdr_type == '380':
        udt_block = 1
    if _dtype_vseq == 7 and hdr_type == '380':
        udt_block = udt_block - 1
        if udt_block == 0:
            logger.info('MD-380 type packet. This should contain the GPS location.')
            logger.info('Packet: ' + str(ahex(bptc_decode(_data))))
            if ba2num(bptc_decode(_data)[1:2]) == 1:
                lat_dir = 'N'
            if ba2num(bptc_decode(_data)[1:2]) == 0:
                lat_dir = 'S'
            if ba2num(bptc_decode(_data)[2:3]) == 1:
                lon_dir = 'E'
            if ba2num(bptc_decode(_data)[2:3]) == 0:
                lon_dir = 'W'
            lat_deg = ba2num(bptc_decode(_data)[11:18])
            lon_deg = ba2num(bptc_decode(_data)[38:46])
            lat_min = ba2num(bptc_decode(_data)[18:24])
            lon_min = ba2num(bptc_decode(_data)[46:52])
            lat_min_dec = str(ba2num(bptc_decode(_data)[24:38])).zfill(4)
            lon_min_dec = str(ba2num(bptc_decode(_data)[52:66])).zfill(4)
            # Old MD-380 coordinate format, keep here until new is confirmed working.
            #aprs_lat = str(str(lat_deg) + str(lat_min) + '.' + str(lat_min_dec)[0:2]).zfill(7) + lat_dir
            #aprs_lon = str(str(lon_deg) + str(lon_min) + '.' + str(lon_min_dec)[0:2]).zfill(8) + lon_dir
            # Fix for MD-380 by G7HIF
            aprs_lat = str(str(lat_deg) + str(lat_min).zfill(2) + '.' + str(lat_min_dec)[0:2]).zfill(7) + lat_dir
            aprs_lon = str(str(lon_deg) + str(lon_min).zfill(2) + '.' + str(lon_min_dec)[0:2]).zfill(8) + lon_dir

            # Form APRS packet
            #logger.info(aprs_loc_packet)
            logger.info('Lat: ' + str(aprs_lat) + ' Lon: ' + str(aprs_lon))
            # 14FRS2013 simplified and moved settings retrieval
            user_settings = ast.literal_eval(os.popen('cat ' + user_settings_file).read())
            if int_id(_rf_src) not in user_settings:	
                ssid = str(user_ssid)	
                icon_table = '/'	
                icon_icon = '['	
                comment = aprs_comment + ' DMR ID: ' + str(int_id(_rf_src)) 	
            else:	
                if user_settings[int_id(_rf_src)][1]['ssid'] == '':	
                    ssid = user_ssid	
                if user_settings[int_id(_rf_src)][3]['comment'] == '':	
                    comment = aprs_comment + ' DMR ID: ' + str(int_id(_rf_src))	
                if user_settings[int_id(_rf_src)][2]['icon'] == '':	
                    icon_table = '/'	
                    icon_icon = '['	
                if user_settings[int_id(_rf_src)][2]['icon'] != '':	
                    icon_table = user_settings[int_id(_rf_src)][2]['icon'][0]	
                    icon_icon = user_settings[int_id(_rf_src)][2]['icon'][1]	
                if user_settings[int_id(_rf_src)][1]['ssid'] != '':	
                    ssid = user_settings[int_id(_rf_src)][1]['ssid']	
                if user_settings[int_id(_rf_src)][3]['comment'] != '':	
                    comment = user_settings[int_id(_rf_src)][3]['comment']
            aprs_loc_packet = str(get_alias(int_id(_rf_src), subscriber_ids)) + '-' + ssid + '>APHBL3,TCPIP*:@' + str(datetime.datetime.utcnow().strftime("%H%M%Sh")) + str(aprs_lat) + icon_table + str(aprs_lon) + icon_icon + '/' + str(comment)
            logger.info(aprs_loc_packet)
            logger.info('User comment: ' + comment)
            logger.info('User SSID: ' + ssid)
            logger.info('User icon: ' + icon_table + icon_icon)
            # Attempt to prevent malformed packets from being uploaded.
            try:
                aprslib.parse(aprs_loc_packet)
                float(lat_deg) < 91
                float(lon_deg) < 121
                if int_id(_dst_id) == data_id:
                    aprs_send(aprs_loc_packet)
                    dashboard_loc_write(str(get_alias(int_id(_rf_src), subscriber_ids)) + '-' + ssid, aprs_lat, aprs_lon, time(), comment, int_id(_rf_src))
                #logger.info('Sent APRS packet')
            except Exception as error_exception:
                logger.info('Error. Failed to send packet. Packet may be malformed.')
                logger.info(error_exception)
                logger.info(str(traceback.extract_tb(error_exception.__traceback__)))
            udt_block = 1
            hdr_type = ''
        else:
              pass
    #NMEA type packets for Anytone like radios.
    #if _call_type == call_type or (_call_type == 'vcsbk' and pckt_seq > 3): #int.from_bytes(_seq, 'big') > 3 ):
    # 14FRS2013 contributed improved header filtering, KF7EEL added conditions to allow both call types at the same time
    if _call_type == call_type or (_call_type == 'vcsbk' and pckt_seq > 3 and call_type != 'unit') or (_call_type == 'group' and pckt_seq > 3 and call_type != 'unit') or (_call_type == 'group' and pckt_seq > 3 and call_type == 'both') or (_call_type == 'vcsbk' and pckt_seq > 3 and call_type == 'both') or (_call_type == 'unit' and pckt_seq > 3 and call_type == 'both'): #int.from_bytes(_seq, 'big') > 3 ):
        global packet_assembly, btf
        if _dtype_vseq == 6 or _dtype_vseq == 'group':
            global btf, hdr_start
            hdr_start = str(header_ID(_data))
            logger.info('Header from ' + str(get_alias(int_id(_rf_src), subscriber_ids)) + '. DMR ID: ' + str(int_id(_rf_src)))
            logger.info(ahex(bptc_decode(_data)))
            logger.info('Blocks to follow: ' + str(ba2num(bptc_decode(_data)[65:72])))
            btf = ba2num(bptc_decode(_data)[65:72])
            # Try resetting packet_assembly
            packet_assembly = ''
        # Data blocks at 1/2 rate, see https://github.com/g4klx/MMDVM/blob/master/DMRDefines.h for data types. _dtype_seq defined here also
        if _dtype_vseq == 7:
            btf = btf - 1
            logger.info('Block #: ' + str(btf))
            #logger.info(_seq)
            logger.info('Data block from ' + str(get_alias(int_id(_rf_src), subscriber_ids)) + '. DMR ID: ' + str(int_id(_rf_src)) + '. Destination: ' + str(int_id(_dst_id)))
            logger.info(ahex(bptc_decode(_data)))
            if _seq == 0:
                n_packet_assembly = 0
                packet_assembly = ''
                
            #if btf < btf + 1:
            # 14FRS2013 removed condition, works great!
            n_packet_assembly = n_packet_assembly + 1
            packet_assembly = packet_assembly + str(bptc_decode(_data)) #str((decode_full_lc(b_packet)).strip('bitarray('))
            # Use block 0 as trigger. $GPRMC must also be in string to indicate NMEA.
            # This triggers the APRS upload
            if btf == 0:
                final_packet = str(bitarray(re.sub("\)|\(|bitarray|'", '', packet_assembly)).tobytes().decode('utf-8', 'ignore'))
                sms_hex = str(ba2hx(bitarray(re.sub("\)|\(|bitarray|'", '', packet_assembly))))
                sms_hex_string = re.sub("b'|'", '', str(sms_hex))
                #NMEA GPS sentence
                if '$GPRMC' in final_packet or '$GNRMC' in final_packet:
                    logger.info(final_packet + '\n')
                    # Eliminate excess bytes based on NMEA type
                    # GPRMC
                    if 'GPRMC' in final_packet:
                        logger.info('GPRMC location')
                        #nmea_parse = re.sub('A\*.*|.*\$', '', str(final_packet))
                        nmea_parse = re.sub('A\*.*|.*\$|\n.*', '', str(final_packet))
                    # GNRMC
                    if 'GNRMC' in final_packet:
                        logger.info('GNRMC location')
                        nmea_parse = re.sub('.*\$|\n.*|V\*.*', '', final_packet)
                    loc = pynmea2.parse(nmea_parse, check=False)
                    logger.info('Latitude: ' + str(loc.lat) + str(loc.lat_dir) + ' Longitude: ' + str(loc.lon) + str(loc.lon_dir) + ' Direction: ' + str(loc.true_course) + ' Speed: ' + str(loc.spd_over_grnd) + '\n')
                    try:
                        # Begin APRS format and upload
                        # Disable opening file for reading to reduce "collision" or reading and writing at same time.
                        # 14FRS2013 simplified and moved settings retrieval
                        user_settings = ast.literal_eval(os.popen('cat ' + user_settings_file).read())	
                        if int_id(_rf_src) not in user_settings:	
                            ssid = str(user_ssid)	
                            icon_table = '/'	
                            icon_icon = '['	
                            comment = aprs_comment + ' DMR ID: ' + str(int_id(_rf_src)) 	
                        else:	
                            if user_settings[int_id(_rf_src)][1]['ssid'] == '':	
                                ssid = user_ssid	
                            if user_settings[int_id(_rf_src)][3]['comment'] == '':	
                                comment = aprs_comment + ' DMR ID: ' + str(int_id(_rf_src))	
                            if user_settings[int_id(_rf_src)][2]['icon'] == '':	
                                icon_table = '/'	
                                icon_icon = '['	
                            if user_settings[int_id(_rf_src)][2]['icon'] != '':	
                                icon_table = user_settings[int_id(_rf_src)][2]['icon'][0]	
                                icon_icon = user_settings[int_id(_rf_src)][2]['icon'][1]	
                            if user_settings[int_id(_rf_src)][1]['ssid'] != '':	
                                ssid = user_settings[int_id(_rf_src)][1]['ssid']	
                            if user_settings[int_id(_rf_src)][3]['comment'] != '':	
                                comment = user_settings[int_id(_rf_src)][3]['comment']	
                        aprs_loc_packet = str(get_alias(int_id(_rf_src), subscriber_ids)) + '-' + ssid + '>APHBL3,TCPIP*:@' + str(datetime.datetime.utcnow().strftime("%H%M%Sh")) + str(loc.lat[0:7]) + str(loc.lat_dir) + icon_table + str(loc.lon[0:8]) + str(loc.lon_dir) + icon_icon + str(round(loc.true_course)).zfill(3) + '/' + str(round(loc.spd_over_grnd)).zfill(3) + '/' + str(comment)
                        logger.info(aprs_loc_packet)
                        logger.info('User comment: ' + comment)
                        logger.info('User SSID: ' + ssid)
                        logger.info('User icon: ' + icon_table + icon_icon)
                    except Exception as error_exception:
                        logger.info('Error or user settings file not found, proceeding with default settings.')
                        aprs_loc_packet = str(get_alias(int_id(_rf_src), subscriber_ids)) + '-' + str(user_ssid) + '>APHBL3,TCPIP*:@' + str(datetime.datetime.utcnow().strftime("%H%M%Sh")) + str(loc.lat[0:7]) + str(loc.lat_dir) + '/' + str(loc.lon[0:8]) + str(loc.lon_dir) + '[' + str(round(loc.true_course)).zfill(3) + '/' + str(round(loc.spd_over_grnd)).zfill(3) + '/' + aprs_comment + ' DMR ID: ' + str(int_id(_rf_src))
                        logger.info(error_exception)
                        logger.info(str(traceback.extract_tb(error_exception.__traceback__)))
                    try:
                    # Try parse of APRS packet. If it fails, it will not upload to APRS-IS
                        aprslib.parse(aprs_loc_packet)
                    # Float values of lat and lon. Anything that is not a number will cause it to fail.
                        float(loc.lat)
                        float(loc.lon)
                        if int_id(_dst_id) == data_id:
                            aprs_send(aprs_loc_packet)
                            dashboard_loc_write(str(get_alias(int_id(_rf_src), subscriber_ids)) + '-' + ssid, str(loc.lat[0:7]) + str(loc.lat_dir), str(loc.lon[0:8]) + str(loc.lon_dir), time(), comment, int_id(_rf_src))
                    except Exception as error_exception:
                        logger.info('Failed to parse packet. Packet may be deformed. Not uploaded.')
                        logger.info(error_exception)
                        logger.info(str(traceback.extract_tb(error_exception.__traceback__)))
                    # Get callsign based on DMR ID
                    # End APRS-IS upload
                # Assume this is an SMS message
                elif '$GPRMC' not in final_packet or '$GNRMC' not in final_packet:
                    
####                            # Motorola type SMS header
##                            if '824a' in hdr_start or '024a' in hdr_start:
##                                logger.info('\nMotorola type SMS')
##                                sms = codecs.decode(bytes.fromhex(''.join(sms_hex[74:-8].split('00'))), 'utf-8')
##                                logger.info('\n\n' + 'Received SMS from ' + str(get_alias(int_id(_rf_src), subscriber_ids)) + ', DMR ID: ' + str(int_id(_rf_src)) + ': ' + str(sms) + '\n')
##                                process_sms(_rf_src, sms)
##                                packet_assembly = ''
##                            # ETSI? type SMS header    
##                            elif '0244' in hdr_start or '8244' in hdr_start:
##                                logger.info('ETSI? type SMS')
##                                sms = codecs.decode(bytes.fromhex(''.join(sms_hex[64:-8].split('00'))), 'utf-8')
##                                logger.info('\n\n' + 'Received SMS from ' + str(get_alias(int_id(_rf_src), subscriber_ids)) + ', DMR ID: ' + str(int_id(_rf_src)) + ': ' + str(sms) + '\n')
##                                #logger.info(final_packet)
##                                #logger.info(sms_hex[64:-8])
##                                process_sms(_rf_src, sms)
##                                packet_assembly = ''
####                                
##                            else:
                        logger.info('\nSMS detected. Attempting to parse.')
                        #logger.info(final_packet)
                        logger.info(sms_hex)
##                                logger.info(type(sms_hex))
##                        logger.info('Attempting to find command...')
##                                sms = codecs.decode(bytes.fromhex(''.join(sms_hex[:-8].split('00'))), 'utf-8', 'ignore')
                        sms = codecs.decode(bytes.fromhex(''.join(sms_hex_string[:-8].split('00'))), 'utf-8', 'ignore')
                        msg_found = re.sub('.*\n', '', sms)
                        logger.info('\n\n' + 'Received SMS from ' + str(get_alias(int_id(_rf_src), subscriber_ids)) + ', DMR ID: ' + str(int_id(_rf_src)) + ': ' + str(msg_found) + '\n')
                        
                        if int_id(_dst_id) == data_id:
                            process_sms(_rf_src, msg_found, _call_type, UNIT_MAP[_rf_src][0])
                        if int_id(_dst_id) != data_id:
                            dashboard_sms_write(str(get_alias(int_id(_rf_src), subscriber_ids)), str(get_alias(int_id(_dst_id), subscriber_ids)), int_id(_dst_id), int_id(_rf_src), msg_found, time(), UNIT_MAP[_rf_src][0])
                        #packet_assembly = ''
                        pass
                        #logger.info(bitarray(re.sub("\)|\(|bitarray|'", '', str(bptc_decode(_data)).tobytes().decode('utf-8', 'ignore'))))
                    #logger.info('\n\n' + 'Received SMS from ' + str(get_alias(int_id(_rf_src), subscriber_ids)) + ', DMR ID: ' + str(int_id(_rf_src)) + ': ' + str(sms) + '\n')
                # Reset the packet assembly to prevent old data from returning.
                # 14FRS2013 moved variable reset
                hdr_start = ''
                n_packet_assembly = 0	
                packet_assembly = ''	
                btf = 0
            #logger.info(_seq)
            #packet_assembly = '' #logger.info(_dtype_vseq)
        #logger.info(ahex(bptc_decode(_data)).decode('utf-8', 'ignore'))
        #logger.info(bitarray(re.sub("\)|\(|bitarray|'", '', str(bptc_decode(_data)).tobytes().decode('utf-8', 'ignore'))))


######

# Send data to all OBP connections that have an encryption key. Data such as subscribers are sent to other HBNet servers.
def svrd_send_all(_svrd_data):
    _svrd_packet = SVRD
    for system in CONFIG['SYSTEMS']:
        if CONFIG['SYSTEMS'][system]['ENABLED']:
                if CONFIG['SYSTEMS'][system]['MODE'] == 'OPENBRIDGE':
                    if CONFIG['SYSTEMS'][system]['ENCRYPTION_KEY'] != b'':
                        systems[system].send_system(_svrd_packet + _svrd_data)

def rule_timer_loop():
    global UNIT_MAP
    logger.debug('(ROUTER) routerHBP Rule timer loop started')
    _now = time()
    _then = _now - 3600
    remove_list = []
    print(UNIT_MAP)
    for unit in UNIT_MAP:
        if UNIT_MAP[unit][1] < (_then):
            remove_list.append(unit)

    for unit in remove_list:
        del UNIT_MAP[unit]

    logger.debug('Removed unit(s) %s from UNIT_MAP', remove_list)
    ping(CONFIG)

    
class OBP(OPENBRIDGE):

    def __init__(self, _name, _config, _report):
        OPENBRIDGE.__init__(self, _name, _config, _report)


    def dmrd_received(self, _peer_id, _rf_src, _dst_id, _seq, _slot, _call_type, _frame_type, _dtype_vseq, _stream_id, _data):
        print(_frame_type)
        UNIT_MAP[_rf_src] = (self._system, time())
        if _rf_src not in PACKET_MATCH:
            PACKET_MATCH[_rf_src] = [_data, time()]

        # Check to see if we have already received this packet
##        print(time() - 1)
        elif _data == PACKET_MATCH[_rf_src][0] and time() - 1 < PACKET_MATCH[_rf_src][1]:
            print('matched, dropping')
            pass
            print(PACKET_MATCH)
        else:
            PACKET_MATCH[_rf_src] = [_data, time()]
            print('OBP RCVD')
            if _dtype_vseq in [3,6,7] and _call_type == 'unit' or _call_type == 'group' and _dtype_vseq == 6 or _call_type == 'vcsbk':
                data_received(self, _peer_id, _rf_src, _dst_id, _seq, _slot, _call_type, _frame_type, _dtype_vseq, _stream_id, _data)
            else:
                pass       

    def svrd_received(self, _mode, _data):
        print('SVRD RCV')
        print(_mode)
        if _mode == b'UNIT':
            UNIT_MAP[_data] = (self._system, time())
            print(UNIT_MAP)
        if _mode == b'DATA':
        # DMR Data packet, sent via SVRD
            _peer_id = _data[11:15]
            _seq = _data[4]
            _rf_src = _data[5:8]
            _dst_id = _data[8:11]
            _bits = _data[15]
            _slot = 2 if (_bits & 0x80) else 1
            #_call_type = 'unit' if (_bits & 0x40) else 'group'
            if _bits & 0x40:
                _call_type = 'unit'
            elif (_bits & 0x23) == 0x23:
                _call_type = 'vcsbk'
            else:
                _call_type = 'group'
            _frame_type = (_bits & 0x30) >> 4
            _dtype_vseq = (_bits & 0xF) # data, 1=voice header, 2=voice terminator; voice, 0=burst A ... 5=burst F
            _stream_id = _data[16:20]

##            # Record last packet to prevent duplicates, think finger printing.
##            PACKET_MATCH[_rf_src] = [_data, time()]


            self.dmrd_received(_peer_id, _rf_src, _dst_id, _seq, _slot, _call_type, _frame_type, _dtype_vseq, _stream_id, _data)



class HBP(HBSYSTEM):

    def __init__(self, _name, _config, _report):
        HBSYSTEM.__init__(self, _name, _config, _report)

    def dmrd_received(self, _peer_id, _rf_src, _dst_id, _seq, _slot, _call_type, _frame_type, _dtype_vseq, _stream_id, _data):
        UNIT_MAP[_rf_src] = (self._system, time())
        print('MMDVM RCVD')
        if _rf_src not in PACKET_MATCH:
            PACKET_MATCH[_rf_src] = [_data, time()]
        elif _data == PACKET_MATCH[_rf_src][0] and time() - 1 < PACKET_MATCH[_rf_src][1]:
            print('matched, dropping')
            print(PACKET_MATCH)
            pass
        else:
            PACKET_MATCH[_rf_src] = [_data, time()]
        if _dtype_vseq in [3,6,7] and _call_type == 'unit' or _call_type == 'group' and _dytpe_vseq == 6 or _call_type == 'vcsbk':
            data_received(self, _peer_id, _rf_src, _dst_id, _seq, _slot, _call_type, _frame_type, _dtype_vseq, _stream_id, _data)
        else:
            pass
##        pass



#************************************************
#      MAIN PROGRAM LOOP STARTS HERE
#************************************************

if __name__ == '__main__':

    import argparse
    import sys
    import os
    import signal

    # Change the current directory to the location of the application
    os.chdir(os.path.dirname(os.path.realpath(sys.argv[0])))

    # CLI argument parser - handles picking up the config file from the command line, and sending a "help" message
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', action='store', dest='CONFIG_FILE', help='/full/path/to/config.file (usually data_gateway.cfg)')
    parser.add_argument('-l', '--logging', action='store', dest='LOG_LEVEL', help='Override config file logging level.')
    cli_args = parser.parse_args()

    # Ensure we have a path for the config file, if one wasn't specified, then use the default (top of file)
    if not cli_args.CONFIG_FILE:
        cli_args.CONFIG_FILE = os.path.dirname(os.path.abspath(__file__))+'/data_gateway.cfg'

    # Call the external routine to build the configuration dictionary
    CONFIG = data_gateway_config.build_config(cli_args.CONFIG_FILE)


    data_id = int(CONFIG['DATA_CONFIG']['DATA_DMR_ID'])
    #echo_id = int(CONFIG['DATA_CONFIG']['ECHO_DMR_ID'])

    # Group call or Unit (private) call
    call_type = CONFIG['DATA_CONFIG']['CALL_TYPE']
    # APRS-IS login information
    aprs_callsign = str(CONFIG['DATA_CONFIG']['APRS_LOGIN_CALL']).upper()
    aprs_passcode = int(CONFIG['DATA_CONFIG']['APRS_LOGIN_PASSCODE'])
    aprs_server = CONFIG['DATA_CONFIG']['APRS_SERVER']
    aprs_port = int(CONFIG['DATA_CONFIG']['APRS_PORT'])
    user_ssid = CONFIG['DATA_CONFIG']['USER_APRS_SSID']
    aprs_comment = CONFIG['DATA_CONFIG']['USER_APRS_COMMENT']
    aprs_filter = CONFIG['DATA_CONFIG']['APRS_FILTER']
    # EMAIL variables
##    email_sender = CONFIG['DATA_CONFIG']['EMAIL_SENDER']
##    email_password = CONFIG['DATA_CONFIG']['EMAIL_PASSWORD']
##    smtp_server = CONFIG['DATA_CONFIG']['SMTP_SERVER']
##    smtp_port = CONFIG['DATA_CONFIG']['SMTP_PORT']

    # Dashboard files
    bb_file = CONFIG['DATA_CONFIG']['BULLETIN_BOARD_FILE']
    loc_file = CONFIG['DATA_CONFIG']['LOCATION_FILE']
    the_mailbox_file = CONFIG['DATA_CONFIG']['MAILBOX_FILE']
    emergency_sos_file = CONFIG['DATA_CONFIG']['EMERGENCY_SOS_FILE']
    sms_file = CONFIG['DATA_CONFIG']['SMS_FILE']
    # User APRS settings
    user_settings_file = CONFIG['DATA_CONFIG']['USER_SETTINGS_FILE']

##    use_api = CONFIG['DATA_CONFIG']['USE_API']

    # Check if user_settings (for APRS settings of users) exists. Creat it if not.
    if Path(user_settings_file).is_file():
        pass
    else:
        Path(user_settings_file).touch()
        with open(user_settings_file, 'w') as user_dict_file:
            user_dict_file.write("{1: [{'call': 'N0CALL'}, {'ssid': ''}, {'icon': ''}, {'comment': ''}, {'pin': ''}, {'APRS': False}]}")
            user_dict_file.close()
    # Check to see if dashboard files exist
    if Path(loc_file).is_file():
        pass
    else:
        Path(loc_file).touch()
        with open(loc_file, 'w') as user_loc_file:
            user_loc_file.write("[]")
            user_loc_file.close()
    if Path(bb_file).is_file():
        pass
    else:
        Path(bb_file).touch()
        with open(bb_file, 'w') as user_bb_file:
            user_bb_file.write("[]")
            user_bb_file.close()
            
    if Path(sms_file).is_file():
        pass
    else:
        Path(sms_file).touch()
        with open(sms_file, 'w') as user_sms_file:
            user_sms_file.write("[]")
            user_sms_file.close()
    try:
        Path('/tmp/.hblink_data_que_' + str(CONFIG['DATA_CONFIG']['APRS_LOGIN_CALL']).upper() + '/').mkdir(parents=True, exist_ok=True)
        logger.info('Created que directory')
    except:
        logger.info('Unable to create data que directory')
        pass    

    # Start the system logger
    if cli_args.LOG_LEVEL:
        CONFIG['LOGGER']['LOG_LEVEL'] = cli_args.LOG_LEVEL
    logger = log.config_logging(CONFIG['LOGGER'])
    logger.info('\n\nCopyright (c) 2020, 2021\n\tKF7EEL - Eric, kf7eel@qsl.net -  All rights reserved.\n')
    logger.info('\n\nCopyright (c) 2013, 2014, 2015, 2016, 2018\n\tThe Regents of the K0USY Group. All rights reserved.\n')
    logger.debug('(GLOBAL) Logging system started, anything from here on gets logged')

    # Set up the signal handler
    def sig_handler(_signal, _frame):
        logger.info('(GLOBAL) SHUTDOWN: CONFBRIDGE IS TERMINATING WITH SIGNAL %s', str(_signal))
        hblink_handler(_signal, _frame)
        logger.info('(GLOBAL) SHUTDOWN: ALL SYSTEM HANDLERS EXECUTED - STOPPING REACTOR')
        reactor.stop()

    # Set signal handers so that we can gracefully exit if need be
    for sig in [signal.SIGINT, signal.SIGTERM]:
        signal.signal(sig, sig_handler)

    # Create the name-number mapping dictionaries
    peer_ids, subscriber_ids, talkgroup_ids = mk_aliases(CONFIG)

    # INITIALIZE THE REPORTING LOOP
    if CONFIG['REPORTS']['REPORT']:
        report_server = config_reports(CONFIG, reportFactory)
    else:
        report_server = None
        logger.info('(REPORT) TCP Socket reporting not configured')

    # HBlink instance creation
    logger.info('(GLOBAL) HBlink \'bridge.py\' -- SYSTEM STARTING...')
    for system in CONFIG['SYSTEMS']:
        if CONFIG['SYSTEMS'][system]['ENABLED']:
            if CONFIG['SYSTEMS'][system]['MODE'] == 'OPENBRIDGE':
                systems[system] = OBP(system, CONFIG, report_server)
            else:
                systems[system] = HBP(system, CONFIG, report_server)
            reactor.listenUDP(CONFIG['SYSTEMS'][system]['PORT'], systems[system], interface=CONFIG['SYSTEMS'][system]['IP'])
            logger.debug('(GLOBAL) %s instance created: %s, %s', CONFIG['SYSTEMS'][system]['MODE'], system, systems[system])

    def loopingErrHandle(failure):
        logger.error('(GLOBAL) STOPPING REACTOR TO AVOID MEMORY LEAK: Unhandled error in timed loop.\n %s', failure)
        reactor.stop()

    # Initialize the rule timer -- this if for user activated stuff
    rule_timer_task = task.LoopingCall(rule_timer_loop)
    rule_timer = rule_timer_task.start(60)
    rule_timer.addErrback(loopingErrHandle)

    if 'N0CALL' in aprs_callsign:
        logger.info('APRS callsighn set to N0CALL, packet not sent.')
        pass
    else:
        aprs_thread = threading.Thread(target=aprs_rx, args=(aprs_callsign, aprs_passcode, aprs_server, aprs_port, aprs_filter, user_ssid,))
        aprs_thread.daemon = True
        aprs_thread.start()
        
    reactor.run()
