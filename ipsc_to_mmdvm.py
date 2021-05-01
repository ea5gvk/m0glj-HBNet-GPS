#!/usr/bin/env python
#
###############################################################################
#   Copyright (C) 2016-2019 Cortney T. Buffington, N0MJS <n0mjs@me.com>
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

# Python modules we need
import sys
from bitarray import bitarray
from time import time
from importlib import import_module

# Twisted is pretty important, so I keep it separate
from twisted.internet.protocol import Factory, Protocol
from twisted.protocols.basic import NetstringReceiver
from twisted.internet import reactor, task

# Things we import from the main hblink module
from hblink import HBSYSTEM, OPENBRIDGE, systems, hblink_handler, reportFactory, REPORT_OPCODES, mk_aliases
from dmr_utils3.utils import bytes_3, int_id, get_alias
from dmr_utils3 import decode, bptc, const
import config
import log
from const import *
import re

# Stuff for socket reporting
import pickle
# REMOVE LATER from datetime import datetime
# The module needs logging, but handlers, etc. are controlled by the parent
import logging
logger = logging.getLogger(__name__)

import ast, os, time


# Does anybody read this stuff? There's a PEP somewhere that says I should do this.
__author__     = 'Cortney T. Buffington, N0MJS'
__copyright__  = 'Copyright (c) 2016-2018 Cortney T. Buffington, N0MJS and the K0USY Group'
__credits__    = 'Colin Durbridge, G4EML, Steve Zingman, N4IRS; Mike Zingman, N4IRR; Jonathan Naylor, G4KLX; Hans Barthen, DL5DI; Torsten Shultze, DG1HT'
__license__    = 'GNU GPLv3'
__maintainer__ = 'Cort Buffington, N0MJS'
__email__      = 'n0mjs@me.com'

def build_unit(CONFIG):
    UNIT = []
    for i in CONFIG['SYSTEMS'].items():
        if i[1]['ENABLED'] == True and i[1]['MODE'] != 'XLXPEER': # and i[0] not in exclude:
            UNIT.append(i[0])
    return UNIT
# Functions
def data_que_check():
    l=task.LoopingCall(data_que_send)
    l.start(.1)
def data_que_send():
    #logger.info('Check SMS que')
    try:
        #logger.info(UNIT_MAP)
        for packet_file in os.listdir('/tmp/.hblink_data_que_ipsc/'):
            logger.info('Sending SMS')
##            logger.info(os.listdir('/tmp/.hblink_data_que_ipsc/'))
            data_file = ast.literal_eval(os.popen('cat /tmp/.hblink_data_que_ipsc/' + str(packet_file)).read())
            #print(ahex(data_file))
            #print((data_file[2:-1]))
            #print(bytes.fromhex(str(packet_file)))
            print(bytes.fromhex(re.sub("b'|'", '', str(data_file))))
            for i in UNIT:
                systems[i].send_system(bytes.fromhex(re.sub("b'|'", '', str(data_file))))
            #systems['PEER-1'].send_system(bytes.fromhex(re.sub("b'|'", '', str(data_file))))
            os.system('rm /tmp/.hblink_data_que_ipsc/' + packet_file)
            #time.sleep(0.2)
##            for data in snd_seq:
##                print(data)
##                # Get dest id
##                dst_id = bytes.fromhex(str(data[10:16])[2:-1])
##                call_type = hex2bits(data)[121:122]
##                # Handle UNIT calls
##                if call_type[0] == True:
##                # If destination ID in map, route call only there
##                    if dst_id in UNIT_MAP:
##                        data_target = UNIT_MAP[dst_id][0]
##                        reactor.callFromThread(systems[data_target].send_system,bytes.fromhex(re.sub("b'|'", '', str(data))))
##                        logger.info('Sending data to ' + str(data[10:16])[2:-1] + ' on system ' + data_target)
##                    # Flood all systems
##                    elif dst_id not in UNIT_MAP:
##                        for i in UNIT:
##                            reactor.callFromThread(systems[i].send_system,bytes.fromhex(re.sub("b'|'", '', str(data))))
##                            logger.info('Sending data to ' + str(data[10:16])[2:-1] + ' on system ' + i)
##                # Handle group calls
##                elif call_type[0] == False:
##                    for i in BRIDGES.items():
##                        for d in i[1]:
##                            if dst_id == d['TGID']:
##                                data_target = d['SYSTEM']
##                                reactor.callFromThread(systems[data_target].send_system,bytes.fromhex(re.sub("b'|'", '', str(data))))
##                                logger.info('Sending data to ' + str(data[10:16])[2:-1] + ' on system ' + data_target)
      
##         os.system('rm /tmp/.hblink_data_que_ipsc/' + packet_file)

                    #routerHBP.send_peer('MASTER-2', bytes.fromhex(re.sub("b'|'", '', str(data))))
    ##            os.system('rm /tmp/.hblink_data_que/' + packet_file)
    except Exception as e:
        logger.info(e)

def mmdvm_encapsulate(dst_id, src_id, peer_id, _seq, _slot, _call_type, _dtype_vseq, _stream_id, _dmr_data):
    signature = 'DMRD'
    # needs to be in bytes
    frame_type = 0x10 #bytes_2(int(10))
    #print((frame_type))
    dest_id = bytes_3(int(dst_id, 16))
#    print((dest_id))

    #print(ahex(dest_id))
    source_id = bytes_3(int(src_id, 16))
    via_id = bytes_4(int(peer_id, 16))
   # print((source_id))
    #print(ahex(via_id))
    seq = int(_seq).to_bytes(1, 'big')
    #print(ahex(seq))
    # Binary, 0 for 1, 1 for 2
    slot = bitarray(str(_slot))
    #print(slot)
    # binary, 0 for group, 1 for unit, bin(1)
   # print(_call_type)
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
    #print('Complete: ' + type(ahex(complete_packet)))
##    #print(hex2bits(ahex(complete_packet))[119:120])
    #print(bitarray.frombytes(ahex(complete_packet)))
    return complete_packet

def dmr_encode(packet_list, _slot):
    send_seq = []
    for i in packet_list:
        stitched_pkt = bptc.interleave_19696(bptc.encode_19696(i))
        l_slot = bitarray('0111011100')
        #MS
        #sync_data = bitarray('110101011101011111110111011111111101011101010111')
        if _slot == 0:
            # TS1 - F7FDD5DDFD55
            sync_data = bitarray('111101111111110111010101110111011111110101010101')
        if _slot == 1:
            #TS2 - D7557F5FF7F5
            sync_data = bitarray('110101110101010101111111010111111111011111110101')
        # TS1
        #sync_data = bitarray('111101111111110111010101110111011111110101010101')
        #TS2
        #sync_data = bitarray('110101110101010101111111010111111111011111110101')
        r_slot = bitarray('1101110001')
        # Data sync? 110101011101011111110111011111111101011101010111 - D5D7F77FD757
        new_pkt = ahex(stitched_pkt[:98] + l_slot + sync_data + r_slot + stitched_pkt[98:])
        send_seq.append(new_pkt)
    return send_seq

# Module gobal varaibles

def config_reports(_config, _factory):
    if True: #_config['REPORTS']['REPORT']:
        def reporting_loop(logger, _server):
            logger.debug('(REPORT) Periodic reporting loop started')
            _server.send_config()
            _server.send_bridge()

        logger.info('(REPORT) HBlink TCP reporting server configured')

        report_server = _factory(_config)
        report_server.clients = []
        reactor.listenTCP(_config['REPORTS']['REPORT_PORT'], report_server)

        reporting = task.LoopingCall(reporting_loop, logger, report_server)
        reporting.start(_config['REPORTS']['REPORT_INTERVAL'])

    return report_server

class bridgeReportFactory(reportFactory):

    def send_bridge(self):
        serialized = pickle.dumps(BRIDGES, protocol=2) #.decode("utf-8", errors='ignore')
        self.send_clients(REPORT_OPCODES['BRIDGE_SND']+serialized)

    def send_bridgeEvent(self, _data):
        if isinstance(_data, str):
            _data = _data.decode('utf-8', error='ignore')
        self.send_clients(REPORT_OPCODES['BRDG_EVENT']+_data)

class OBP(OPENBRIDGE):

    def __init__(self, _name, _config, _report):
        OPENBRIDGE.__init__(self, _name, _config, _report)


    def dmrd_received(self, _peer_id, _rf_src, _dst_id, _seq, _slot, _call_type, _frame_type, _dtype_vseq, _stream_id, _data):
        pass


class HBP(HBSYSTEM):

    def __init__(self, _name, _config, _report):
        HBSYSTEM.__init__(self, _name, _config, _report)

    def dmrd_received(self, _peer_id, _rf_src, _dst_id, _seq, _slot, _call_type, _frame_type, _dtype_vseq, _stream_id, _data):
        pass



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
    parser.add_argument('-c', '--config', action='store', dest='CONFIG_FILE', help='/full/path/to/config.file (usually hblink.cfg)')
    parser.add_argument('-l', '--logging', action='store', dest='LOG_LEVEL', help='Override config file logging level.')
    cli_args = parser.parse_args()

    # Ensure we have a path for the config file, if one wasn't specified, then use the default (top of file)
    if not cli_args.CONFIG_FILE:
        cli_args.CONFIG_FILE = os.path.dirname(os.path.abspath(__file__))+'/ipsc_to_mmdvm.cfg'

    # Call the external routine to build the configuration dictionary
    CONFIG = config.build_config(cli_args.CONFIG_FILE)

    # Start the system logger
    if cli_args.LOG_LEVEL:
        CONFIG['LOGGER']['LOG_LEVEL'] = cli_args.LOG_LEVEL
    logger = log.config_logging(CONFIG['LOGGER'])
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
        report_server = config_reports(CONFIG, bridgeReportFactory)
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
    try:
        Path('.hblink_data_que_ipsc/').mkdir(parents=True, exist_ok=True)
    except:
        logger.info('Unable to create data que directory')
        pass
    UNIT = build_unit(CONFIG)
    data_que_check()


    reactor.run()
