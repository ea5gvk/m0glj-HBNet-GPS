# HBNet Web Server
###############################################################################
#   HBNet Web Server - Copyright (C) 2020 Eric Craw, KF7EEL <kf7eel@qsl.net>
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
Flask based application that is the web server for HBNet. Controls user authentication, DMR server config, etc.
'''

from flask import Flask, render_template_string, request, make_response, jsonify, render_template, Markup, flash, redirect, url_for, current_app, Response
from flask_sqlalchemy import SQLAlchemy
from flask_user import login_required, UserManager, UserMixin, user_registered, roles_required
from werkzeug.security import check_password_hash
from flask_login import current_user, login_user, logout_user
from wtforms import StringField, SubmitField
import requests
import base64, hashlib
from dmr_utils3.utils import int_id, bytes_4
from config import *
import ast
import json
import datetime, time
from flask_babelex import Babel
import libscrc
import random
from flask_mail import Message, Mail
from socket import gethostbyname
import re
import folium

from gen_script_template import gen_script

import os, ast
##import hb_config

from cryptography.fernet import Fernet



script_links = {}
active_tgs = {}
ping_list = {}
peer_locations = {}

# Query radioid.net for list of IDs
def get_ids(callsign):
    try:
        url = "https://www.radioid.net"
        response = requests.get(url+"/api/dmr/user/?callsign=" + callsign)
        result = response.json()
##        print(result)
    #        id_list = []
        id_list = {}
        f_name = result['results'][0]['fname']
        l_name = result['results'][0]['surname']
        try:
            city = str(result['results'][0]['city'] + ', ' + result['results'][0]['state'] + ', ' + result['results'][0]['country'])
        except:
            city = result['results'][0]['country']
        for i in result['results']:
             id_list[i['id']] = 0
        return str([id_list, f_name, l_name, city])
    except:
        return str([{}, '', '', ''])
 

# Return string in NATO phonetics
def convert_nato(string):
    d_nato = { 'A': 'ALPHA', 'B': 'BRAVO', 'C': 'CHARLIE', 'D': 'DELTA',
          'E': 'ECHO', 'F': 'FOXTROT', 'G': 'GOLF', 'H': 'HOTEL',
          'I': 'INDIA', 'J': 'JULIETT','K': 'KILO', 'L': 'LIMA',
         'M': 'MIKE', 'N': 'NOVEMBER','O': 'OSCAR', 'P': 'PAPA',
         'Q': 'QUEBEC', 'R': 'ROMEO', 'S': 'SIERRA', 'T': 'TANGO',
         'U': 'UNIFORM', 'V': 'VICTOR', 'W': 'WHISKEY', 'X': 'X-RAY',
         'Y': 'YANKEE', 'Z': 'ZULU', '0': 'zero(0)', '1': 'one(1)',
         '2': 'two(2)', '3': 'three(3)', '4': 'four(4)', '5': 'five(5)',
         '6': 'six(6)', '7': 'seven(7)', '8': 'eight(8)', '9': 'nine(9)',
         'a': 'alpha', 'b': 'bravo', 'c': 'charlie', 'd': 'delta',
         'e': 'echo', 'f': 'foxtrot', 'g': 'golf', 'h': 'hotel',
         'i': 'india', 'j': 'juliett','k': 'kilo', 'l': 'lima',
         'm': 'mike', 'n': 'november','o': 'oscar', 'p': 'papa',
         'q': 'quebec', 'r': 'romeo', 's': 'sierra', 't': 'tango',
         'u': 'uniform', 'v': 'victor', 'w': 'whiskey', 'x': 'x-ray',
         'y': 'yankee', 'z': 'Zulu'}
    ns = ''
    for c in string:
        try:
            ns = ns + d_nato[c] + ' '
        except:
            ns = ns + c + ' '
    return ns

# Convert APRS to map coordinates
def aprs_to_latlon(x):
    degrees = int(x) // 100
    minutes = x - 100*degrees
    return degrees + minutes/60 

# Class-based application configuration
class ConfigClass(object):
    from config import MAIL_SERVER, MAIL_PORT, MAIL_USE_SSL, MAIL_USE_TLS, MAIL_USERNAME, MAIL_PASSWORD, MAIL_DEFAULT_SENDER, USER_ENABLE_EMAIL, USER_ENABLE_USERNAME, USER_REQUIRE_RETYPE_PASSWORD, USER_ENABLE_CHANGE_USERNAME, USER_ENABLE_MULTIPLE_EMAILS, USER_ENABLE_CONFIRM_EMAIL, USER_ENABLE_REGISTER, USER_AUTO_LOGIN_AFTER_CONFIRM, USER_SHOW_USERNAME_DOES_NOT_EXIST 
    """ Flask application config """

    # Flask settings
    SECRET_KEY = secret_key

    # Flask-SQLAlchemy settings
    SQLALCHEMY_DATABASE_URI = db_location    # File-based SQL database
    SQLALCHEMY_TRACK_MODIFICATIONS = False    # Avoids SQLAlchemy warning

    # Flask-User settings
    USER_APP_NAME = title      # Shown in and email templates and page footers
    USER_EMAIL_SENDER_EMAIL = MAIL_DEFAULT_SENDER
    USER_EDIT_USER_PROFILE_TEMPLATE = 'flask_user/edit_user_profile.html'




     
# Setup Flask-User
def create_app():
    """ Flask application factory """
    
    # Create Flask app load app.config
    mail = Mail()
    app = Flask(__name__)
    app.config.from_object(__name__+'.ConfigClass')

        # Initialize Flask-BabelEx
    babel = Babel(app)

    # Initialize Flask-SQLAlchemy
    db = SQLAlchemy(app)

    # Define the User data-model.
    # NB: Make sure to add flask_user UserMixin !!!
    class User(db.Model, UserMixin):
        __tablename__ = 'users'
        id = db.Column(db.Integer, primary_key=True)
        active = db.Column('is_active', db.Boolean(), nullable=False, server_default='1')

        # User authentication information. The collation='NOCASE' is required
        # to search case insensitively when USER_IFIND_MODE is 'nocase_collation'.
        username = db.Column(db.String(100,), nullable=False, unique=True)
        password = db.Column(db.String(255), nullable=False, server_default='')
        email_confirmed_at = db.Column(db.DateTime())
        email = db.Column(db.String(255), nullable=True, unique=True)
        
        # User information
        first_name = db.Column(db.String(100), nullable=False, server_default='')
        last_name = db.Column(db.String(100), nullable=False, server_default='')
        dmr_ids = db.Column(db.String(1000), nullable=False, server_default='')
        city = db.Column(db.String(100), nullable=False, server_default='')
        notes = db.Column(db.String(2000), nullable=False, server_default='')
        aprs = db.Column(db.String(2000), nullable=False, server_default='')
        #Used for initial approval
        initial_admin_approved = db.Column('initial_admin_approved', db.Boolean(), nullable=False, server_default='1')
        # Define the relationship to Role via UserRoles
        roles = db.relationship('Role', secondary='user_roles')
        
    # Define the Role data-model
    class Role(db.Model):
        __tablename__ = 'roles'
        id = db.Column(db.Integer(), primary_key=True)
        name = db.Column(db.String(50), unique=True)

    # Define the UserRoles association table
    class UserRoles(db.Model):
        __tablename__ = 'user_roles'
        id = db.Column(db.Integer(), primary_key=True)
        user_id = db.Column(db.Integer(), db.ForeignKey('users.id', ondelete='CASCADE'))
        role_id = db.Column(db.Integer(), db.ForeignKey('roles.id', ondelete='CASCADE'))
    class BurnList(db.Model):
        __tablename__ = 'burn_list'
##        id = db.Column(db.Integer(), primary_key=True)
        dmr_id = db.Column(db.Integer(), unique=True, primary_key=True)
        version = db.Column(db.Integer(), primary_key=True)
    class AuthLog(db.Model):
        __tablename__ = 'auth_log'
        id = db.Column(db.Integer(), primary_key=True)
        login_dmr_id = db.Column(db.Integer())
        login_time = db.Column(db.DateTime())
        peer_ip = db.Column(db.String(100), nullable=False, server_default='')
        server_name = db.Column(db.String(100))
        login_auth_method = db.Column(db.String(100), nullable=False, server_default='')
        portal_username = db.Column(db.String(100), nullable=False, server_default='')
        login_type = db.Column(db.String(100), nullable=False, server_default='')
    class mmdvmPeer(db.Model):
        __tablename__ = 'MMDVM_peers'
        id = db.Column(db.Integer(), primary_key=True)
        name = db.Column(db.String(100), nullable=False, server_default='')
        enabled = db.Column(db.Boolean(), nullable=False, server_default='1')
        loose = db.Column(db.Boolean(), nullable=False, server_default='1')
        ip = db.Column(db.String(100), nullable=False, server_default='127.0.0.1')
        port = db.Column(db.Integer(), primary_key=False)
        master_ip = db.Column(db.String(100), nullable=False, server_default='')
        master_port = db.Column(db.Integer(), primary_key=False)
        passphrase = db.Column(db.String(100), nullable=False, server_default='')
        callsign = db.Column(db.String(100), nullable=False, server_default='')
        radio_id = db.Column(db.Integer(), primary_key=False)
        rx_freq = db.Column(db.String(100), nullable=False, server_default='')
        tx_freq = db.Column(db.String(100), nullable=False, server_default='')
        tx_power = db.Column(db.String(100), nullable=False, server_default='')
        color_code = db.Column(db.String(100), nullable=False, server_default='')
        latitude = db.Column(db.String(100), nullable=False, server_default='')
        longitude = db.Column(db.String(100), nullable=False, server_default='')
        height = db.Column(db.String(100), nullable=False, server_default='')
        location = db.Column(db.String(100), nullable=False, server_default='')
        description = db.Column(db.String(100), nullable=False, server_default='')
        slots = db.Column(db.String(100), nullable=False, server_default='')
        url = db.Column(db.String(100), nullable=False, server_default='')
        group_hangtime = db.Column(db.String(100), nullable=False, server_default='')
        enable_unit = db.Column(db.Boolean(), nullable=False, server_default='1')
        options = db.Column(db.String(100), nullable=False, server_default='')
        use_acl = db.Column(db.Boolean(), nullable=False, server_default='0')
        sub_acl = db.Column(db.String(100), nullable=False, server_default='')
        tg1_acl = db.Column(db.String(100), nullable=False, server_default='')
        tg2_acl = db.Column(db.String(100), nullable=False, server_default='')
        server = db.Column(db.String(100), nullable=False, server_default='')
        notes =  db.Column(db.String(500), nullable=False, server_default='')
        other_options = db.Column(db.String(1000), nullable=False, server_default='')

    class xlxPeer(db.Model):
        __tablename__ = 'XLX_peers'
        id = db.Column(db.Integer(), primary_key=True)
        name = db.Column(db.String(100), nullable=False, server_default='')
        enabled = db.Column(db.Boolean(), nullable=False, server_default='1')
        loose = db.Column(db.Boolean(), nullable=False, server_default='1')
        ip = db.Column(db.String(100), nullable=False, server_default='127.0.0.1')
        port = db.Column(db.Integer(), primary_key=False)
        master_ip = db.Column(db.String(100), nullable=False, server_default='')
        master_port = db.Column(db.Integer(), primary_key=False)
        passphrase = db.Column(db.String(100), nullable=False, server_default='')
        callsign = db.Column(db.String(100), nullable=False, server_default='')
        radio_id = db.Column(db.Integer(), primary_key=False)
        rx_freq = db.Column(db.String(100), nullable=False, server_default='')
        tx_freq = db.Column(db.String(100), nullable=False, server_default='')
        tx_power = db.Column(db.String(100), nullable=False, server_default='')
        color_code = db.Column(db.String(100), nullable=False, server_default='')
        latitude = db.Column(db.String(100), nullable=False, server_default='')
        longitude = db.Column(db.String(100), nullable=False, server_default='')
        height = db.Column(db.String(100), nullable=False, server_default='')
        location = db.Column(db.String(100), nullable=False, server_default='')
        description = db.Column(db.String(100), nullable=False, server_default='')
        slots = db.Column(db.String(100), nullable=False, server_default='')
        url = db.Column(db.String(100), nullable=False, server_default='')
        group_hangtime = db.Column(db.String(100), nullable=False, server_default='')
        xlxmodule = db.Column(db.String(100), nullable=False, server_default='')
        options = db.Column(db.String(100), nullable=False, server_default='')
        enable_unit = db.Column(db.Boolean(), nullable=False, server_default='1')
        use_acl = db.Column(db.Boolean(), nullable=False, server_default='0')
        sub_acl = db.Column(db.String(100), nullable=False, server_default='')
        tg1_acl = db.Column(db.String(100), nullable=False, server_default='')
        tg2_acl = db.Column(db.String(100), nullable=False, server_default='')
        server = db.Column(db.String(100), nullable=False, server_default='')
        notes = db.Column(db.String(500), nullable=False, server_default='')
        other_options = db.Column(db.String(1000), nullable=False, server_default='')
        
    class ServerList(db.Model):
        __tablename__ = 'server_list'
        name = db.Column(db.String(100), unique=True, primary_key=True)
        secret = db.Column(db.String(255), nullable=False, server_default='')
##        public_list = db.Column(db.Boolean(), nullable=False, server_default='1')
        id = db.Column(db.Integer(), primary_key=False)
        ip = db.Column(db.String(100), nullable=False, server_default='')
        global_path = db.Column(db.String(100), nullable=False, server_default='./')
        global_ping_time = db.Column(db.Integer(), primary_key=False)
        global_max_missed = db.Column(db.Integer(), primary_key=False)
        global_use_acl = db.Column(db.Boolean(), nullable=False, server_default='1')
        global_reg_acl = db.Column(db.String(100), nullable=False, server_default='PERMIT:ALL')
        global_sub_acl = db.Column(db.String(100), nullable=False, server_default='DENY:1')
        global_tg1_acl = db.Column(db.String(100), nullable=False, server_default='PERMIT:ALL')
        global_tg2_acl = db.Column(db.String(100), nullable=False, server_default='PERMIT:ALL')
        ai_try_download = db.Column(db.Boolean(), nullable=False, server_default='1')
        ai_path = db.Column(db.String(100), nullable=False, server_default='./')
        ai_peer_file = db.Column(db.String(100), nullable=False, server_default='peer_ids.json')
        ai_subscriber_file = db.Column(db.String(100), nullable=False, server_default='subscriber_ids.json')
        ai_tgid_file = db.Column(db.String(100), nullable=False, server_default='talkgroup_ids.json')
        ai_peer_url = db.Column(db.String(100), nullable=False, server_default='https://www.radioid.net/static/rptrs.json')
        ai_subs_url = db.Column(db.String(100), nullable=False, server_default='https://www.radioid.net/static/users.json')
        ai_stale = db.Column(db.Integer(), primary_key=False, server_default='7')
        # Pull from config file for now
##        um_append_int = db.Column(db.Integer(), primary_key=False, server_default='2')
        um_shorten_passphrase = db.Column(db.Boolean(), nullable=False, server_default='0')
        um_burn_file = db.Column(db.String(100), nullable=False, server_default='./burned_ids.txt')
        # Pull from config file for now
##        um_burn_int = db.Column(db.Integer(), primary_key=False, server_default='6')
        report_enable = db.Column(db.Boolean(), nullable=False, server_default='1')
        report_interval = db.Column(db.Integer(), primary_key=False, server_default='60')
        report_port = db.Column(db.Integer(), primary_key=False, server_default='4321')
        report_clients =db.Column(db.String(100), nullable=False, server_default='127.0.0.1')
        unit_time = db.Column(db.Integer(), primary_key=False, server_default='10080')
        notes =  db.Column(db.String(100), nullable=False, server_default='')
        dash_url = db.Column(db.String(1000), nullable=True, server_default='https://hbnet.xyz')
        public_notes =  db.Column(db.String(1000), nullable=False, server_default='')
        other_options = db.Column(db.String(1000), nullable=False, server_default='')

    class MasterList(db.Model):
        __tablename__ = 'master_list'
        id = db.Column(db.Integer(), primary_key=True)
        name = db.Column(db.String(100), nullable=False, server_default='')
        static_positions = db.Column(db.Boolean(), nullable=False, server_default='0')
        repeat = db.Column(db.Boolean(), nullable=False, server_default='1')
        active = db.Column(db.Boolean(), nullable=False, server_default='1')
        max_peers = db.Column(db.Integer(), primary_key=False, server_default='10')
        ip = db.Column(db.String(100), nullable=False, server_default='')
        port = db.Column(db.Integer(), primary_key=False)
        enable_um = db.Column(db.Boolean(), nullable=False, server_default='1')
        passphrase = db.Column(db.String(100), nullable=False, server_default='')
        group_hang_time = db.Column(db.Integer(), primary_key=False, server_default='5')
        use_acl = db.Column(db.Boolean(), nullable=False, server_default='1')
        reg_acl = db.Column(db.String(100), nullable=False, server_default='')
        sub_acl = db.Column(db.String(100), nullable=False, server_default='')
        tg1_acl = db.Column(db.String(100), nullable=False, server_default='')
        tg2_acl = db.Column(db.String(100), nullable=False, server_default='')
        enable_unit = db.Column(db.Boolean(), nullable=False, server_default='1')
        server = db.Column(db.String(100), nullable=False, server_default='')
        notes = db.Column(db.String(500), nullable=False, server_default='')
        public_list = db.Column(db.Boolean(), nullable=False, server_default='1')
        other_options = db.Column(db.String(1000), nullable=False, server_default='')


    class ProxyList(db.Model):
        __tablename__ = 'proxy_list'
        id = db.Column(db.Integer(), primary_key=True)
        name = db.Column(db.String(100), nullable=False, server_default='')
        active = db.Column(db.Boolean(), nullable=False, server_default='1')
        static_positions = db.Column(db.Boolean(), nullable=False, server_default='0')
        repeat = db.Column(db.Boolean(), nullable=False, server_default='1')
        enable_um = db.Column(db.Boolean(), nullable=False, server_default='1')
        passphrase = db.Column(db.String(100), nullable=False, server_default='')
        external_proxy = db.Column(db.Boolean(), nullable=False, server_default='0')
        external_port = db.Column(db.Integer(), primary_key=False)
        group_hang_time = db.Column(db.Integer(), primary_key=False)
        internal_start_port = db.Column(db.Integer(), primary_key=False)
        internal_stop_port = db.Column(db.Integer(), primary_key=False)
        use_acl = db.Column(db.Boolean(), nullable=False, server_default='1')
        reg_acl = db.Column(db.String(100), nullable=False, server_default='')
        sub_acl = db.Column(db.String(100), nullable=False, server_default='')
        tg1_acl = db.Column(db.String(100), nullable=False, server_default='')
        tg2_acl = db.Column(db.String(100), nullable=False, server_default='')
        enable_unit = db.Column(db.Boolean(), nullable=False, server_default='1')
        server = db.Column(db.String(100), nullable=False, server_default='')
        notes = db.Column(db.String(500), nullable=False, server_default='')
        public_list = db.Column(db.Boolean(), nullable=False, server_default='1')
        other_options = db.Column(db.String(1000), nullable=False, server_default='')

        
    class OBP(db.Model):
        __tablename__ = 'OpenBridge'
        id = db.Column(db.Integer(), primary_key=True)
        name = db.Column(db.String(100), nullable=False, server_default='')
        enabled = db.Column(db.Boolean(), nullable=False, server_default='1')
        network_id = db.Column(db.Integer(), primary_key=False)
        ip = db.Column(db.String(100), nullable=False, server_default='')
        port = db.Column(db.Integer(), primary_key=False)
        passphrase = db.Column(db.String(100), nullable=False, server_default='')
        target_ip = db.Column(db.String(100), nullable=False, server_default='')
        target_port = db.Column(db.Integer(), primary_key=False)
        both_slots = db.Column(db.Boolean(), nullable=False, server_default='1')
        use_acl = db.Column(db.Boolean(), nullable=False, server_default='1')
        sub_acl = db.Column(db.String(100), nullable=False, server_default='')
        tg_acl = db.Column(db.String(100), nullable=False, server_default='')
        enable_unit = db.Column(db.Boolean(), nullable=False, server_default='1')
        server = db.Column(db.String(100), nullable=False, server_default='')
        notes = db.Column(db.String(500), nullable=False, server_default='')
        other_options = db.Column(db.String(1000), nullable=False, server_default='')
        encryption_key = db.Column(db.String(200), nullable=False, server_default='')
        obp_encryption = db.Column(db.Boolean(), nullable=False, server_default='0')
        
    class BridgeRules(db.Model):
        __tablename__ = 'bridge_rules'
        id = db.Column(db.Integer(), primary_key=True)
        bridge_name = db.Column(db.String(100), nullable=False, server_default='')
        system_name = db.Column(db.String(100), nullable=False, server_default='')
        ts = db.Column(db.Integer(), primary_key=False)
        tg = db.Column(db.Integer(), primary_key=False)
        active = db.Column(db.Boolean(), nullable=False, server_default='1')
        timeout = db.Column(db.Integer(), primary_key=False)
        to_type = db.Column(db.String(100), nullable=False, server_default='')
        on = db.Column(db.String(100), nullable=False, server_default='')
        off = db.Column(db.String(100), nullable=False, server_default='')
        reset = db.Column(db.String(100), nullable=False, server_default='')
        server = db.Column(db.String(100), nullable=False, server_default='')
##        public_list = db.Column(db.Boolean(), nullable=False, server_default='0')
        proxy = db.Column(db.Boolean(), nullable=False, server_default='0')

    class BridgeList(db.Model):
        __tablename__ = 'bridge_list'
        id = db.Column(db.Integer(), primary_key=True)
        bridge_name = db.Column(db.String(100), nullable=False, server_default='')
        description = db.Column(db.String(5000), nullable=False, server_default='')
        public_list = db.Column(db.Boolean(), nullable=False, server_default='0')
        tg = db.Column(db.Integer(), primary_key=False)
        
    class GPS_LocLog(db.Model):
        __tablename__ = 'gps_locations'
        id = db.Column(db.Integer(), primary_key=True)
        callsign = db.Column(db.String(100), nullable=False, server_default='')
        comment = db.Column(db.String(150), nullable=False, server_default='')
        lat = db.Column(db.String(100), nullable=False, server_default='')
        lon = db.Column(db.String(100), nullable=False, server_default='')
        time = db.Column(db.DateTime())
        server = db.Column(db.String(100), nullable=False, server_default='')
        system_name = db.Column(db.String(100), nullable=False, server_default='')
        dmr_id = db.Column(db.Integer(), primary_key=False)
        
    class BulletinBoard(db.Model):
        __tablename__ = 'sms_bb'
        id = db.Column(db.Integer(), primary_key=True)
        callsign = db.Column(db.String(100), nullable=False, server_default='')
        bulletin = db.Column(db.String(150), nullable=False, server_default='')
        time = db.Column(db.DateTime())
        server = db.Column(db.String(100), nullable=False, server_default='')
        system_name = db.Column(db.String(100), nullable=False, server_default='')
        dmr_id = db.Column(db.Integer(), primary_key=False)

    class SMSLog(db.Model):
        __tablename__ = 'sms_log'
        id = db.Column(db.Integer(), primary_key=True)
        snd_callsign = db.Column(db.String(100), nullable=False, server_default='')
        rcv_callsign = db.Column(db.String(100), nullable=False, server_default='')
        message = db.Column(db.String(100), nullable=False, server_default='')
        time = db.Column(db.DateTime())
        server = db.Column(db.String(100), nullable=False, server_default='')
        system_name = db.Column(db.String(100), nullable=False, server_default='')
        snd_id = db.Column(db.Integer(), primary_key=False)
        rcv_id = db.Column(db.Integer(), primary_key=False)
        
    class MailBox(db.Model):
        __tablename__ = 'sms_aprs_mailbox'
        id = db.Column(db.Integer(), primary_key=True)
        snd_callsign = db.Column(db.String(100), nullable=False, server_default='')
        rcv_callsign = db.Column(db.String(100), nullable=False, server_default='')
        message = db.Column(db.String(150), nullable=False, server_default='')
        time = db.Column(db.DateTime())
        server = db.Column(db.String(100), nullable=False, server_default='')
        system_name = db.Column(db.String(100), nullable=False, server_default='')
        snd_id = db.Column(db.Integer(), primary_key=False)
        rcv_id = db.Column(db.Integer(), primary_key=False)

    class News(db.Model):
        __tablename__ = 'news'
        id = db.Column(db.Integer(), primary_key=True)
        subject = db.Column(db.String(100), nullable=False, server_default='')
        text = db.Column(db.String(5000), nullable=False, server_default='')
        date = db.Column(db.String(100), nullable=False, server_default='')
        time = db.Column(db.DateTime())

    class PeerLoc(db.Model):
        __tablename__ = 'peer_locations'
        id = db.Column(db.Integer(), primary_key=True)
        callsign = db.Column(db.String(100), nullable=False, server_default='')
        comment = db.Column(db.String(100), nullable=False, server_default='')
        lat = db.Column(db.String(100), nullable=False, server_default='')
        lon = db.Column(db.String(100), nullable=False, server_default='')
        time = db.Column(db.DateTime())
        server = db.Column(db.String(100), nullable=False, server_default='')
        system_name = db.Column(db.String(100), nullable=False, server_default='')
        user = db.Column(db.Boolean(), nullable=False, server_default='1')
        dmr_id = db.Column(db.Integer(), primary_key=False)

    class CustomID(db.Model):
        __tablename__ = 'custom_dmr_id'
        id = db.Column(db.Integer(), primary_key=True)
        callsign = db.Column(db.String(100), nullable=False, server_default='')
        f_name = db.Column(db.String(100), nullable=False, server_default='')
        l_name = db.Column(db.String(100), nullable=False, server_default='')
        city = db.Column(db.String(100), nullable=False, server_default='')
        country = db.Column(db.String(100), nullable=False, server_default='')
        dmr_id = db.Column(db.Integer(), primary_key=False)

    class Social(db.Model):
        __tablename__ = 'social'
        id = db.Column(db.Integer(), primary_key=True)
        callsign = db.Column(db.String(100), nullable=False, server_default='')
        message = db.Column(db.String(150), nullable=False, server_default='')
        time = db.Column(db.DateTime())
        
    class Misc(db.Model):
        __tablename__ = 'misc'
        id = db.Column(db.Integer(), primary_key=True)
        field_1 = db.Column(db.String(500), nullable=True, server_default='')
        field_2 = db.Column(db.String(500), nullable=True, server_default='')
        field_3 = db.Column(db.String(500), nullable=True, server_default='')
        field_4 = db.Column(db.String(500), nullable=True, server_default='')
        int_1 = db.Column(db.Integer(), nullable=True)
        int_2 = db.Column(db.Integer(), nullable=True)
        int_3 = db.Column(db.Integer(), nullable=True)
        int_4 = db.Column(db.Integer(), nullable=True)
        boo_1 = db.Column(db.Boolean(), nullable=True, server_default='1')
        boo_2 = db.Column(db.Boolean(), nullable=True, server_default='1')
        time = db.Column(db.DateTime())




        
    # Customize Flask-User
    class CustomUserManager(UserManager):
    # Override or extend the default login view method
        def login_view(self):
            """Prepare and process the login form."""

            # Authenticate username/email and login authenticated users.
            
            safe_next_url = self._get_safe_next_url('next', self.USER_AFTER_LOGIN_ENDPOINT)
            safe_reg_next = self._get_safe_next_url('reg_next', self.USER_AFTER_REGISTER_ENDPOINT)

            # Immediately redirect already logged in users
            if self.call_or_get(current_user.is_authenticated) and self.USER_AUTO_LOGIN_AT_LOGIN:
                return redirect(safe_next_url)

            # Initialize form
            login_form = self.LoginFormClass(request.form)  # for login.html
            register_form = self.RegisterFormClass()  # for login_or_register.html
            if request.method != 'POST':
                login_form.next.data = register_form.next.data = safe_next_url
                login_form.reg_next.data = register_form.reg_next.data = safe_reg_next

            # Process valid POST
            if request.method == 'POST' and login_form.validate():
                # Retrieve User
                user = None
                user_email = None
                if self.USER_ENABLE_USERNAME:
                    # Find user record by username
                    user = self.db_manager.find_user_by_username(login_form.username.data)
                    
                    # Find user record by email (with form.username)
                    if not user and self.USER_ENABLE_EMAIL:
                        user, user_email = self.db_manager.get_user_and_user_email_by_email(login_form.username.data)
                else:
                    # Find user by email (with form.email)
                    user, user_email = self.db_manager.get_user_and_user_email_by_email(login_form.email.data)
                #Add aditional message
                flash_text = Misc.query.filter_by(field_1='approval_flash').first()
                if not user.initial_admin_approved:
                        flash(flash_text.field_2, 'success')

                if user:
                    # Log user in
                    safe_next_url = self.make_safe_url(login_form.next.data)
                    return self._do_login_user(user, safe_next_url, login_form.remember_me.data)

            # Render form
            tos_db = Misc.query.filter_by(field_1='terms_of_service').first()
            print(Misc.query.filter_by(field_1='terms_of_service').first())
            self.prepare_domain_translations()
            template_filename = self.USER_LOGIN_AUTH0_TEMPLATE if self.USER_ENABLE_AUTH0 else self.USER_LOGIN_TEMPLATE
            return render_template(template_filename,
                          form=login_form,
                          login_form=login_form,
                          tos='hello there!',
                          register_form=register_form)
   
    #user_manager = UserManager(app, db, User)
    user_manager = CustomUserManager(app, db, User)


    # Create all database tables
    db.create_all()


    if not User.query.filter(User.username == 'admin').first():
        user = User(
            username='admin',
            email='admin@no.reply',
            email_confirmed_at=datetime.datetime.utcnow(),
            password=user_manager.hash_password('admin'),
            initial_admin_approved = True,
            notes='Default admin account created during installation.',
            dmr_ids='{}'
        )
        user.roles.append(Role(name='Admin'))
        user.roles.append(Role(name='User'))
        db.session.add(user)
        # Add approval messages to DB for editing
        email_entry_add = Misc(
            field_1 = 'approval_email',
            field_2 = 'You are receiving this message because an administrator has approved your account. You may now login and use ' + title + '.',
            time = datetime.datetime.utcnow()
            )
        db.session.add(email_entry_add)
        flash_entry_add = Misc(
            field_1 = 'approval_flash',
            field_2 = '<strong>You account is waiting for approval from an administrator. See <a href="/help">the Help page</a> for more information. You will receive an email when your account is approved.</strong>',
            time = datetime.datetime.utcnow()
            )
        db.session.add(flash_entry_add)
        tos_entry_add = Misc(
            field_1 = 'terms_of_service',
            field_2 = '''<div class="panel panel-default">
  <div class="panel-heading" style="text-align: center;"><h4>Terms of Use</h4></div>
  <div class="panel-body">
  <p>By using <strong>''' + title + '''</strong>, you agree not to do anything malicious. You agree to use the system with respect and courtesy to others. Please operate with the laws of your country.</p>
  
  </div>
</div>''',
            time = datetime.datetime.utcnow()
            )
        db.session.add(tos_entry_add)
        home_entry_add = Misc(
            field_1 = 'home_page',
            field_2 = '<p>Welcome to <strong>' + title + '</strong></p>.',
            time = datetime.datetime.utcnow()
            )
        db.session.add(home_entry_add)
        db.session.commit()

    # Query radioid.net for list of DMR IDs, then add to DB
    @user_registered.connect_via(app)
    def _after_user_registered_hook(sender, user, **extra):
        edit_user = User.query.filter(User.username == user.username).first()
        radioid_data = ast.literal_eval(get_ids(user.username))
##        edit_user.notes = ''
        edit_user.dmr_ids = str(radioid_data[0])
        edit_user.first_name = str(radioid_data[1])
        edit_user.last_name = str(radioid_data[2])
        edit_user.city = str(radioid_data[3])
        user_role = UserRoles(
            user_id=edit_user.id,
            role_id=2,
            )
        db.session.add(user_role)
        if default_account_state == False:
            edit_user.active = default_account_state
            edit_user.initial_admin_approved = False
        db.session.commit()       

    def gen_passphrase(dmr_id):
        _new_peer_id = bytes_4(int(str(dmr_id)[:7]))
        trimmed_id = int(str(dmr_id)[:7])
        b_list = get_burnlist()
        # print(b_list)
        burned = False
        for ui in b_list.items():
            # print(ui)
            #print(b_list)
            if ui[0] == trimmed_id:
                if ui[0] != 0:
                    calc_passphrase = hashlib.sha256(str(extra_1).encode() + str(extra_int_1).encode() + str(_new_peer_id).encode()[-3:]).hexdigest().upper().encode()[::14] + base64.b64encode(bytes.fromhex(str(hex(libscrc.ccitt((_new_peer_id) + b_list[trimmed_id].to_bytes(2, 'big') + burn_int.to_bytes(2, 'big') + append_int.to_bytes(2, 'big') + bytes.fromhex(str(hex(libscrc.posix((_new_peer_id) + b_list[trimmed_id].to_bytes(2, 'big') + burn_int.to_bytes(2, 'big') + append_int.to_bytes(2, 'big'))))[2:].zfill(8)))))[2:].zfill(4)) + (_new_peer_id) + b_list[trimmed_id].to_bytes(2, 'big') + burn_int.to_bytes(2, 'big') + append_int.to_bytes(2, 'big') + bytes.fromhex(str(hex(libscrc.posix((_new_peer_id) + b_list[trimmed_id].to_bytes(2, 'big') + burn_int.to_bytes(2, 'big') + append_int.to_bytes(2, 'big'))))[2:].zfill(8))) + hashlib.sha256(str(extra_2).encode() + str(extra_int_2).encode() + str(_new_peer_id).encode()[-3:]).hexdigest().upper().encode()[::14]
                    burned = True
        if burned == False:
            calc_passphrase = hashlib.sha256(str(extra_1).encode() + str(extra_int_1).encode() + str(_new_peer_id).encode()[-3:]).hexdigest().upper().encode()[::14] + base64.b64encode(bytes.fromhex(str(hex(libscrc.ccitt((_new_peer_id) + append_int.to_bytes(2, 'big') + bytes.fromhex(str(hex(libscrc.posix((_new_peer_id) + append_int.to_bytes(2, 'big'))))[2:].zfill(8)))))[2:].zfill(4)) + (_new_peer_id) + append_int.to_bytes(2, 'big') + bytes.fromhex(str(hex(libscrc.posix((_new_peer_id) + append_int.to_bytes(2, 'big'))))[2:].zfill(8))) + hashlib.sha256(str(extra_2).encode() + str(extra_int_2).encode() + str(_new_peer_id).encode()[-3:]).hexdigest().upper().encode()[::14]
        if use_short_passphrase == True:
            trim_pass = str(calc_passphrase)[2:-1]
            new_pass = trim_pass[::int(shorten_sample)][-int(shorten_length):]
            return str(new_pass)
        elif use_short_passphrase ==False:
            return str(calc_passphrase)[2:-1]


    def update_from_radioid(callsign):
        edit_user = User.query.filter(User.username == callsign).first()
        #edit_user.dmr_ids = str(ast.literal_eval(get_ids(callsign))[0])
        radioid_dict = ast.literal_eval(get_ids(callsign))[0]
        db_id_dict = ast.literal_eval(edit_user.dmr_ids)
        new_id_dict = db_id_dict.copy()
        for i in radioid_dict.items():
            if i[0] in db_id_dict:
                pass
            elif i[0] not in db_id_dict:
                new_id_dict[i[0]] = 0
        edit_user.dmr_ids = str(new_id_dict)
        edit_user.first_name = str(ast.literal_eval(get_ids(callsign))[1])
        edit_user.last_name = str(ast.literal_eval(get_ids(callsign))[2])
        edit_user.city = str(ast.literal_eval(get_ids(callsign))[3])

        db.session.commit()

    # The Home page is accessible to anyone
    @app.route('/')
    def home_page():
        home_text = Misc.query.filter_by(field_1='home_page').first()
        #content = Markup('<strong>Index</strong>')
        try:
            l_news = News.query.order_by(News.time.desc()).first()
            content = '''

<div class="well well-sm" style="text-align: center;"><h3>''' + l_news.subject + '''</h3>
<hr />
<p>&nbsp;</p>
<strong>''' + l_news.date + '''</strong> - <a href="/news/''' + str(l_news.id) + '''"><button type="button" class="btn btn-primary">Link</button></a>
<p>&nbsp;</p>

<hr />
<div class="well well-sm" style="max-width:900px; word-wrap:break-word;">
''' + l_news.text + '''
</div>
</div>
  
  </div>
    '''
        except:
            content = ''
        return render_template('index.html', news = Markup(content), content_block = Markup(home_text.field_2))

    @app.route('/tos')
    def tos_page():
        tos_text = Misc.query.filter_by(field_1='terms_of_service').first()
        content = tos_text.field_2
        
        return render_template('flask_user_layout.html', markup_content = Markup(content))

    @app.route('/map')
    @login_required
    def map_page():
        dev_loc = GPS_LocLog.query.order_by(GPS_LocLog.time.desc()).limit(300).all()
        dev_list = []
        f_map = folium.Map(location=center_map, zoom_start=map_zoom)
        for i in dev_loc:
            if i.callsign in dev_list:
                pass
            elif i.callsign not in dev_list:
                dev_list.append(i.callsign)
                lat = i.lat
                lon = i.lon
                if 'S' in i.lat:
                    lat = aprs_to_latlon(float(re.sub('[A-Za-z]','', i.lat)))
                    lat = -lat
                if 'S' not in i.lat:
                    lat = aprs_to_latlon(float(re.sub('[A-Za-z]','', i.lat)))
                if 'W' in i.lon:
                    lon = aprs_to_latlon(float(re.sub('[A-Za-z]','', i.lon)))
                    lon = -lon
                if 'W' not in i.lon:
                    lon = aprs_to_latlon(float(re.sub('[A-Za-z]','', i.lon)))
                folium.Marker([lat, lon], popup="""<i>
                    <table style="width: 150px;">
                    <tbody>
                    <tr>
                    <td style="text-align: center;">Last Location:</td>
                    </tr>
                    <tr>
                    <td style="text-align: center;"><strong>"""+ str(i.callsign) +"""</strong></td>
                    </tr>
                    <tr>
                    <td style="text-align: center;"><em>"""+ str(i.time.strftime(time_format)) +"""</em></td>
                    """ + i.comment + """
                    </tr>
                    </tbody>
                    </table>
                    </i>
                    """, icon=folium.Icon(color="blue", icon="record"), tooltip='<strong>' + i.callsign + '</strong>').add_to(f_map)
        for l in peer_locations.items():
##            folium.Marker([float(l[1][1]), float(l[1][2])], popup='''
##<div class="panel panel-default">
##  <div class="panel-heading" style="text-align: center;"><h4>''' + l[1][0] + '''</h4></div>
##  <div class="panel-body">
##  ''' + l[1][5] + '''
##  <hr />
##  ''' + l[1][1] + ''', ''' + l[1][2] + '''
##  <hr />
##  ''' + l[1][3] + '''
##  <hr />
##  ''' + l[1][4] + '''
##  <hr />
##  ''' + l[1][6] + '''
##    </div>
##</div>
##         ''', icon=folium.Icon(color="red", icon="record"), tooltip='<strong>' + l[1][0] + '</strong>').add_to(f_map)

            folium.Marker([float(l[1][1]), float(l[1][2])], popup='''
<table border="1">
<tbody>
<tr>
<td>&nbsp;<strong><h4>''' + l[1][0] + '''</strong></h4>&nbsp;</td>
</tr>
</tbody>
</table>
<table border="1">
<tbody>
<tr>
<td style="width: 64.4667px;"><strong>DMR ID:</strong></td>
<td>&nbsp;''' + str(l[0]) + '''&nbsp;</td>
</tr>
<tr>
<td style="width: 64.4667px;"><strong>Location:</strong></td>
<td>&nbsp;''' + l[1][5] + '''&nbsp;</td>
</tr>
<tr>
<td style="width: 64.4667px;"><strong>Lat, Lon:</strong></td>
<td>&nbsp;''' + l[1][1] + ''', ''' + l[1][2] + '''&nbsp;</td>
</tr>
<tr>
<td style="width: 64.4667px;"><strong>Description:</strong></td>
<td>&nbsp;''' + l[1][4] + '''&nbsp;</td>
</tr>
<tr>
<td style="width: 64.4667px;"><p><strong>URL:</strong></p>
</td>
<td><a href="''' + l[1][3] + '''">&nbsp;''' + l[1][3] + '''&nbsp;</a></td>
</tr>
<tr>
<td style="width: 64.4667px;"><strong>Device:</strong></td>
<td>&nbsp;''' + l[1][6] + '''&nbsp;</td>
</tr>
</tbody>
</table>
         ''', icon=folium.Icon(color="red", icon="record"), tooltip='<strong>' + l[1][0] + '</strong>').add_to(f_map)
        content = f_map._repr_html_()
       
        return render_template('map.html', markup_content = Markup(content))
    
    @app.route('/help')
    def help_page():
        return render_template('help.html')

    @app.route('/generate_passphrase/pi-star', methods = ['GET'])
    @login_required
    def gen_pi_star():
        try:
            u = current_user
            id_dict = ast.literal_eval(u.dmr_ids)
            #u = User.query.filter_by(username=user).first()
    ##        print(request.args.get('mode'))
    ##        if request.args.get('mode') == 'generated':
            content = ''
            for i in id_dict.items():
                #if i[1] == '':
                link_num = str(random.randint(1,99999999)).zfill(8) + str(time.time()) + str(random.randint(1,99999999)).zfill(8)
                script_links[i[0]] = link_num
                content = content + '''
        <div class="panel panel-default">
  <div class="panel-heading" style="text-align: center;"><h4>ID: ''' + str(i[0]) + '''</h4></div>
  <div class="panel-body"><pre>rpi-rw; wget -O /root/auto_pistar.py "<a href="''' + str(url) + '/get_script?dmr_id=' + str(i[0]) + '&number=' + str(link_num) + '''">''' + str(url) + '/get_script?dmr_id=' + str(i[0]) + '&number=' + str(link_num) + '''</a>"; chmod +x /root/auto_pistar.py; python3 /root/auto_pistar.py; pistar-update</pre></div>
</div>
    '''
                #else:
                #    content = content + '''\n<p style="text-align: center;">Error</p>'''
            
        except:
            content = Markup('<strong>No DMR IDs found or other error.</strong>')
        
            
        #return str(content)
        return render_template('pi-star_gen.html', markup_content = Markup(content))
        

    
    @app.route('/generate_passphrase', methods = ['GET'])
    @login_required
    def gen():
        #print(str(gen_passphrase(3153591))) #(int(i[0])))
        sl = ServerList.query.all()
        svr_content = ''
        for i in sl:
            try:
                if time.time() - ping_list[i.name] < 20:
                    svr_status = '''<div class="alert alert-success">
      <strong>Online</strong>
       </div> '''
                elif time.time() - ping_list[i.name] <= 300:
                    svr_status = '''<div class="alert alert-warning">
      <strong>Unknown <br /> (No pings, less than 5 min.)</strong>
       </div> '''
                elif time.time() - ping_list[i.name] > 300:
                    svr_status = '''<div class="alert alert-danger">
      <strong>Offline</strong>
       </div> '''
                else:
                    svr_status = '''<div class="alert alert-warning">
      <strong>Unknown Condition</strong>
       </div> '''
                    print(ping_list)
                    print(time.time())
            except:
                svr_status = '''<div class="alert alert-warning">
      <strong>Unknown</strong>
       </div> '''
               
            svr_content = svr_content + '''
<div class="panel panel-default">
  <div class="panel-heading" style="text-align: center;"><h3>''' + i.name + '''</h3></div>
  <div class="panel-body container-fluid center;">
  <hr />
  ''' + svr_status + '''
    <div style="max-width:200px; word-wrap:break-word; text-align: center;">''' + i.public_notes + '''</div>
    <p>&nbsp;</p>
    <a href="/talkgroups/''' + i.name + '''"><button type="button" class="btn btn-primary btn-block" >Available Talkgroups</button></a>
    <hr />
    <a href="''' + i.dash_url + '''"><button  type="button" class="btn btn-success btn-block" >Dashboard</button></a>

  </div>
</div>

'''
        try:
            #user_id = request.args.get('user_id')
            u = current_user
            id_dict = ast.literal_eval(u.dmr_ids)
            #u = User.query.filter_by(username=user).first()
    ##        if request.args.get('mode') == 'generated':
          
            content = '\n'
            for i in id_dict.items():
                if isinstance(i[1], int) == True and i[1] != 0:
                    link_num = str(random.randint(1,99999999)).zfill(8) + str(time.time()) + str(random.randint(1,99999999)).zfill(8)
                    script_links[i[0]] = link_num
                    #print(script_links)
                    content = content + '''\n
            <div class="panel panel-default" style="text-align: center;">
  <div class="panel-heading"><h4>''' + str(i[0]) + '''</h4></div>
  <div class="panel-body" style="max-width:300px; word-wrap:break-word; text-align: center;">MMDVM Passphrase:
  <pre><strong>''' + str(gen_passphrase(int(i[0]))) + '''</strong></pre>
  <hr />
  <br />
  <p class="bg-warning"><em>''' + convert_nato(str(gen_passphrase(int(i[0])))) + '''</em></p>
  </div>
</div>
        '''
                elif i[1] == 0:
                    link_num = str(random.randint(1,99999999)).zfill(8) + str(time.time()) + str(random.randint(1,99999999)).zfill(8)
                    script_links[i[0]] = link_num
                    #print(script_links)
                    content = content + '''\n
<div class="panel panel-default" style="text-align: center;">
  <div class="panel-heading"><h4>''' + str(i[0]) + '''</h4></div>
  <div class="panel-body" style="max-width:300px; word-wrap:break-word; text-align: center;">MMDVM Passphrase:
  <pre><strong>''' + str(gen_passphrase(int(i[0]))) + '''</strong></pre>
  <hr />
  <br />
  <p class="bg-warning"><em>''' + convert_nato(str(gen_passphrase(int(i[0])))) + '''</em></p>
  </div>
</div>
        '''
                elif i[1] == '':
                    content = content + '''
<div class="panel panel-default" style="text-align: center;">
  <div class="panel-heading"><h4>''' + str(i[0]) + '''</h4></div>
  <div class="panel-body" style="max-width:300px; word-wrap:break-word; text-align: center;">MMDVM Passphrase:
  <pre><strong>''' + legacy_passphrase + '''</strong></pre>
  <hr />
  <br />
  <p class="bg-warning"><em>''' + convert_nato(legacy_passphrase) + '''</em></p>
  </div>
</div>
            '''
                else:
                    content = content + '''
  <div class="panel panel-default" style="text-align: center;">
  <div class="panel-heading"><h4>''' + str(i[0]) + '''</h4></div>
  <div class="panel-body" style="max-width:300px; word-wrap:break-word; text-align: center;">MMDVM Passphrase:
  <pre><strong>''' + str(i[1]) + '''</strong></pre>
  <hr />
  <br />
  <p class="bg-warning"><em>''' + convert_nato(str(i[1])) + '''</em></p>
  </div>
</div>   
    '''
            #content = content + '\n\n' + str(script_links[i[0]])
        except:
            content = Markup('<strong>No DMR IDs found or other error.</strong>')
        
            
        #return str(content)
        return render_template('view_passphrase.html', passphrase_content = Markup(content), server_content = Markup(svr_content))

  
    @app.route('/update_ids', methods=['POST', 'GET'])
    @login_required    # User must be authenticated
    def update_info():
        #print(request.args.get('callsign'))
        #print(current_user.username)
        if request.args.get('callsign') == current_user.username or request.args.get('callsign') and request.args.get('callsign') != current_user.username and current_user.has_roles('Admin'):
            content = '<h3 style="text-align: center;"><strong>Updated your information.</strong></h3>'
            update_from_radioid(request.args.get('callsign'))
        else:
            content = '''
<p>Use this page to sync changes from <a href="https://www.radioid.net/">RadioID.net</a> with this system (such as a new DMR ID, name change, etc.).</p>
<p>Update your information from <a href="https://www.radioid.net/">RadioID.net</a> to change your city, name, or add any additional DMR IDs.</p>
<p>&nbsp;</p>
<h2 style="text-align: center;"><a href="update_ids?callsign=''' + current_user.username + '''">Yes, update my information.</a></h2>

'''
        return render_template('flask_user_layout.html', markup_content = Markup(content))


    @app.route('/email_user', methods=['POST', 'GET'])
    @roles_required('Admin')
    @login_required    # User must be authenticated
    def email_user():
        
        if request.method == 'GET' and request.args.get('callsign'):
            content = '''
<h2 style="text-align: center;">Send email to user: ''' + request.args.get('callsign') + '''</h2>
<table style="margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td style="text-align: center;"><form action="/email_user?callsign=''' + request.args.get('callsign') + '''" method="POST">
<p><strong><label for="fname"><br />Subject<br /></label></strong><br /> <input id="subject" name="subject" type="text" /><br /><br /><strong> <label for="message">Message<br /></label></strong><br /><textarea cols="40" name="message" rows="5"></textarea><br /><br /> <input type="submit" value="Submit" /></p>
</form></td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>'''
        elif request.method == 'POST': # and request.form.get('callsign') and request.form.get('subject') and request.form.get('message'):
            u = User.query.filter_by(username=request.args.get('callsign')).first()
            msg = Message(recipients=[u.email],
                          sender=(title, MAIL_DEFAULT_SENDER),
                          subject=request.form.get('subject'),
                          body=request.form.get('message'))
            mail.send(msg)
            content = '<p style="text-align: center;"><strong>Sent email to: ' + u.email + '</strong></p>'
        else:
            content = '''<p style="text-align: center;"><strong>Find user in "List Users", then click on the email link.'</strong></p>'''
        return render_template('flask_user_layout.html', markup_content = Markup(content))
        
        

    @app.route('/list_users')
    @roles_required('Admin')
    @login_required    # User must be authenticated
    def list_users():
        u = User.query.all()
        # Broken for now, link taken out - <h2 style="text-align: center;"><strong>List/edit users:</strong></h2><p>&nbsp;</p><p style="text-align: center;"><a href="edit_user"><strong>Enter Callsign</strong></a></p>
        u_list = '''<p>&nbsp;</p><table style="width: 700px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td style="width: 107px; text-align: center;"><strong>Callsign</strong></td>
<td style="width: 107px; text-align: center;"><strong>Name</strong></td>
<td style="width: 226.683px; text-align: center;"><strong>Enabled</strong></td>
<td style="width: 522.317px; text-align: center;"><strong>DMR ID:Authentication</strong></td>
<td style="width: 522.317px; text-align: center;"><strong>Notes</strong></td>
</tr>'''
        for i in u:
            u_list = u_list + '''
<tr>
<td style="width: 107px;"><a href="''' + url + '/edit_user?callsign=' + str(i.username) +'''"><strong>&nbsp;''' + str(i.username) + '''&nbsp;</strong></a></td>
<td style="width: 226.683px; text-align: center;">&nbsp;''' + str(i.first_name) + ' ' + str(i.last_name) + '''&nbsp;</td>
<td style="width: 226.683px; text-align: center;">&nbsp;''' + str(i.active) + '''&nbsp;</td>
<td style="width: 522.317px;">&nbsp;''' + str(i.dmr_ids) + '''&nbsp;</td>
<td style="width: 622.317px;">&nbsp;''' + str(i.notes) + '''&nbsp;</td>
</tr>
'''+ '\n'
        content = u_list + '''</tbody>
                              </table>
                              <p>&nbsp;</p>'''
        return render_template('flask_user_layout.html', markup_content = Markup(content))
    
    @app.route('/approve_users', methods=['POST', 'GET'])
    @login_required
    @roles_required('Admin')    # Use of @roles_required decorator
    def approve_list():
        u = User.query.all()
        wait_list = '''<h2 style="text-align: center;"><strong>Users waiting for approval:</strong></h2>
<p>&nbsp;</p>

<p style="text-align: center;">Click on the callsign to approve user. An email may be sent to inform the user that they can login.</p>

<p>&nbsp;</p>
<table style="width: 700px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td style="width: 107px; text-align: center;"><strong>Callsign</strong></td>
<td style="width: 107px; text-align: center;"><strong>Name</strong></td>
<td style="width: 226.683px; text-align: center;"><strong>Enabled</strong></td>
<td style="width: 522.317px; text-align: center;"><strong>DMR ID:Authentication</strong></td>
</tr>'''
        for i in u:
##            print(i.username)
##            print(i.initial_admin_approved)
            if i.initial_admin_approved == False:
                wait_list = wait_list+ '''
<tr>
<td style="width: 107px;">&nbsp;<a href="''' + url + '/edit_user?callsign=' + str(i.username) +'''&admin_approve=true"><strong>''' + str(i.username) + '''</strong></a>&nbsp;</td>
<td style="width: 226.683px; text-align: center;">&nbsp;''' + str(i.first_name) + ' ' + str(i.last_name) + '''&nbsp;</td>
<td style="width: 226.683px; text-align: center;">&nbsp;''' + str(i.active) + '''&nbsp;</td>
<td style="width: 522.317px;">&nbsp;''' + str(i.dmr_ids) + '''&nbsp;</td>
</tr>
'''+ '\n'
            content = wait_list + '''</tbody>
                              </table>
                              <p>&nbsp;</p>'''
        return render_template('flask_user_layout.html', markup_content = Markup(content))
                

    
    # The Admin page requires an 'Admin' role.
    @app.route('/edit_user', methods=['POST', 'GET'])
    @login_required
    @roles_required('Admin')    # Use of @roles_required decorator
    def admin_page():
        #print(request.args.get('callsign'))
        #print(request.args.get('callsign'))
##        if request.method == 'POST' and request.form.get('callsign'):
##            #result = request.json
##            callsign = request.form.get('callsign')
##            u = User.query.filter_by(username=callsign).first()
##            content = u.dmr_ids
        if request.method == 'POST' and request.args.get('callsign') == None:
            content = 'Not found'
        elif request.method == 'POST' and request.args.get('callsign') and request.form.get('user_status'):
            user = request.args.get('callsign')
            #print(user)
            edit_user = User.query.filter(User.username == user).first()
            content = ''
            if request.form.get('user_status') != edit_user.active:
                if request.form.get('user_status') == "True":
                    edit_user.active = True
                    content = content + '''<p style="text-align: center;">User <strong>''' + str(user) + '''</strong> has been enabled.</p>\n'''
                if request.form.get('user_status') == "False":
                    edit_user.active = False
                    content = content + '''<p style="text-align: center;">User <strong>''' + str(user) + '''</strong> has been disabled.</p>\n'''
##                print(request.form.get('username'))
            if user != request.form.get('username'):
####                #print(edit_user.username)
                content = content + '''<p style="text-align: center;">User <strong>''' + str(user) + '''</strong> changed to <strong>''' + request.form.get('username') + '''</strong>.</p>\n'''
                edit_user.username = request.form.get('username')
            if request.form.get('email') != edit_user.email:
                edit_user.email = request.form.get('email')
                content = content + '''<p style="text-align: center;">Changed email for user: <strong>''' + str(user) + ''' to ''' + request.form.get('email') + '''</strong></p>\n'''
            if request.form.get('notes') != edit_user.notes:
                edit_user.notes = request.form.get('notes')
                content = content + '''<p style="text-align: center;">Changed notes for user: <strong>''' + str(user) + '''</strong>.</p>\n'''
            if request.form.get('password') != '':
                edit_user.password = user_manager.hash_password(request.form.get('password'))
                content = content + '''<p style="text-align: center;">Changed password for user: <strong>''' + str(user) + '''</strong></p>\n'''
            if request.form.get('dmr_ids') != edit_user.dmr_ids:
                edit_user.dmr_ids = request.form.get('dmr_ids')
                dmr_auth_dict = ast.literal_eval(request.form.get('dmr_ids'))
                for id_user in dmr_auth_dict:
                    if isinstance(dmr_auth_dict[id_user], int) == True and dmr_auth_dict[id_user] != 0:
                        #print('burn it')
                        if id_user in get_burnlist():
##                            print('burned')
                            if get_burnlist()[id_user] != dmr_auth_dict[id_user]:
##                                print('update vers')
                                update_burnlist(id_user, dmr_auth_dict[id_user])
                            else:
                                pass
##                                print('no update')
                        else:
                            add_burnlist(id_user, dmr_auth_dict[id_user])
##                            print('not in list, adding')
                    elif isinstance(dmr_auth_dict[id_user], int) == False and id_user in get_burnlist():
                        delete_burnlist(id_user)
##                        print('remove from burn list - string')
                    elif dmr_auth_dict[id_user] == 0:
##                        print('remove from burn list')
                        if id_user in get_burnlist():
                            delete_burnlist(id_user)

                
                
                content = content + '''<p style="text-align: center;">Changed authentication settings for user: <strong>''' + str(user) + '''</strong></p>\n'''
            db.session.commit()
            #edit_user = User.query.filter(User.username == request.args.get('callsign')).first()
        elif request.method == 'GET' and request.args.get('callsign') and request.args.get('delete_user') == 'true':
            delete_user = User.query.filter(User.username == request.args.get('callsign')).first()
            db.session.delete(delete_user)
            db.session.commit()
            content = '''<p style="text-align: center;">Deleted user: <strong>''' + str(delete_user.username) + '''</strong></p>\n'''

        elif request.method == 'GET' and request.args.get('callsign') and request.args.get('make_user_admin') == 'true':
            u = User.query.filter_by(username=request.args.get('callsign')).first()
            u_role = UserRoles.query.filter_by(user_id=u.id).first()
            u_role.role_id = 1
            db.session.commit()
            content = '''<p style="text-align: center;">User now Admin: <strong>''' + str(request.args.get('callsign')) + '''</strong></p>\n'''
           
        elif request.method == 'GET' and request.args.get('callsign') and request.args.get('make_user_admin') == 'false':
            u = User.query.filter_by(username=request.args.get('callsign')).first()
            u_role = UserRoles.query.filter_by(user_id=u.id).first()
            u_role.role_id = 2
            db.session.commit()
            content = '''<p style="text-align: center;">Admin now a user: <strong>''' + str(request.args.get('callsign') ) + '''</strong></p>\n'''
            
        elif request.method == 'GET' and request.args.get('callsign') and request.args.get('admin_approve') == 'true':
            edit_user = User.query.filter(User.username == request.args.get('callsign')).first()
            edit_user.active = True
            edit_user.initial_admin_approved = True
            db.session.commit()
            email_text = Misc.query.filter_by(field_1='approval_email').first()
            try:
                msg = Message(recipients=[edit_user.email],
                              sender=(title, MAIL_DEFAULT_SENDER),
                              subject='Account Approval',
                              body = str(email_text.field_2))
                mail.send(msg)
            except:
                content = 'Failed to send email. Approved user anyway'
            content = content + '''<p style="text-align: center;">User approved: <strong>''' + str(request.args.get('callsign')) + '''</strong></p>\n'''
            
        elif request.method == 'GET' and request.args.get('callsign') and request.args.get('email_verified') == 'true':
            edit_user = User.query.filter(User.username == request.args.get('callsign')).first()
            edit_user.email_confirmed_at = datetime.datetime.utcnow()
            db.session.commit()
            content = '''<p style="text-align: center;">Email verified for: <strong>''' + str(request.args.get('callsign')) + '''</strong></p>\n'''
                  
        elif request.method == 'POST' and request.form.get('callsign') and not request.form.get('user_status')  or request.method == 'GET' and request.args.get('callsign'):# and request.form.get('user_status') :
            if request.args.get('callsign'):
                callsign = request.args.get('callsign')
            if request.form.get('callsign'):
                callsign = request.form.get('callsign')
            u = User.query.filter_by(username=callsign).first()
            user_email_address = 'None'
            if str(u.email):
                user_email_address = str(u.email)
            confirm_link = ''
            if u.email_confirmed_at == None:
                confirm_link = '''<p style="text-align: center;"><a href="''' + url + '/edit_user?email_verified=true&callsign=' + str(u.username) + '''"><strong>Verify email -  <strong>''' + str(u.username) + '''</strong></strong></a></p>\n'''
            u_role = UserRoles.query.filter_by(user_id=u.id).first()
            if u_role.role_id == 2:
                # Link to promote to Admin
                role_link = '''<p style="text-align: center;"><a href="''' + url + '/edit_user?make_user_admin=true&callsign=' + str(u.username) + '''"><strong>Give Admin role: <strong>''' + str(u.username) + '''</strong></strong></a></p>\n'''
            if u_role.role_id == 1:
                # Link to promote to User
                role_link = '''<p style="text-align: center;"><a href="''' + url + '/edit_user?make_user_admin=false&callsign=' + str(u.username) + '''"><strong>Revert to User role: <strong>''' + str(u.username) + '''</strong></strong></a></p>\n'''
            id_dict = ast.literal_eval(u.dmr_ids)
            passphrase_list = '''
<table style="width: 600px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td style="text-align: center;"><strong>DMR ID</strong></td>
<td style="text-align: center;"><strong>Passphrase</strong></td>
</tr> '''
            for i in id_dict.items():
##                print(i[1])
                if isinstance(i[1], int) == True: 
                    passphrase_list = passphrase_list + '''
<tr>
<td style="text-align: center;">''' + str(i[0]) + '''</td>
<td style="text-align: center;">''' + str(gen_passphrase(int(i[0]))) + '''</td>
</tr> \n'''
                if i[1] == '':
                    passphrase_list = passphrase_list + '''<tr>
<td style="text-align: center;">''' + str(i[0]) + '''</td>
<td style="text-align: center;">''' + legacy_passphrase + '''</td>
</tr> \n'''
                if not isinstance(i[1], int) == True and i[1] != '':
                    passphrase_list = passphrase_list + '''<tr>
<td style="text-align: center;">''' + str(i[0]) + '''</td>
<td style="text-align: center;">''' + str(i[1]) + '''</td>
</tr> \n'''
            
            passphrase_list = passphrase_list + '</tbody></table>' 
            content = '''
<p>&nbsp;</p>

<table style="width: 500px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td style="text-align: center;"><strong>First Name</strong></td>
<td style="text-align: center;"><strong>Last Name</strong></td>
</tr>
<tr>
<td>&nbsp;''' + u.first_name + '''</td>
<td>&nbsp;''' + u.last_name + '''</td>
</tr>
<tr>
<td style="text-align: center;"><strong>City</strong></td>
<td>''' + u.city + '''</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>

''' + passphrase_list + '''

<h3 style="text-align: center;">&nbsp;Options for: ''' + u.username  + '''&nbsp;</h3>

<table style="width: 600px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td>&nbsp;
<p style="text-align: center;"><strong><a href="update_ids?callsign=''' + u.username + '''">Update from RadioID.net</a></strong></p>
&nbsp;</td>
<td>&nbsp;''' + confirm_link + '''&nbsp; <br /><p style="text-align: center;"><strong>Email confirmed: ''' + str(u.email_confirmed_at.strftime(time_format)) + '''</strong></p></td>
</tr>
<tr>
<td>&nbsp;
<p style="text-align: center;"><strong><a href="email_user?callsign=''' + u.username + '''">Send user an email</a></strong></p>
&nbsp;</td>
<td>&nbsp;''' + role_link + '''&nbsp;</td>
</tr>
<tr>
<td>&nbsp;<p style="text-align: center;"><strong><a href="auth_log?portal_username=''' + u.username + '''">View user auth log</a></strong></p>
&nbsp;</td>
<td>&nbsp;
<p style="text-align: center;"><a href="''' + url + '/edit_user?delete_user=true&amp;callsign=' + str(u.username) + '''"><strong>Deleted user</strong></strong></a></p>
&nbsp;</td>
</tr>
</tbody>
</table>

<td><form action="edit_user?callsign=''' + callsign + '''" method="POST">
<table style="margin-left: auto; margin-right: auto;">
<tbody>
<tr style="height: 62px;">
<td style="text-align: center; height: 62px;">
<strong><label for="user_id">Enable/Disable</label></strong>
</td>
</tr>


<tr style="height: 51.1667px;">
<td style="height: 51.1667px; text-align: center;"><select name="user_status">
<option selected="selected" value="''' + str(u.active) + '''">Current: ''' + str(u.active) + '''</option>
<option value="True">True</option>
<option value="False">False</option>
</select></td></td>
</tr>

<tr style="height: 51.1667px;">
<td style="height: 51.1667px; text-align: center;">
  <label for="username">Portal Email:</label><br>
  <input type="text" id="email" name="email" value="''' + user_email_address + '''"><br>
</td></tr>

<tr style="height: 51.1667px;">
<td style="height: 51.1667px; text-align: center;">
  <label for="username">Portal Username:</label><br>
  <input type="text" id="username" name="username" value="''' + u.username + '''"><br>
</td></tr>

<tr style="height: 51.1667px;">
<td style="height: 51.1667px; text-align: center;">
  <label for="username">Portal Password:</label><br>
  <input type="text" id="password" name="password" value=""><br>
</td></tr>

<tr style="height: 51.1667px;">
<td style="height: 51.1667px; text-align: center;">
  <label for="username">MMDVM Authentication Settings:</label><br>
  <input type="text" id="dmr_ids" name="dmr_ids" value="''' + str(u.dmr_ids) + '''"><br>
</td></tr>

<tr style="height: 51.1667px;">
<td style="height: 51.1667px; text-align: center;">
<label for="message">Notes<br /></label></strong><br /><textarea cols="40" name="notes" rows="5" >''' + str(u.notes) + '''</textarea><br /><br />
</td></tr>


<tr style="height: 27px;">
<td style="text-align: center; height: 27px;"><input type="submit" value="Submit" /></td>
</tr>
</tbody>
</table>
</form></td>

</tr>
</tbody>
</table>
<p>&nbsp;</p>

<h3 style="text-align: center;">&nbsp;Passphrase Authentication Method Key</h3>
<table style="width: 300px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td style="width: 70.8px; text-align: center;"><strong>Calculated</strong></td>
<td style="width: 103.45px; text-align: center;"><strong>Legacy (config)</strong></td>
<td style="width: 77.7167px; text-align: center;"><strong>Custom</strong></td>
</tr>
<tr>
<td style="text-align: center; width: 70.8px;">0 - default,<br />1-999 - new calculation</td>
<td style="text-align: center; width: 103.45px;">''</td>
<td style="text-align: center; width: 77.7167px;">'passphrase'</td>
</tr>
</tbody>
</table>
<p style="text-align: center;"><strong>{</strong>DMR ID<strong>:</strong> Method<strong>,</strong> 2nd DMR ID<strong>:</strong> Method<strong>}</strong></p>
<p style="text-align: center;">Example:<br /><strong>{</strong>1234567<strong>: '',</strong> 134568<strong>: 0,</strong> 1234569<strong>: '</strong>passphr8s3<strong>'}</strong></p>


'''
        else:
            content = '''
<table style="width: 600px; margin-left: auto; margin-right: auto;" border="3">
<tbody>
<tr>
<td><form action="edit_user" method="POST">
<table style="margin-left: auto; margin-right: auto;">
<tbody>
<tr style="height: 62px;">
<td style="text-align: center; height: 62px;">
<h2><strong><label for="user_id">Callsign</label></strong></h2>
</td>
</tr>
<tr style="height: 51.1667px;">
<td style="height: 51.1667px; text-align: center;"><input id="callsign" name="callsign" type="text" /></td>
</tr>
<tr style="height: 27px;">
<td style="text-align: center; height: 27px;"><input type="submit" value="Submit" /></td>
</tr>
</tbody>
</table>
</form></td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
'''
       
        return render_template('flask_user_layout.html', markup_content = Markup(content))

    @app.route('/get_script')
    def get_script():
        dmr_id = int(request.args.get('dmr_id'))
        number = float(request.args.get('number'))
        #print(type(script_links[dmr_id]))
        u = User.query.filter(User.dmr_ids.contains(request.args.get('dmr_id'))).first()

        pub_list = []
        

        
        #print(u.dmr_ids)

        if authorized_peer(dmr_id)[1] == 0:
            passphrase = gen_passphrase(dmr_id)
        elif authorized_peer(dmr_id)[1] != 0 and isinstance(authorized_peer(dmr_id)[1], int) == True:
            passphrase = gen_passphrase(dmr_id)
        elif authorized_peer(dmr_id)[1] == '':
            passphrase = legacy_passphrase
        elif authorized_peer(dmr_id)[1] != '' or authorized_peer(dmr_id)[1] != 0:
            passphrase = authorized_peer(dmr_id)[1]
        #try:
        if dmr_id in script_links and number == float(script_links[dmr_id]):
            script_links.pop(dmr_id)
            
            ml = MasterList.query.filter_by(public_list=True).filter_by(active=True).all()
            pl = ProxyList.query.filter_by(public_list=True).filter_by(active=True).all()
            print(ml)
            print(pl)
            for m in ml:
                print(m.name)
##                print(m.server)
##                print(m.port)
##                print(m.enable_um)
##                print(m.passphrase)
                sl = ServerList.query.filter_by(name=m.server).first()
##                print(sl.ip)
                if m.enable_um == True:
                    passp = passphrase
                pub_list.append([m.server + '_' + m.name, sl.ip, passphrase, m.port])
            for p in pl:
                sl = ServerList.query.filter_by(name=p.server).first()
                if p.enable_um == True:
                    passp = passphrase
                pub_list.append([p.server + '_' + p.name, sl.ip, passphrase, p.external_port])


            
            return str(gen_script(dmr_id, pub_list))
        #except:
            #else:
            #content = '<strong>Link used or other error.</strong>'
            #return content
            #return render_template('flask_user_layout.html', markup_content = content, logo = logo)
        

    def authorized_peer(peer_id):
        try:
            u = User.query.filter(User.dmr_ids.contains(str(peer_id))).first()
            login_passphrase = ast.literal_eval(u.dmr_ids)
            return [u.is_active, login_passphrase[peer_id], str(u.username)]
        except:
            return [False]

    @app.route('/auth_log', methods=['POST', 'GET'])
    @login_required    # User must be authenticated
    @roles_required('Admin')
    def all_auth_list():
        if request.args.get('flush_db') == 'true':
            content = '''<p style="text-align: center;"><strong>Flushed entire auth DB.</strong></strong></p>\n'''
            authlog_flush()
        elif request.args.get('flush_user_db') == 'true' and request.args.get('portal_username'):
            content = '''<p style="text-align: center;"><strong>Flushed auth DB for: ''' + request.args.get('portal_username') + '''</strong></strong></p>\n'''
            authlog_flush_user(request.args.get('portal_username'))
        elif request.args.get('flush_db_mmdvm') == 'true' and request.args.get('mmdvm_server'):
            content = '''<p style="text-align: center;"><strong>Flushed auth DB for: ''' + request.args.get('mmdvm_server') + '''</strong></strong></p>\n'''
            authlog_flush_mmdvm_server(request.args.get('mmdvm_server'))
        elif request.args.get('flush_db_ip') == 'true' and request.args.get('peer_ip'): 
            content = '''<p style="text-align: center;"><strong>Flushed auth DB for: ''' + request.args.get('peer_ip') + '''</strong></strong></p>\n'''
            authlog_flush_ip(request.args.get('peer_ip'))
        elif request.args.get('flush_dmr_id_db') == 'true' and request.args.get('dmr_id'):
            content = '''<p style="text-align: center;"><strong>Flushed auth DB for: ''' + request.args.get('dmr_id') + '''</strong></strong></p>\n'''
            authlog_flush_dmr_id(request.args.get('dmr_id'))
        elif request.args.get('portal_username') and not request.args.get('flush_user_db') and not request.args.get('flush_dmr_id_db') or request.args.get('dmr_id') and not request.args.get('flush_user_db') and not request.args.get('flush_dmr_id_db'):
            if request.args.get('portal_username'):
##                s_filter = portal_username=request.args.get('portal_username')
                a = AuthLog.query.filter_by(portal_username=str(request.args.get('portal_username')).strip('"')).order_by(AuthLog.login_time.desc()).all()
                g_arg = str(request.args.get('portal_username')).strip('"')
                f_link = '''    <p style="text-align: center;"><strong><a href="auth_log?flush_user_db=true&portal_username=''' + request.args.get('portal_username') + '''"><button type="button" class="btn btn-danger">Flush auth log for: ''' + request.args.get('portal_username') + '''</button></a></strong></p>'''
            elif request.args.get('dmr_id'):
##                s_filter = login_dmr_id=request.args.get('dmr_id')
                a = AuthLog.query.filter_by(login_dmr_id=request.args.get('dmr_id')).order_by(AuthLog.login_time.desc()).all()
                g_arg = request.args.get('dmr_id')
                f_link = '''<p style="text-align: center;"><strong><a href="auth_log?flush_dmr_id_db=true&dmr_id=''' + request.args.get('dmr_id') + '''"><button type="button" class="btn btn-danger">Flush auth log for: ''' + request.args.get('dmr_id') + '''</button></a></strong></p>'''
##            print(s_filter)
##            a = AuthLog.query.filter_by(s_filter).order_by(AuthLog.login_dmr_id.desc()).all()

            content = '''
    <p>&nbsp;</p>

    <p style="text-align: center;"><strong>Log for: ''' + g_arg + '''</strong></p>

    ''' + f_link + '''

    <table style="margin-left: auto; margin-right: auto;" border="1">
    <tbody>
    <tr>
    <td>&nbsp;<span style="color: #000000; background-color: #ff2400;">&nbsp;<strong>Failed</strong></span>&nbsp;= Not authorized.&nbsp;</td>
    <td>&nbsp;<span style="color: #000000; background-color: #ffff00;"><strong>Attempt</strong></span>&nbsp;= Checking if authorized.&nbsp;</td>
    <td>&nbsp;<span style="color: #000000; background-color: #00ff00;"><strong>Confirmed</strong></span>&nbsp;= Authorized, connection comfirmed.&nbsp;</td>
    </tr>
    </tbody>
    </table>
    <p>&nbsp;</p>
    
    <table style="width: 1000px; margin-left: auto; margin-right: auto;" border="1">
    <tbody>
    <tr>
    <td style="text-align: center;">
    <h4>&nbsp;DMR ID&nbsp;</h4>
    </td>
    <td style="text-align: center;">
    <h4>&nbsp;Portal Username&nbsp;</h4>
    </td>
    <td style="text-align: center;">
    <h4>&nbsp;Login IP&nbsp;</h4>
    </td>
    <td style="text-align: center;">
    <h4>&nbsp;Passphrase&nbsp;</h4>
    </td>
    <td style="text-align: center;">
    <h4>&nbsp;Server&nbsp;</h4>
    </td>
    <td style="text-align: center;">
    <h4>&nbsp;Time (UTC)&nbsp;</h4>
    </td>
    <td style="text-align: center;">
    <h4>&nbsp;Login Status&nbsp;</h4>
    </td>
    </tr> \n'''
            for i in a:
                if i.login_type == 'Attempt':
                    content = content + '''
    <tr >
    <td style="text-align: center;">&nbsp;<strong><a href="auth_log?dmr_id=''' + str(i.login_dmr_id) + '''">''' + str(i.login_dmr_id) + '''</a></strong>&nbsp;</td>
    <td style="text-align: center;">&nbsp;&nbsp;<a href="auth_log?portal_username=''' + i.portal_username + '''">''' + i.portal_username + '''</a>&nbsp;</td>
    <td style="text-align: center;">&nbsp;&nbsp;<strong><a href="auth_log?peer_ip=''' + str(i.peer_ip) + '''">''' + str(i.peer_ip) + '''</a></strong>&nbsp;</td>
    <td style="text-align: center;">&nbsp;''' + i.login_auth_method + '''&nbsp;</td>
    <td style="text-align: center;">&nbsp;<a href="auth_log?mmdvm_server=''' + str(i.server_name) + '''">''' + str(i.server_name) + '''</a>&nbsp;</td>
    <td style="text-align: center;">&nbsp;''' + str(i.login_time) + '''&nbsp;</td>
    <td style="text-align: center;">&nbsp;<span style="color: #000000; background-color: #ffff00;"><strong>''' + str(i.login_type) + '''</span></strong>&nbsp;</td> 
    </tr>
'''
                if i.login_type == 'Confirmed':
                    content = content + '''
    <tr >
    <td style="text-align: center;">&nbsp;<strong><a href="auth_log?dmr_id=''' + str(i.login_dmr_id) + '''">''' + str(i.login_dmr_id) + '''</a></strong>&nbsp;</td>
    <td style="text-align: center;">&nbsp;<a href=auth_log?portal_username=''' + i.portal_username + '''">''' + i.portal_username + '''</a>&nbsp;</td>
    <td style="text-align: center;">&nbsp;&nbsp;<strong><a href="auth_log?peer_ip=''' + str(i.peer_ip) + '''">''' + str(i.peer_ip) + '''</a></strong>&nbsp;</td>
    <td style="text-align: center;">&nbsp;''' + i.login_auth_method + '''&nbsp;</td>
    <td style="text-align: center;">&nbsp;<a href="auth_log?mmdvm_server=''' + str(i.server_name) + '''">''' + str(i.server_name) + '''</a>&nbsp;</td>
    <td style="text-align: center;">&nbsp;''' + str(i.login_time) + '''&nbsp;</td>
    <td style="text-align: center;">&nbsp;<span style="color: #000000; background-color: #00ff00;"><strong>''' + str(i.login_type) + '''</span></strong>&nbsp;</td> 
    </tr>
'''
                if i.login_type == 'Failed':
                    content = content + '''
    <tr >
    <td style="text-align: center;">&nbsp;<strong><a href="auth_log?dmr_id=''' + str(i.login_dmr_id) + '''">''' + str(i.login_dmr_id) + '''</a></strong>&nbsp;</td>
    <td style="text-align: center;">&nbsp;''' + i.portal_username + '''&nbsp;</a></td>
    <td style="text-align: center;">&nbsp;&nbsp;<strong><a href="auth_log?peer_ip=''' + str(i.peer_ip) + '''">''' + str(i.peer_ip) + '''</a></strong>&nbsp;</td>
    <td style="text-align: center;">&nbsp;''' + i.login_auth_method + '''&nbsp;</td>
    <td style="text-align: center;">&nbsp;<a href="auth_log?mmdvm_server=''' + str(i.server_name) + '''">''' + str(i.server_name) + '''</a>&nbsp;</td>
    <td style="text-align: center;">&nbsp;''' + str(i.login_time) + '''&nbsp;</td>
    <td style="text-align: center;"><span style="color: #000000; background-color: #FF2400;">&nbsp;<strong>''' + str(i.login_type) + '''</span></strong>&nbsp;</td> 
    </tr>
'''
            content = content + '</tbody></table>'
            
        elif request.args.get('mmdvm_server') and not request.args.get('flush_db_mmdvm'):
            a = AuthLog.query.filter_by(server_name=request.args.get('mmdvm_server')).order_by(AuthLog.login_time.desc()).all()
            content = '''
    <p>&nbsp;</p>
    <p style="text-align: center;"><strong><a href="auth_log?flush_db_mmdvm=true&mmdvm_server=''' + request.args.get('mmdvm_server') + '''"><button type="button" class="btn btn-danger">Flush authentication log for server: ''' + request.args.get('mmdvm_server') + '''</button></a></strong></p>
    <p style="text-align: center;"><strong>Log for MMDVM server: ''' + request.args.get('mmdvm_server') + '''</strong></p>

    <table style="margin-left: auto; margin-right: auto;" border="1">
    <tbody>
    <tr>
    <td>&nbsp;<span style="color: #000000; background-color: #ff2400;">&nbsp;<strong>Failed</strong></span>&nbsp;= Not authorized.&nbsp;</td>
    <td>&nbsp;<span style="color: #000000; background-color: #ffff00;"><strong>Attempt</strong></span>&nbsp;= Checking if authorized.&nbsp;</td>
    <td>&nbsp;<span style="color: #000000; background-color: #00ff00;"><strong>Confirmed</strong></span>&nbsp;= Authorized, connection comfirmed.&nbsp;</td>
    </tr>
    </tbody>
    </table>
    <p>&nbsp;</p>
    
    <table style="width: 1000px; margin-left: auto; margin-right: auto;" border="1">
    <tbody>
    <tr>
    <td style="text-align: center;">
    <h4>&nbsp;DMR ID&nbsp;</h4>
    </td>
    <td style="text-align: center;">
    <h4>&nbsp;Portal Username&nbsp;</h4>
    </td>
    <td style="text-align: center;">
    <h4>&nbsp;Login IP&nbsp;</h4>
    </td>
    <td style="text-align: center;">
    <h4>&nbsp;Passphrase&nbsp;</h4>
    </td>
    <td style="text-align: center;">
    <h4>&nbsp;Server&nbsp;</h4>
    </td>
    <td style="text-align: center;">
    <h4>&nbsp;Time (UTC)&nbsp;</h4>
    </td>
    <td style="text-align: center;">
    <h4>&nbsp;Login Status&nbsp;</h4>
    </td>
    </tr> \n'''
            for i in a:
                if i.login_type == 'Attempt':
                    content = content + '''
    <tr >
    <td style="text-align: center;">&nbsp;<strong><a href="auth_log?dmr_id=''' + str(i.login_dmr_id) + '''">''' + str(i.login_dmr_id) + '''</a></strong>&nbsp;</td>
    <td style="text-align: center;">&nbsp;&nbsp;<a href="auth_log?portal_username=''' + i.portal_username + '''">''' + i.portal_username + '''</a>&nbsp;</td>
    <td style="text-align: center;">&nbsp;&nbsp;<strong><a href="auth_log?peer_ip=''' + str(i.peer_ip) + '''">''' + str(i.peer_ip) + '''</a></strong>&nbsp;</td>
    <td style="text-align: center;">&nbsp;''' + i.login_auth_method + '''&nbsp;</td>
    <td style="text-align: center;">&nbsp;''' + i.server_name + '''&nbsp;</td>
    <td style="text-align: center;">&nbsp;''' + str(i.login_time) + '''&nbsp;</td>
    <td style="text-align: center;">&nbsp;<span style="color: #000000; background-color: #ffff00;"><strong>''' + str(i.login_type) + '''</span></strong>&nbsp;</td> 
    </tr>
'''
                if i.login_type == 'Confirmed':
                    content = content + '''
    <tr >
    <td style="text-align: center;">&nbsp;<strong><a href="auth_log?dmr_id=''' + str(i.login_dmr_id) + '''">''' + str(i.login_dmr_id) + '''</a></strong>&nbsp;</td>
    <td style="text-align: center;">&nbsp;<a href="auth_log?portal_username=''' + i.portal_username + '''">''' + i.portal_username + '''</a>&nbsp;</td>
    <td style="text-align: center;">&nbsp;&nbsp;<strong><a href="auth_log?peer_ip=''' + str(i.peer_ip) + '''">''' + str(i.peer_ip) + '''</a></strong>&nbsp;</td>
    <td style="text-align: center;">&nbsp;''' + i.login_auth_method + '''&nbsp;</td>
    <td style="text-align: center;">&nbsp;''' + i.server_name + '''&nbsp;</td>
    <td style="text-align: center;">&nbsp;''' + str(i.login_time) + '''&nbsp;</td>
    <td style="text-align: center;">&nbsp;<span style="color: #000000; background-color: #00ff00;"><strong>''' + str(i.login_type) + '''</span></strong>&nbsp;</td> 
    </tr>
'''
                if i.login_type == 'Failed':
                    content = content + '''
    <tr >
    <td style="text-align: center;">&nbsp;<strong><a href="auth_log?dmr_id=''' + str(i.login_dmr_id) + '''">''' + str(i.login_dmr_id) + '''</a></strong>&nbsp;</td>
    <td style="text-align: center;">&nbsp;''' + i.portal_username + '''&nbsp;</a></td>
    <td style="text-align: center;">&nbsp;&nbsp;<strong><a href="auth_log?peer_ip=''' + str(i.peer_ip) + '''">''' + str(i.peer_ip) + '''</a></strong>&nbsp;</td>
    <td style="text-align: center;">&nbsp;''' + i.login_auth_method + '''&nbsp;</td>
    <td style="text-align: center;">&nbsp;''' + i.server_name + '''&nbsp;</td>
    <td style="text-align: center;">&nbsp;''' + str(i.login_time) + '''&nbsp;</td>
    <td style="text-align: center;"><span style="color: #000000; background-color: #FF2400;">&nbsp;<strong>''' + str(i.login_type) + '''</span></strong>&nbsp;</td> 
    </tr>
'''
            content = content + '</tbody></table>'

        elif request.args.get('peer_ip') and not request.args.get('flush_db_ip'):
            a = AuthLog.query.filter_by(peer_ip=request.args.get('peer_ip')).order_by(AuthLog.login_time.desc()).all()
            content = '''
    <p>&nbsp;</p>
    <p style="text-align: center;"><strong><a href="auth_log?flush_db_ip=true&peer_ip=''' + request.args.get('peer_ip') + '''"><button type="button" class="btn btn-danger">Flush authentication log for IP: ''' + request.args.get('peer_ip') + '''</button></a></strong></p>
    <p style="text-align: center;"><strong>Log for IP address: ''' + request.args.get('peer_ip') + '''</strong></p>

    <table style="margin-left: auto; margin-right: auto;" border="1">
    <tbody>
    <tr>
    <td>&nbsp;<span style="color: #000000; background-color: #ff2400;">&nbsp;<strong>Failed</strong></span>&nbsp;= Not authorized.&nbsp;</td>
    <td>&nbsp;<span style="color: #000000; background-color: #ffff00;"><strong>Attempt</strong></span>&nbsp;= Checking if authorized.&nbsp;</td>
    <td>&nbsp;<span style="color: #000000; background-color: #00ff00;"><strong>Confirmed</strong></span>&nbsp;= Authorized, connection comfirmed.&nbsp;</td>
    </tr>
    </tbody>
    </table>
    <p>&nbsp;</p>
    
    <table style="width: 1000px; margin-left: auto; margin-right: auto;" border="1">
    <tbody>
    <tr>
    <td style="text-align: center;">
    <h4>&nbsp;DMR ID&nbsp;</h4>
    </td>
    <td style="text-align: center;">
    <h4>&nbsp;Portal Username&nbsp;</h4>
    </td>
    <td style="text-align: center;">
    <h4>&nbsp;Login IP&nbsp;</h4>
    </td>
    <td style="text-align: center;">
    <h4>&nbsp;Passphrase&nbsp;</h4>
    </td>
    <td style="text-align: center;">
    <h4>&nbsp;Server&nbsp;</h4>
    </td>
    <td style="text-align: center;">
    <h4>&nbsp;Time (UTC)&nbsp;</h4>
    </td>
    <td style="text-align: center;">
    <h4>&nbsp;Login Status&nbsp;</h4>
    </td>
    </tr> \n'''
            for i in a:
                if i.login_type == 'Attempt':
                    content = content + '''
    <tr >
    <td style="text-align: center;">&nbsp;<strong><a href="auth_log?dmr_id=''' + str(i.login_dmr_id) + '''">''' + str(i.login_dmr_id) + '''</a></strong>&nbsp;</td>
    <td style="text-align: center;">&nbsp;&nbsp;<a href="auth_log?portal_username=''' + i.portal_username + '''">''' + i.portal_username + '''</a>&nbsp;</td>
    <td style="text-align: center;">&nbsp;<strong>''' + i.peer_ip + '''</strong>&nbsp;</td>
    <td style="text-align: center;">&nbsp;''' + i.login_auth_method + '''&nbsp;</td>
    <td style="text-align: center;">&nbsp;<a href="auth_log?mmdvm_server=''' + str(i.server_name) + '''">''' + str(i.server_name) + '''</a>&nbsp;</td>
    <td style="text-align: center;">&nbsp;''' + str(i.login_time) + '''&nbsp;</td>
    <td style="text-align: center;">&nbsp;<span style="color: #000000; background-color: #ffff00;"><strong>''' + str(i.login_type) + '''</span></strong>&nbsp;</td> 
    </tr>
'''
                if i.login_type == 'Confirmed':
                    content = content + '''
    <tr >
    <td style="text-align: center;">&nbsp;<strong><a href="auth_log?dmr_id=''' + str(i.login_dmr_id) + '''">''' + str(i.login_dmr_id) + '''</a></strong>&nbsp;</td>
    <td style="text-align: center;">&nbsp;<a href="auth_log?portal_username=''' + i.portal_username + '''">''' + i.portal_username + '''</a>&nbsp;</td>
    <td style="text-align: center;">&nbsp;<strong>''' + i.peer_ip + '''</strong>&nbsp;</td>
    <td style="text-align: center;">&nbsp;''' + i.login_auth_method + '''&nbsp;</td>
    <td style="text-align: center;">&nbsp;<a href="auth_log?mmdvm_server=''' + str(i.server_name) + '''">''' + str(i.server_name) + '''</a>&nbsp;</td>
    <td style="text-align: center;">&nbsp;''' + str(i.login_time) + '''&nbsp;</td>
    <td style="text-align: center;">&nbsp;<span style="color: #000000; background-color: #00ff00;"><strong>''' + str(i.login_type) + '''</span></strong>&nbsp;</td> 
    </tr>
'''
                if i.login_type == 'Failed':
                    content = content + '''
    <tr >
    <td style="text-align: center;">&nbsp;<strong><a href="auth_log?dmr_id=''' + str(i.login_dmr_id) + '''">''' + str(i.login_dmr_id) + '''</a></strong>&nbsp;</td>
    <td style="text-align: center;">&nbsp;''' + i.portal_username + '''&nbsp;</a></td>
    <td style="text-align: center;">&nbsp;<strong>''' + i.peer_ip + '''</strong>&nbsp;</td>
    <td style="text-align: center;">&nbsp;''' + i.login_auth_method + '''&nbsp;</td>
    <td style="text-align: center;">&nbsp;<a href="auth_log?mmdvm_server=''' + str(i.server_name) + '''">''' + str(i.server_name) + '''</a>&nbsp;</td>
    <td style="text-align: center;">&nbsp;''' + str(i.login_time) + '''&nbsp;</td>
    <td style="text-align: center;"><span style="color: #000000; background-color: #FF2400;">&nbsp;<strong>''' + str(i.login_type) + '''</span></strong>&nbsp;</td> 
    </tr>
'''
            content = content + '</tbody></table>'
            
        else:
            #a = AuthLog.query.all()
##            a = AuthLog.query.order_by(AuthLog.login_time.desc()).limit(300).all()
            a = AuthLog.query.order_by(AuthLog.login_time.desc()).all()
            recent_list = []
##            r = AuthLog.query.order_by(AuthLog.login_dmr_id.desc()).all()
            content = '''
    <p>&nbsp;</p>
    <p style="text-align: center;"><strong><a href="auth_log?flush_db=true"><button type="button" class="btn btn-danger">Flush entire authentication log</button></a></strong></p>
    <p style="text-align: center;"><strong><a href="auth_log?portal_username=Not Registered"><button type="button" class="btn btn-primary">Un-registered authentication attempts</button></a></strong></p>
    <p style="text-align: center;"><strong>Authentication log by DMR ID</strong></p>

    <table style="margin-left: auto; margin-right: auto;" border="1">
    <tbody>
    <tr>
    <td>&nbsp;<span style="color: #000000; background-color: #ff2400;">&nbsp;<strong>Failed</strong></span>&nbsp;= Not authorized.&nbsp;</td>
    <td>&nbsp;<span style="color: #000000; background-color: #ffff00;"><strong>Attempt</strong></span>&nbsp;= Checking if authorized.&nbsp;</td>
    <td>&nbsp;<span style="color: #000000; background-color: #00ff00;"><strong>Confirmed</strong></span>&nbsp;= Authorized, connection comfirmed.&nbsp;</td>
    </tr>
    </tbody>
    </table>
    <p>&nbsp;</p>
    
    <table style="width: 1000px; margin-left: auto; margin-right: auto;" border="1">
    <tbody>
    <tr>
    <td style="text-align: center;">
    <h4>&nbsp;DMR ID&nbsp;</h4>
    </td>
    <td style="text-align: center;">
    <h4>&nbsp;Portal Username&nbsp;</h4>
    </td>
    <td style="text-align: center;">
    <h4>&nbsp;Login IP&nbsp;</h4>
    </td>
    <td style="text-align: center;">
    <h4>&nbsp;Passphrase&nbsp;</h4>
    </td>
    <td style="text-align: center;">
    <h4>&nbsp;Server&nbsp;</h4>
    </td>
    <td style="text-align: center;">
    <h4>&nbsp;Time (UTC)&nbsp;</h4>
    </td>
    <td style="text-align: center;">
    <h4>&nbsp;Last Login Status&nbsp;</h4>
    </td>
    </tr> \n'''
            for i in a:
                if i.login_dmr_id not in recent_list:
                    recent_list.append(i.login_dmr_id)
                    if i.login_type == 'Attempt':
                        content = content + '''
    <tr >
    <td style="text-align: center;">&nbsp;<strong><a href="auth_log?dmr_id=''' + str(i.login_dmr_id) + '''">''' + str(i.login_dmr_id) + '''</a></strong>&nbsp;</td>
    <td style="text-align: center;">&nbsp;<a href="auth_log?portal_username=''' + i.portal_username + '''">''' + i.portal_username + '''</a>&nbsp;</td>
    <td style="text-align: center;">&nbsp;&nbsp;<strong><a href="auth_log?peer_ip=''' + str(i.peer_ip) + '''">''' + str(i.peer_ip) + '''</a></strong>&nbsp;</td>
    <td style="text-align: center;">&nbsp;''' + i.login_auth_method + '''&nbsp;</td>
    <td style="text-align: center;">&nbsp;<a href="auth_log?mmdvm_server=''' + str(i.server_name) + '''">''' + str(i.server_name) + '''</a>&nbsp;</td>
    <td style="text-align: center;">&nbsp;''' + str(i.login_time) + '''&nbsp;</td>
    <td style="text-align: center;">&nbsp;<span style="color: #000000; background-color: #ffff00;"><strong>''' + str(i.login_type) + '''</span></strong>&nbsp;</td> 
    </tr>
'''
                    if i.login_type == 'Confirmed':
                        content = content + '''
    <tr >
       <td style="text-align: center;">&nbsp;<strong><a href="auth_log?dmr_id=''' + str(i.login_dmr_id) + '''">''' + str(i.login_dmr_id) + '''</a></strong>&nbsp;</td>
    <td style="text-align: center;">&nbsp;<a href="auth_log?portal_username=''' + i.portal_username + '''">''' + i.portal_username + '''</a>&nbsp;</td>
    <td style="text-align: center;">&nbsp;&nbsp;<strong><a href="auth_log?peer_ip=''' + str(i.peer_ip) + '''">''' + str(i.peer_ip) + '''</a></strong>&nbsp;</td>
    <td style="text-align: center;">&nbsp;''' + i.login_auth_method + '''&nbsp;</td>
    <td style="text-align: center;">&nbsp;<a href="auth_log?mmdvm_server=''' + str(i.server_name) + '''">''' + str(i.server_name) + '''</a>&nbsp;</td>
    <td style="text-align: center;">&nbsp;''' + str(i.login_time) + '''&nbsp;</td>
    <td style="text-align: center;">&nbsp;<span style="color: #000000; background-color: #00ff00;"><strong>''' + str(i.login_type) + '''</span></strong>&nbsp;</td> 
    </tr>
'''
                    if i.login_type == 'Failed':
                        content = content + '''
    <tr >
        <td style="text-align: center;">&nbsp;<strong><a href="auth_log?dmr_id=''' + str(i.login_dmr_id) + '''">''' + str(i.login_dmr_id) + '''</a></strong>&nbsp;</td>
    <td style="text-align: center;">&nbsp;<a href="auth_log?portal_username=''' + i.portal_username + '''">''' + i.portal_username + '''</a>&nbsp;</a></td>
    <td style="text-align: center;">&nbsp;&nbsp;<strong><a href="auth_log?peer_ip=''' + str(i.peer_ip) + '''">''' + str(i.peer_ip) + '''</a></strong>&nbsp;</td>
    <td style="text-align: center;">&nbsp;''' + i.login_auth_method + '''&nbsp;</td>
    <td style="text-align: center;">&nbsp;<a href="auth_log?mmdvm_server=''' + str(i.server_name) + '''">''' + str(i.server_name) + '''</a>&nbsp;</td>
    <td style="text-align: center;">&nbsp;''' + str(i.login_time) + '''&nbsp;</td>
    <td style="text-align: center;"><span style="color: #000000; background-color: #FF2400;">&nbsp;<strong>''' + str(i.login_type) + '''</span></strong>&nbsp;</td> 
    </tr>
'''
               
            content = content + '</tbody></table>'
        return render_template('flask_user_layout.html', markup_content = Markup(content))

    
    @app.route('/news') #, methods=['POST', 'GET'])
##    @login_required
    def view_news():
        
        view_news =  News.query.order_by(News.time.desc()).all()
##        page = request.args.get('page', 1, type=int)
##        view_news =  News.query.order_by(News.time.desc()).paginate(page=page, per_page=1)

        #content = '''<table style="width: 600px; margin-left: auto; margin-right: auto;" border="1"><tbody>'''
        news_content = ''
        art_count = 0
        for article in view_news:
            if request.args.get('all_news'):
                art_count = 1
            if art_count < 16:
                news_content = news_content + '''
<div class="well well-sm" s style="text-align: center;"><h3>''' + article.subject + '''</h3>
<hr />
<p style="text-align: center;">&nbsp;</p>
<strong>''' + article.date + '''</strong> - <a href="news/''' + str(article.id) + '''"><button type="button" class="btn btn-primary">Link</button></a>
<p style="text-align: center;">&nbsp;</p>
<hr />
<div class="well well-sm" style="max-width:900px; word-wrap:break-word;">
''' + article.text + '''
</div>
</div>
  

'''
                art_count = art_count + 1
        #content = content + '''</tbody></table><p>&nbsp;</p>'''
        return render_template('news.html', markup_content = Markup(news_content))

    @app.route('/news/<article>') #, methods=['POST', 'GET'])
    def view_arts(article):
        
        view_arti =  News.query.filter_by(id=article).first()

        content = '''
<div class="well well-sm" style="text-align: center;"><h3>''' + view_arti.subject + '''</h3>
<hr />
<p>&nbsp;</p>
<strong>''' + view_arti.date + '''</strong>
<p>&nbsp;</p>
<hr />
<div class="well well-sm" style="max-width:900px; word-wrap:break-word;">
''' + view_arti.text + '''
</div>
</div>
  

'''
        return render_template('news.html', markup_content = Markup(content))

    

    @app.route('/add_news', methods=['POST', 'GET'])
    @login_required
    @roles_required('Admin')
    def edit_news():
        if request.args.get('add') == 'new':
            content = '''<h3 style="text-align: center;">Added news article.</h3>
    <p style="text-align: center;">Redirecting in 3 seconds.</p>
    <meta http-equiv="refresh" content="3; URL=manage_news" />'''
            news_add(request.form.get('subject'), request.form.get('time'), request.form.get('news'))
        else:
            content = '''
<p>&nbsp;</p>
<h2 style="text-align: center;"><strong>Post News Article<br /></strong></h2>
<p>&nbsp;</p>
<form action="add_news?add=new" method="POST">
<table style="width: 200px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr style="height: 51.1667px;">
<td style="height: 51.1667px; text-align: center;"><label for="bridge_name">Subject:</label><br /> <input id="subject" name="subject" type="text"  />
<p>&nbsp;</p>
</td>
</tr>
<tr style="height: 51.1667px;">
<td style="height: 51.1667px; text-align: center;"><label for="tg">Date:</label><br /> <input id="time" name="time" type="text"  />
<p>&nbsp;</p>
</td>
</tr>
<tr style="height: 51.1667px;">
<td style="height: 51.1667px; text-align: center;"><label for="description">News (HTML OK):</label><br /> <textarea id="news" cols="80" name="news" rows="10"></textarea></td>
</tr>

<tr style="height: 27px;">
<td style="text-align: center; height: 27px;">
<p>&nbsp;</p>
<p><input type="submit" value="Submit" /></p>
</td>
</tr>
</tbody>
</table>
</form>
'''
        return render_template('flask_user_layout.html', markup_content = Markup(content))

    @app.route('/manage_news', methods=['POST', 'GET'])
    @login_required
    @roles_required('Admin')
    def manage_news():
        view_news =  News.query.order_by(News.time.desc()).all()
        if request.args.get('delete'):
            content = '''<h3 style="text-align: center;">Deleted news article.</h3>
    <p style="text-align: center;">Redirecting in 3 seconds.</p>
    <meta http-equiv="refresh" content="3; URL=manage_news" />'''
            news_delete(request.args.get('delete'))
            
        else:
            content = '''
<p>&nbsp;</p>
<p style="text-align: center;"><a href="add_news"><strong><button type="button" class="btn btn-success">Add News Article</button></strong></a></p>
<p>&nbsp;</p>

<table style="width: 500px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td style="text-align: center;"><strong>Subject</strong></td>
<td style="text-align: center;"><strong>Date</strong></td>
<td style="text-align: center;"><strong>ID</strong></td>

</tr>'''
            for a in view_news:
                content = content + '''
            
<tr>
<td><a href="news/''' + str(a.id) + '''">''' + a.subject + '''</a>    |    <a href="manage_news?delete=''' + str(a.id )+ '''"><button type="button" class="btn btn-danger">Delete</button></a></td>
<td>''' + a.date + '''</td>
<td>''' + str(a.id) + '''</td>

</tr>'''
            content = content + '''
</tbody>
</table>
<p>&nbsp;</p>
'''
        return render_template('flask_user_layout.html', markup_content = Markup(content))

    @app.route('/misc_settings', methods=['POST', 'GET'])
    @login_required
    @roles_required('Admin')
    def misc_sett():
        if request.args.get('approve_email') == 'save':
            misc_edit_field_1('approval_email', request.form.get('email_text'), None, None, None, None, None, None, None, None)
            content = '''<h3 style="text-align: center;">Saved email text.</h3>
            <p style="text-align: center;">Redirecting in 3 seconds.</p>
            <meta http-equiv="refresh" content="3; URL=misc_settings" /> '''
        elif request.args.get('approve_flash') == 'save':
            misc_edit_field_1('approval_flash', request.form.get('flash_text'), None, None, None, None, None, None, None, None)
            content = '''<h3 style="text-align: center;">Saved flash text.</h3>
            <p style="text-align: center;">Redirecting in 3 seconds.</p>
            <meta http-equiv="refresh" content="3; URL=misc_settings" /> '''
        elif request.args.get('home') == 'save':
            misc_edit_field_1('home_page', request.form.get('home_text'), None, None, None, None, None, None, None, None)
            content = '''<h3 style="text-align: center;">Saved home page.</h3>
            <p style="text-align: center;">Redirecting in 3 seconds.</p>
            <meta http-equiv="refresh" content="3; URL=misc_settings" /> '''
        elif request.args.get('tos') == 'save':
            misc_edit_field_1('terms_of_service', request.form.get('tos_text'), None, None, None, None, None, None, None, None)
            content = '''<h3 style="text-align: center;">Saved terms of service.</h3>
            <p style="text-align: center;">Redirecting in 3 seconds.</p>
            <meta http-equiv="refresh" content="3; URL=misc_settings" /> '''
        else:
                
            email_text = Misc.query.filter_by(field_1='approval_email').first()
            flash_text = Misc.query.filter_by(field_1='approval_flash').first()
            home_text = Misc.query.filter_by(field_1='home_page').first()
            tos_text = Misc.query.filter_by(field_1='terms_of_service').first()
            content = '''
    <p>&nbsp;</p>
    <form action="misc_settings?approve_email=save" method="POST">
    <table style="width: 500px; margin-left: auto; margin-right: auto;" border="1">
    <tbody>
    <tr style="height: 51.1667px;">
    <td style="height: 51.1667px; text-align: center;"><label for="email_text">Account Approval email text (HTML OK):</label><br /> <textarea id="email_text" cols="65" name="email_text" rows="4">''' + email_text.field_2 + '''</textarea></td>
    </tr>
    <tr style="height: 27px;">
    <td style="text-align: center; height: 27px;">
    <p>&nbsp;</p>
    <p><input type="submit" value="Submit" /></p>
    </td>
    </tr>
    </tbody>
    </table>
    </form>
    <p>&nbsp;</p>

    <form action="misc_settings?approve_flash=save" method="POST">
    <table style="width: 500px; margin-left: auto; margin-right: auto;" border="1">
    <tbody>
    <tr style="height: 51.1667px;">
    <td style="height: 51.1667px; text-align: center;"><label for="flash_text">Account Approval flash text (HTML OK):</label><br /> <textarea id="flash_text" cols="65" name="flash_text" rows="4">''' + flash_text.field_2 + '''</textarea></td>
    </tr>
    <tr style="height: 27px;">
    <td style="text-align: center; height: 27px;">
    <p>&nbsp;</p>
    <p><input type="submit" value="Submit" /></p>
    </td>
    </tr>
    </tbody>
    </table>
    </form>
    
    <p>&nbsp;</p>

    <form action="misc_settings?home=save" method="POST">
    <table style="width: 500px; margin-left: auto; margin-right: auto;" border="1">
    <tbody>
    <tr style="height: 51.1667px;">
    <td style="height: 51.1667px; text-align: center;"><label for="home_text">Homepage (HTML OK, 5000 characters max):</label><br /> <textarea id="home_text" cols="65" name="home_text" rows="4">''' + home_text.field_2 + '''</textarea></td>
    </tr>
    <tr style="height: 27px;">
    <td style="text-align: center; height: 27px;">
    <p>&nbsp;</p>
    <p><input type="submit" value="Submit" /></p>
    </td>
    </tr>
    </tbody>
    </table>
    </form>
    <p>&nbsp;</p>

        <p>&nbsp;</p>

    <form action="misc_settings?tos=save" method="POST">
    <table style="width: 500px; margin-left: auto; margin-right: auto;" border="1">
    <tbody>
    <tr style="height: 51.1667px;">
    <td style="height: 51.1667px; text-align: center;"><label for="tos_text">Terms of Service (HTML OK, 5000 characters max):</label><br /> <textarea id="tos_text" cols="65" name="tos_text" rows="4">''' + tos_text.field_2 + '''</textarea></td>
    </tr>
    <tr style="height: 27px;">
    <td style="text-align: center; height: 27px;">
    <p>&nbsp;</p>
    <p><input type="submit" value="Submit" /></p>
    </td>
    </tr>
    </tbody>
    </table>
    </form>
    <p>&nbsp;</p>
    '''
        return render_template('flask_user_layout.html', markup_content = Markup(content))

    @app.route('/import_rules/<server>', methods=['POST', 'GET'])
    @login_required
    @roles_required('Admin')
    def import_rules(server):
        if request.args.get('import') == 'true':
            try:
                imp_dict = ast.literal_eval(request.form.get('rules'))
                for e in imp_dict.items():
                    b_db = BridgeList.query.filter_by(bridge_name=e[0]).first()
                    if b_db == None:
                        bridge_add(e[0], 'Add a description', True, 0)
                    for i in e[1]: #.items():
                        add_system_rule(e[0], i['SYSTEM'], i['TS'], i['TGID'], i['ACTIVE'], i['TIMEOUT'], i['TO_TYPE'], re.sub('\[|\]', '', str(i['ON'])), re.sub('\[|\]', '', str(i['OFF'])), re.sub('\[|\]', '', str(i['RESET'])), server)
                content = '''<h3 style="text-align: center;">Sucessfully imported rules (or something else).</h3>
                <p style="text-align: center;">Redirecting in 3 seconds.</p>
                <meta http-equiv="refresh" content="3; URL=manage_servers" /> '''
            except:
                content = '''<h3 style="text-align: center;">Rules import failed.</h3>
                <p style="text-align: center;">Redirecting in 3 seconds.</p>
                <meta http-equiv="refresh" content="3; URL=manage_servers" /> '''
        else:
            content = '''
<h3 style="text-align: center;">Before importing:</h3>
<p style="text-align: center;">1. You must have master, proxy, and peer connections set up prior to importing rules. The names of each master, proxy, or peer must match <strong>'SYSTEM'</strong> in your rules.py.</p>
<p style="text-align: center;">2. In rules.py, locate <strong>BRIDGES = {...................}</strong>. Copy and paste the brackets, { and }, and everything in between into the box below.</p>

    <form action="''' + server + '''?import=true" method="POST">
    <table style="width: 800px; margin-left: auto; margin-right: auto;" border="1">
    <tbody>
    <tr style="height: 51.1667px;">
    <td style="height: 51.1667px; text-align: center;"><label for="rules">Paste from rules.py:</label><br /> <textarea id="rules" cols="200" name="rules" rows="20"></textarea></td>
    </tr>
    <tr style="height: 27px;">
    <td style="text-align: center; height: 27px;">
    <p>&nbsp;</p>
    <p><input type="submit" value="Submit" /></p>
    </td>
    </tr>
    </tbody>
    </table>
    </form>
'''
        return render_template('flask_user_layout.html', markup_content = Markup(content))

    @app.route('/user_tg')
    def tg_status():
        cu = current_user
        u = User.query.filter_by(username=cu.username).first()
        sl = ServerList.query.all()
        user_ids = ast.literal_eval(u.dmr_ids)
        content = '<p style="text-align: center;">Currently active talkgroups. Updated every 2 minutes.</p>'
##        print(active_tgs)
        for s in sl:
            for i in user_ids.items():
                for ts in active_tgs[s.name].items():
##                    print(ts)
##                    print(ts[1][3]['peer_id'])
                    if i[0] == ts[1][3]['peer_id']:
##                        print(i[0])
                        print(ts)
##                    if i[0] in active_tgs[s.name]:
##                        for x in ts[1]:
##                            print(x)
##    ##                            if i[0] != ts[1][x][3]['peer_id']:
##    ##                                print('nope')
##    ##                                pass
##    ##                            elif i[0] == ts[1][x][3]['peer_id']:
##    ##                            print(x)
##    ##                            print(s.name)
##    ##                            print('-----ts-----')
##    ##                            print(ts[1][x][3]['peer_id']) #[s.name][3]['peer_id'])
##    ##                            print(active_tgs)
##                            
##        ##                    print(active_tgs[s.name])
##        ##                        print(str(active_tgs[ts[1]]))
##                        # Remove 0 from TG list
                        try:
                            active_tgs[s.name][ts[0]][0]['1'].remove(0)
                            active_tgs[s.name][ts[0]][1]['2'].remove(0)
                        except:
                            pass
####                try:
                        content = content + ''' <table style="width: 500px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td style="text-align: center;">
<h3><strong>Server:</strong> ''' + str(s.name) + '''</h3>
<p><strong>DMR ID:</strong> ''' + str(i[0]) + '''</p>
</td>
</tr>
<tr>
<td>&nbsp;
<table style="width: 499px; float: left;" border="1">
<tbody>
<tr>
<td style="width: 85.7px;"><strong>Timeslot 1</strong></td>
<td style="width: 377.3px;">&nbsp;''' + str(active_tgs[s.name][ts[0]][0]['1'])[1:-1] + '''</td>
</tr>
<tr>
<td style="width: 85.7px;"><strong>Timeslot 2</strong></td>
<td style="width: 377.3px;">&nbsp;''' + str(active_tgs[s.name][ts[0]][1]['2'])[1:-1] + '''</td>
</tr>
</tbody>
</table>
</td>
</tr>
</tbody>
</table>'''
##                except:
##                    pass
           
       
##                #TS1
##                for tg in active_tgs[s.name][i[0]][1]['2']:
##                    content = content + '''<td style="width: 377.3px;">&nbsp;''' + str(tg) + '''</td>
##'''
##                print(active_tgs[s.name][i[0]])
##                content = active_tgs[s.name][i[0]][1]['2']
##        content = 'hji'
        
        return render_template('flask_user_layout.html', markup_content = Markup(content))
    
    @app.route('/tg/<name>') #, methods=['POST', 'GET'])
##    @login_required
    def tg_details(name):
        tg_d = BridgeList.query.filter_by(bridge_name=name).first()
        content = ''' 

<div class="row">
    <div class="well well-sm" style="text-align: center;"><h2>''' + tg_d.bridge_name + '''</h2>
<hr />
TG #: <strong> ''' + str(tg_d.tg) + '''</strong>
<hr />
<div class="well well-sm" style="max-width:900px; word-wrap:break-word;">
''' + tg_d.description + '''
</div>
</div>
  
  </div>
'''
        return render_template('tg.html', markup_content = Markup(content))

    @app.route('/hbnet_tg.csv')
##    @login_required
    def tg_csv():
        cbl = BridgeList.query.filter_by(public_list=True).all()
        gen_csv = 'TG, Name\n'
        for t in cbl:
            gen_csv = gen_csv + str(t.tg) + ', ' + t.bridge_name + '\n'
        response = Response(gen_csv, mimetype="text/csv")
        return response

    @app.route('/hbnet_tg_anytone.csv')
##    @login_required
    def anytone_tg_csv():
        cbl = BridgeList.query.filter_by(public_list=True).all()
        gen_csv = 'No., Radio ID, Name, Call Type, Call Alert\n'
        num = 1
        for t in cbl:
            gen_csv = gen_csv + str(num) + ', ' + str(t.tg) + ', ' + t.bridge_name + ', Group Call, None' + '\n'
            num = num + 1
        response = Response(gen_csv, mimetype="text/csv")
        return response

    @app.route('/talkgroups')
##    @login_required
    def tg_list():
        cbl = BridgeList.query.filter_by(public_list=True).all()
        content = ''
        for i in cbl:
            print(str(re.sub('<[^>]*>', '', i.description))[:50])
            content = content + '''
<tr>
      <td>&nbsp;<a href="/tg/''' + i.bridge_name + '''"><button type="button" class="btn btn-primary">''' + i.bridge_name + '''</button></a></td>
      <td style="width: 89.9px;">&nbsp;''' + str(i.tg) + '''</td>
      <td style="width: 339px;">&nbsp;''' + str(re.sub('<[^>]*>|\s\s+', ' ', i.description))[:50] + '''...</td>
      </tr>'''
        
        return render_template('tg_all.html', markup_content = Markup(content))

    @app.route('/talkgroups/<server>') #, methods=['POST', 'GET'])
    @login_required
    def tg_list_server(server):
        svr = ServerList.query.filter_by(name=server).first()
        content = '''
<p>&nbsp;</p>
<table style="width: 700px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr style="height: 18px;">
<td style="text-align: center; height: 18px;">&nbsp;<h4>Server: <strong>''' + svr.name + '''</strong>&nbsp; -&nbsp; IP/Host: <strong>''' + str(svr.ip) + '''</strong></h4></td>
</tr> '''
        m_list = MasterList.query.filter_by(server=server).filter_by(active=True).filter_by(public_list=True).all()
        p_list = ProxyList.query.filter_by(server=server).filter_by(active=True).filter_by(public_list=True).all()
        tg_list = ''
        for m in m_list:
            br = BridgeRules.query.filter_by(server=server).filter_by(system_name=m.name).all()
            print(br)
##            for t in br:
##                print(t.tg)
            for b in br:
                print(b.bridge_name)
                bl = BridgeList.query.filter_by(bridge_name=b.bridge_name).first()
##                print(bl)
                if m.name == b.system_name and m.server == b.server and bl.public_list == True:
##                    print(b.bridge_name)
                    tg_list = tg_list + '''<tr>
<td>&nbsp;<a href="/tg/''' + b.bridge_name + '''">''' + b.bridge_name + '''</a></td>
<td>&nbsp;''' + str(b.tg) + '''</td>
<td>&nbsp;''' + str(b.ts) + '''</td>
<td>&nbsp;''' + b.to_type + '''</td>
<td>&nbsp;''' + str(b.timeout) + '''</td>

</tr> '''
            content = content + '''<tr style="height: 48.2px;">
<td style="height: 48.2px;">''' + ''' <table style="width: 690px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td style="text-align: center;">Name: <strong>''' + m.name + '''</strong>&nbsp; -&nbsp; Port: <strong>''' + str(m.port) + '''</strong></td>
</tr>
<table style="width: 680px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td style="text-align: center; width: 267.767px;">&nbsp;<strong>Name</strong></td>
<td style="text-align: center; width: 74.2333px;">&nbsp;<strong>TG</strong></td>
<td style="text-align: center; width: 87px;"><strong><strong>&nbsp;TS</strong></td>
<td style="text-align: center; width: 128px;"><strong>Timer Type</strong></td>
<td style="text-align: center; width: 77px;"><strong>Time (Min)</strong></td>
</tr>
''' + tg_list + '''
</tbody>
</table> ''' + '''</td>'''
            tg_list = ''
            
        for p in p_list:
            br = BridgeRules.query.filter_by(server=server).filter_by(system_name=p.name).all()
            for b in br:
                bl = BridgeList.query.filter_by(bridge_name=b.bridge_name).first()
##                print(bl.bridge_name)
                if p.name == b.system_name and p.server == b.server and bl.public_list == True:
##                    print(b.bridge_name)
                    tg_list = tg_list + '''<tr>
<td>&nbsp;<a href="/tg/''' + b.bridge_name + '''">''' + b.bridge_name + '''</a></td>
<td>&nbsp;''' + str(b.tg) + '''</td>
<td>&nbsp;''' + str(b.ts) + '''</td>
<td>&nbsp;''' + b.to_type + '''</td>
<td>&nbsp;''' + str(b.timeout) + '''</td>
</tr> '''
            content = content + '''<tr style="height: 48.2px;">
<td style="height: 48.2px;">''' + ''' <table style="width: 690px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td style="text-align: center;">Name: <strong>''' + p.name + '''</strong>&nbsp; -&nbsp; Port: <strong>''' + str(p.external_port) + '''</strong></td>
</tr>
<table style="width: 680px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td style="text-align: center; width: 267.767px;">&nbsp;<strong>Name</strong></td>
<td style="text-align: center; width: 74.2333px;">&nbsp;<strong>TG</strong></td>
<td style="text-align: center; width: 87px;"><strong><strong>&nbsp;TS</strong></td>
<td style="text-align: center; width: 128px;"><strong>Timer Type</strong></td>
<td style="text-align: center; width: 77px;"><strong>Time (Min)</strong></td>
</tr>
''' + tg_list + '''
<td>&nbsp;Disconnect from all activated TGs.</td>
<td>&nbsp;4000</td>
<td>&nbsp;</td>
</tbody>
</table> ''' + '''</td>'''
            tg_list = ''
        content = content + ''' </tr>
</tbody>
</table>
<p>&nbsp;</p> '''

        return render_template('flask_user_layout.html', markup_content = Markup(content))

###### DB functions #############################
    
    def get_peer_configs(_server_name):
        mmdvm_pl = mmdvmPeer.query.filter_by(server=_server_name).filter_by(enabled=True).all()
        xlx_pl = xlxPeer.query.filter_by(server=_server_name).filter_by(enabled=True).all()
##        print(mmdvm_pl)
        peer_config_list = {}
        for i in mmdvm_pl:
##            print(i.master_ip)
            peer_config_list.update({i.name: {
                        'MODE': 'PEER',
                        'ENABLED': i.enabled,
                        'LOOSE': i.loose,
                        'SOCK_ADDR': (gethostbyname(i.ip), i.port),
                        'IP': i.ip,
                        'PORT': i.port,
                        'MASTER_SOCKADDR': (gethostbyname(i.master_ip), i.master_port),
                        'MASTER_IP': i.master_ip,
                        'MASTER_PORT': i.master_port,

                        'PASSPHRASE': i.passphrase,
                        'CALLSIGN': i.callsign,
                        'RADIO_ID': int(i.radio_id), #int(i.radio_id).to_bytes(4, 'big'),
                        'RX_FREQ': i.rx_freq,
                        'TX_FREQ': i.tx_freq,
                        'TX_POWER': i.tx_power,
                        'COLORCODE': i.color_code,
                        'LATITUDE': i.latitude,
                        'LONGITUDE': i.longitude,
                        'HEIGHT': i.height,
                        'LOCATION': i.location,
                        'DESCRIPTION': i.description,
                        'SLOTS': i.slots,
                        'URL': i.url,
                        'GROUP_HANGTIME': i.group_hangtime,
                        'OPTIONS':  i.options,
                        'USE_ACL': i.use_acl,
                        'SUB_ACL': i.sub_acl,
                        'TG1_ACL': i.tg1_acl,
                        'TG2_ACL': i.tg2_acl,
                        'OTHER_OPTIONS': i.other_options
                    }})
        for i in xlx_pl:
            peer_config_list.update({i.name: {
                        'MODE': 'XLXPEER',
                        'ENABLED': i.enabled,
                        'LOOSE': i.loose,
                        'SOCK_ADDR': (gethostbyname(i.ip), i.port),
                        'IP': i.ip,
                        'PORT': i.port,
                        'MASTER_SOCKADDR': (gethostbyname(i.master_ip), i.master_port),
                        'MASTER_IP': i.master_ip,
                        'MASTER_PORT': i.master_port,

                        'PASSPHRASE': i.passphrase,
                        'CALLSIGN': i.callsign,
                        'RADIO_ID': int(i.radio_id), #int(i.radio_id).to_bytes(4, 'big'),
                        'RX_FREQ': i.rx_freq,
                        'TX_FREQ': i.tx_freq,
                        'TX_POWER': i.tx_power,
                        'COLORCODE': i.color_code,
                        'LATITUDE': i.latitude,
                        'LONGITUDE': i.longitude,
                        'HEIGHT': i.height,
                        'LOCATION': i.location,
                        'DESCRIPTION': i.description,
                        'SLOTS': i.slots,
                        'URL': i.url,
                        'OPTIONS':  i.options,
                        'GROUP_HANGTIME': i.group_hangtime,
                        'XLXMODULE': i.xlxmodule,
                        'USE_ACL': i.use_acl,
                        'SUB_ACL': i.sub_acl,
                        'TG1_ACL': i.tg1_acl,
                        'TG2_ACL': i.tg2_acl,
                        'OTHER_OPTIONS': i.other_options
                    }})
####                            print('peers')
##                print('----------------')
        return peer_config_list

    def get_burnlist():
        b = BurnList.query.all()
        #print(b)
        burn_dict = {}
        for i in b:
            #print(i.dmr_id)
            burn_dict[i.dmr_id] = i.version
        return burn_dict
        
    def add_burnlist(_dmr_id, _version):
        burn_list = BurnList(
            dmr_id=_dmr_id,
            version=_version,
            )
        db.session.add(burn_list)
        db.session.commit()

    def dash_loc_add(_call, _lat, _lon, _comment, _dmr_id, _server):
        add_loc = GPS_LocLog(
            callsign = _call,
            lat = _lat,
            lon = _lon,
            time = datetime.datetime.utcnow(),
            comment = _comment,
            dmr_id = _dmr_id,
            server = _server,
            system_name = ''
            )
        db.session.add(add_loc)
        db.session.commit()
        
    def trim_dash_loc():
        trim_dash = GPS_LocLog.query.all()
##        db.session.delete(delete_b)
##        db.session.commit()
        for i in trim_dash:
            elap_time = int(datetime.datetime.utcnow().strftime('%s')) - int(i.time.strftime('%s'))
            # Remove entries more than 2 weeks old
            if elap_time > 1209600:
                db.session.delete(i)
        db.session.commit()
        
    def update_burnlist(_dmr_id, _version):
        update_b = BurnList.query.filter_by(dmr_id=_dmr_id).first()
        update_b.version=_version
        db.session.commit()
        
    def delete_burnlist(_dmr_id):
        delete_b = BurnList.query.filter_by(dmr_id=_dmr_id).first()
        db.session.delete(delete_b)
        db.session.commit()

    def authlog_add(_dmr_id, _peer_ip, _server_name, _portal_username, _auth_method, _login_type):
        auth_log_add = AuthLog(
            login_dmr_id=_dmr_id,
            login_time=datetime.datetime.utcnow(),
            portal_username = _portal_username,
            peer_ip = _peer_ip,
            server_name = _server_name,
            login_auth_method=_auth_method,
            login_type=_login_type
            )
        db.session.add(auth_log_add)
        db.session.commit()

    def misc_add(_field_1, _field_2, _field_3, _field_4, int_1, _int_2, _int_3, _int_4, _boo_1, _boo_2):
        misc_entry_add = Misc(
            field_1 = _field_1,
            field_2 = _field_2,
            field_3 = _field_3,
            field_4 = _field_4,
            int_1 = _int_1,
            int_2 = _int_2,
            int_3 = _int_3,
            int_4 = _int_4,
            boo_1 = _boo_1,
            boo_2 = _boo_2,
            time = datetime.datetime.utcnow()
            )
        db.session.add(misc_entry_add)
        db.session.commit()

    def misc_edit_field_1(_field_1, _field_2, _field_3, _field_4, _int_1, _int_2, _int_3, _int_4, _boo_1, _boo_2):
        m = Misc.query.filter_by(field_1=_field_1).first()
        m.field_1 = _field_1
        m.field_2 = _field_2
        m.field_3 = _field_3
        m.field_4 = _field_4
        m.int_1 = _int_1
        m.int_2 = _int_2
        m.int_3 = _int_3
        m.int_4 = _int_4
        m.boo_1 = _boo_1
        m.boo_2 = _boo_2
        db.session.commit()
        
    def delete_misc_field_1(_field_1):
        delete_f1 = Misc.query.filter_by(field_1=_field_1).first()
        db.session.delete(delete_f1)
        db.session.commit()
        
    def authlog_flush():
        AuthLog.query.delete()
        db.session.commit()
        
    def authlog_flush_user(_user):
        flush_e = AuthLog.query.filter_by(portal_username=_user).all()
        for i in flush_e:
            db.session.delete(i)
        db.session.commit()

    def authlog_flush_dmr_id(_dmr_id):
        flush_e = AuthLog.query.filter_by(login_dmr_id=_dmr_id).all()
        for i in flush_e:
            db.session.delete(i)
        db.session.commit()
    def authlog_flush_mmdvm_server(_mmdvm_serv):
        flush_e = AuthLog.query.filter_by(server_name=_mmdvm_serv).all()
        for i in flush_e:
            db.session.delete(i)
        db.session.commit()
    def authlog_flush_ip(_ip):
        flush_e = AuthLog.query.filter_by(peer_ip=_ip).all()
        for i in flush_e:
            db.session.delete(i)
        db.session.commit()
##    def peer_delete(_mode, _id):
##        if _mode == 'xlx':
##           p = xlxPeer.query.filter_by(id=_id).first()
##        if _mode == 'mmdvm':
##           p = mmdvmPeer.query.filter_by(id=_id).first()
##        db.session.delete(p)
##        db.session.commit()

    def news_delete(_id):
        del_n = News.query.filter_by(id=_id).all()
        for i in del_n:
            db.session.delete(i)
        db.session.commit()

    def news_add(_subject, _time, _news):
        add_news = News(
            subject = _subject,
            date = _time,
            text = _news,
            time = datetime.datetime.utcnow()
            )
        db.session.add(add_news)
        db.session.commit()

    def server_delete(_name):
        s = ServerList.query.filter_by(name=_name).first()
        m = MasterList.query.filter_by(server=_name).all()
        p = ProxyList.query.filter_by(server=_name).all()
        o = OBP.query.filter_by(server=_name).all()
        dr = BridgeRules.query.filter_by(server=_name).all()
        mp = mmdvmPeer.query.filter_by(server=_name).all()
        xp = xlxPeer.query.filter_by(server=_name).all()
        for d in m:
            db.session.delete(d)
        for d in p:
            db.session.delete(d)
        for d in o:
            db.session.delete(d)
        for d in dr:
            db.session.delete(d)
        for d in mp:
            db.session.delete(d)
        for d in xp:
            db.session.delete(d)
        db.session.delete(s)
        
        db.session.commit()
    def peer_delete(_mode, _server, _name):
        if _mode == 'mmdvm':
            p = mmdvmPeer.query.filter_by(server=_server).filter_by(name=_name).first()
        if _mode == 'xlx':
            p = xlxPeer.query.filter_by(server=_server).filter_by(name=_name).first()
        dr = BridgeRules.query.filter_by(server=_server).filter_by(system_name=_name).all()
        for d in dr:
            db.session.delete(d)
        db.session.delete(p)
        db.session.commit()

    def shared_secrets():
        s = ServerList.query.all() #filter_by(name=_name).first()
        r_list = []
        for i in s:
            r_list.append(str(i.secret))
        return r_list

    def bridge_add(_name, _desc, _public, _tg):
        add_bridge = BridgeList(
            bridge_name = _name,
            description = _desc,
            public_list = _public,
            tg = _tg
            )
        db.session.add(add_bridge)
        db.session.commit()
    def update_bridge_list(_name, _desc, _public, _new_name, _tg):
        bl = BridgeList.query.filter_by(bridge_name=_name).first()
        bl.bridge_name = _new_name
        bl.description = _desc
        bl.public_list = _public
        bl.tg = _tg
        br = BridgeRules.query.filter_by(bridge_name=_name).all()
        for b in br:
            b.bridge_name = _new_name
        db.session.commit()

    def bridge_delete(_name): #, _server):
        bl = BridgeList.query.filter_by(bridge_name=_name).first()
        db.session.delete(bl)
        sl = ServerList.query.all()
        for i in sl:
            delete_system_bridge(_name, i.name)
        db.session.commit()
        
    def generate_rules(_name):

        # generate UNIT list
##        print('get rules')
##        print(_name)
        xlx_p = xlxPeer.query.filter_by(server=_name).all()
        mmdvm_p = mmdvmPeer.query.filter_by(server=_name).all()
        all_m = MasterList.query.filter_by(server=_name).all()
        all_o = OBP.query.filter_by(server=_name).all()
        all_p = ProxyList.query.filter_by(server=_name).all()
        rules = BridgeRules.query.filter_by(server=_name).all()
        UNIT = []
        BRIDGES = {}
        disabled = {}
        for i in all_m:
            if i.active == False:
                disabled[i.name] = i.name
            else:
                if i.enable_unit == True:
                    UNIT.append(i.name)
        for i in all_p:
            if i.active == False:
                disabled[i.name] = i.name
            else:
                if i.enable_unit == True:
                    n_systems = i.internal_stop_port - i.internal_start_port
                    n_count = 0
                    while n_count < n_systems:
                        UNIT.append(i.name + '-' + str(n_count))
                        n_count = n_count + 1
        for i in all_o:
            if i.enabled == False:
                disabled[i.name] = i.name
            else:
                if i.enable_unit == True:
                    UNIT.append(i.name)
        for i in xlx_p:
            if i.enabled == False:
                disabled[i.name] = i.name
            else:
                if i.enable_unit == True:
                    UNIT.append(i.name)
        for i in mmdvm_p:
            if i.enabled == False:
                disabled[i.name] = i.name
            else:
                if i.enable_unit == True:
                    UNIT.append(i.name)
        temp_dict = {}
        # populate dict with needed bridges
        for r in rules:
##            print(r.bridge_name)
##            b = BridgeRules.query.filter_by(server=_name).filter_by(server=_name).all()
##            for d in temp_dict.items():
##                if r.bridge_name == d[0]:
##                    print('update rule')
##                if r.bridge_name != d[0]:
##                    print('add dict entry and rule')
            temp_dict[r.bridge_name] = []
##        print(temp_dict)
        BRIDGES = temp_dict.copy()
        for r in temp_dict.items():
            b = BridgeRules.query.filter_by(bridge_name=r[0]).filter_by(server=_name).all()
            for s in b:
                try:
                    if s.system_name == disabled[s.system_name]:
                        pass
                except:
                    if s.timeout == '':
                        timeout = 0
                    else:
                        timeout = int(s.timeout)
                    if s.proxy == True:
                        p = ProxyList.query.filter_by(server=_name).filter_by(name=s.system_name).first()
##                        print(p.external_port)
                        n_systems = p.internal_stop_port - p.internal_start_port
                        n_count = 0
                        while n_count < n_systems:
                            BRIDGES[r[0]].append({'SYSTEM': s.system_name + '-' + str(n_count),    'TS': s.ts, 'TGID': s.tg,    'ACTIVE': s.active, 'TIMEOUT': timeout, 'TO_TYPE': s.to_type,  'ON': ast.literal_eval(str('[' + s.on + ']')), 'OFF': ast.literal_eval(str('[4000,' + s.off + ']')), 'RESET': ast.literal_eval(str('[' + s.reset + ']'))})
                            n_count = n_count + 1

                    else:
                       BRIDGES[r[0]].append({'SYSTEM': s.system_name,    'TS': s.ts, 'TGID': s.tg,    'ACTIVE': s.active, 'TIMEOUT': timeout, 'TO_TYPE': s.to_type,  'ON': ast.literal_eval(str('[' + s.on + ']')), 'OFF': ast.literal_eval(str('[' + s.off + ']')), 'RESET': ast.literal_eval(str('[' + s.reset + ']'))})
            
##            for d in b:
##                print(b.system_name)
        
##                if r.bridge_name == d[0]:
##                    print('update rule')
##                if r.bridge_name != d[0]:
##                    print('add dict entry and rule')
            
##            print(r.tg)
##            print(BRIDGES)
        return [UNIT, BRIDGES]


    def server_get(_name):
##        print(_name)
        #s = ServerList.query.filter_by(name=_name).first()
       # print(s.name)        
        i = ServerList.query.filter_by(name=_name).first()
##        print(i.name)
        s_config = {}
        s_config['GLOBAL'] = {}
        s_config['REPORTS'] = {}
        s_config['ALIASES'] = {}
        s_config['WEB_SERVICE'] = {}
        s_config['OTHER'] = {}

        s_config['GLOBAL'].update({
                    'PATH': i.global_path,
                    'PING_TIME': i.global_ping_time,
                    'MAX_MISSED': i.global_max_missed,
                    'USE_ACL': i.global_use_acl,
                    'REG_ACL': i.global_reg_acl,
                    'SUB_ACL': i.global_sub_acl,
                    'TG1_ACL': i.global_tg1_acl,
                    'TG2_ACL': i.global_tg2_acl
                })
        
        s_config['REPORTS'].update({
                    'REPORT': i.report_enable,
                    'REPORT_INTERVAL': i.report_interval,
                    'REPORT_PORT': i.report_port,
                    'REPORT_CLIENTS': i.report_clients.split(',')
                })
        s_config['ALIASES'].update({
                    'TRY_DOWNLOAD':i.ai_try_download,
                    'PATH': i.ai_path,
                    'PEER_FILE': i.ai_peer_file,
                    'SUBSCRIBER_FILE': i.ai_subscriber_file,
                    'TGID_FILE': i.ai_tgid_file,
                    'PEER_URL': i.ai_peer_url,
                    'SUBSCRIBER_URL': i.ai_subs_url,
                    'STALE_TIME': i.ai_stale * 86400,
                })
        s_config['WEB_SERVICE'].update({
                    'SHORTEN_LENGTH': shorten_length,
                    'SHORTEN_SAMPLE': shorten_sample,
                    'EXTRA_1': extra_1,
                    'EXTRA_2': extra_2,
                    'EXTRA_INT_1': extra_int_1,
                    'EXTRA_INT_2': extra_int_2,
                    'APPEND_INT': append_int,
                    'SHORTEN_PASSPHRASE': i.um_shorten_passphrase,
                    'BURN_FILE': i.um_burn_file,
                    'BURN_INT': burn_int,


                })
        s_config['OTHER'].update({
            'UNIT_TIME': i.unit_time,
            'OTHER_OPTIONS': i.other_options
            })
##        print(s_config['REPORTS'])
        return s_config
    def masters_get(_name):
##        # print(_name)
        #s = ServerList.query.filter_by(name=_name).first()
       # print(s.name)        
        i = MasterList.query.filter_by(server=_name).filter_by(active=True).all()
        o = OBP.query.filter_by(server=_name).filter_by(enabled=True).all()
        p = ProxyList.query.filter_by(server=_name).filter_by(active=True).all()
        # print('get masters')
        master_config_list = {}
##        master_config_list['SYSTEMS'] = {}
        # print(i)
        for m in i:
##            print (m.name)
            master_config_list.update({m.name: {
                'MODE': 'MASTER',
                'ENABLED': m.active,
                'USE_USER_MAN': m.enable_um,
                'STATIC_APRS_POSITION_ENABLED': m.static_positions,
                'REPEAT': m.repeat,
                'MAX_PEERS': m.max_peers,
                'IP': m.ip,
                'PORT': m.port,
                'PASSPHRASE': m.passphrase, #bytes(m.passphrase, 'utf-8'),
                'GROUP_HANGTIME': m.group_hang_time,
                'USE_ACL': m.use_acl,
                'REG_ACL': m.reg_acl,
                'SUB_ACL': m.sub_acl,
                'TG1_ACL': m.tg1_acl,
                'TG2_ACL': m.tg2_acl,
                'OTHER_OPTIONS': m.other_options
            }})
            master_config_list[m.name].update({'PEERS': {}})
        for obp in o:
##            print(type(obp.network_id))
            master_config_list.update({obp.name: {
                        'MODE': 'OPENBRIDGE',
                        'ENABLED': obp.enabled,
                        'NETWORK_ID': obp.network_id, #int(obp.network_id).to_bytes(4, 'big'),
                        'IP': gethostbyname(obp.ip),
                        'PORT': obp.port,
                        'PASSPHRASE': obp.passphrase, #bytes(obp.passphrase.ljust(20,'\x00')[:20], 'utf-8'),
                        'TARGET_SOCK': (obp.target_ip, obp.target_port),
                        'TARGET_IP': gethostbyname(obp.target_ip),
                        'TARGET_PORT': obp.target_port,
                        'BOTH_SLOTS': obp.both_slots,
                        'USE_ACL': obp.use_acl,
                        'SUB_ACL': obp.sub_acl,
                        'TG1_ACL': obp.tg_acl,
                        'TG2_ACL': 'PERMIT:ALL',
                        'USE_ENCRYPTION': obp.obp_encryption,
                        'ENCRYPTION_KEY': obp.encryption_key,
                        'OTHER_OPTIONS': obp.other_options
                    }})
        for pr in p:
            master_config_list.update({pr.name: {
                        'MODE': 'PROXY',
                        'ENABLED': pr.active,
                        'EXTERNAL_PROXY_SCRIPT': pr.external_proxy,
                        'STATIC_APRS_POSITION_ENABLED': pr.static_positions,
                        'USE_USER_MAN': pr.enable_um,
                        'REPEAT': pr.repeat,
                        'PASSPHRASE': pr.passphrase, #bytes(pr.passphrase, 'utf-8'),
                        'EXTERNAL_PORT': pr.external_port,
                        'INTERNAL_PORT_START': pr.internal_start_port,
                        'INTERNAL_PORT_STOP': pr.internal_stop_port,
                        'GROUP_HANGTIME': pr.group_hang_time,
                        'USE_ACL': pr.use_acl,
                        'REG_ACL': pr.reg_acl,
                        'SUB_ACL': pr.sub_acl,
                        'TG1_ACL': pr.tg1_acl,
                        'TG2_ACL': pr.tg2_acl,
                        'OTHER_OPTIONS': pr.other_options
                    }})
            master_config_list[pr.name].update({'PEERS': {}})
            
        # print(master_config_list)
        return master_config_list

    def add_system_rule(_bridge_name, _system_name, _ts, _tg, _active, _timeout, _to_type, _on, _off, _reset, _server):
        proxy = ProxyList.query.filter_by(server=_server).filter_by(name=_system_name).first()
        is_proxy = False
        try:
            if _system_name == proxy.name:
                is_proxy = True
        except:
            pass
        add_system = BridgeRules(
            bridge_name = _bridge_name,
            system_name = _system_name,
            ts = _ts,
            tg = _tg,
            active = _active,
            timeout = _timeout,
            to_type = _to_type,
            on = _on,
            off = _off,
            reset = _reset,
            server = _server,
            proxy = is_proxy
            )
        db.session.add(add_system)
        db.session.commit()

    def edit_system_rule(_bridge_name, _system_name, _ts, _tg, _active, _timeout, _to_type, _on, _off, _reset, _server):
        proxy = ProxyList.query.filter_by(server=_server).filter_by(name=_system_name).first()
        is_proxy = False
        try:
            if _system_name == proxy.name:
                is_proxy = True
        except:
            pass
        r = BridgeRules.query.filter_by(system_name=_system_name).filter_by(bridge_name=_bridge_name).first()
##        print('---')
##        print(_system_name)
##        print(_bridge_name)
##        print(r)
##        for i in r:
##            print(i.name)
##        add_system = BridgeRules(
        r.bridge_name = _bridge_name
        r.system_name = _system_name
        r.ts = _ts
        r.tg = _tg
        r.active = _active
        r.timeout = _timeout
        r.to_type = _to_type
        r.on = _on
        r.off = _off
        r.reset = _reset
        r.server = _server
        #r.public_list = _public_list
        r.proxy = is_proxy
##        db.session.add(add_system)
        db.session.commit()

    def delete_system_bridge(_name, _server):
        dr = BridgeRules.query.filter_by(server=_server).filter_by(bridge_name=_name).all()
        for i in dr:
            db.session.delete(i)
        db.session.commit()
        
    def delete_system_rule(_name, _server, _system):
        dr = BridgeRules.query.filter_by(server=_server).filter_by(bridge_name=_name).filter_by(system_name=_system).first()
        db.session.delete(dr)
        db.session.commit()


    def server_edit(_name, _secret, _ip, _global_path, _global_ping_time, _global_max_missed, _global_use_acl, _global_reg_acl, _global_sub_acl, _global_tg1_acl, _global_tg2_acl, _ai_subscriber_file, _ai_try_download, _ai_path, _ai_peer_file, _ai_tgid_file, _ai_peer_url, _ai_subs_url, _ai_stale, _um_shorten_passphrase, _um_burn_file, _report_enable, _report_interval, _report_port, _report_clients, _unit_time, _notes, _dash_url, _public_notes, _other_options):
        print(_public_notes)
        s = ServerList.query.filter_by(name=_name).first()
        # print(_name)
        if _secret == '':
            s.secret = s.secret
        else:
            s.secret = hashlib.sha256(_secret.encode()).hexdigest()
        s.ip = _ip
        s.global_path =_global_path
        s.global_ping_time = _global_ping_time
        s.global_max_missed = _global_max_missed
        s.global_use_acl = _global_use_acl
        s.global_reg_acl = _global_reg_acl
        s.global_sub_acl = _global_sub_acl
        s.global_tg1_acl = _global_tg1_acl
        s.global_tg2_acl = _global_tg2_acl
        s.ai_try_download = _ai_try_download
        s.ai_path = _ai_path
        s.ai_peer_file = _ai_peer_file
        s.ai_subscriber_file = _ai_subscriber_file
        s.ai_tgid_file = _ai_tgid_file
        s.ai_peer_url = _ai_peer_url
        s.ai_subs_url = _ai_subs_url
        s.ai_stale = _ai_stale
        # Pull from config file for now
##        um_append_int = db.Column(db.Integer(), primary_key=False, server_default='2')
        s.um_shorten_passphrase = _um_shorten_passphrase
        s.um_burn_file = _um_burn_file
        # Pull from config file for now
##        um_burn_int = db.Column(db.Integer(), primary_key=False, server_default='6')
        s.report_enable = _report_enable
        s.report_interval = _report_interval
        s.report_port = _report_port
        s.report_clients = _report_clients
        s.unit_time = int(_unit_time)
        s.notes = _notes
        s.dash_url = _dash_url
        s.public_notes = _public_notes
        s.other_options = _other_options
        db.session.commit()
        
    def master_delete(_mode, _server, _name):
        if _mode == 'MASTER':
            m = MasterList.query.filter_by(server=_server).filter_by(name=_name).first()
        if _mode == 'PROXY':
            m = ProxyList.query.filter_by(server=_server).filter_by(name=_name).first()
        if _mode == 'OBP':
            m = OBP.query.filter_by(server=_server).filter_by(name=_name).first()
        dr = BridgeRules.query.filter_by(server=_server).filter_by(system_name=_name).all()
        for d in dr:
            db.session.delete(d)
        db.session.delete(m)
        db.session.commit()

    def edit_master(_mode, _name, _server, _static_positions, _repeat, _active, _max_peers, _ip, _port, _enable_um, _passphrase, _group_hang_time, _use_acl, _reg_acl, _sub_acl, _tg1_acl, _tg2_acl, _enable_unit, _notes, _external_proxy, _int_start_port, _int_stop_port, _network_id, _target_ip, _target_port, _both_slots, _public, _other_options, _encryption_key, _obp_encryption):
##        print(_mode)
####        print(_server)
##        print(_name)
        if _mode == 'MASTER':
##            print(_name)
            m = MasterList.query.filter_by(server=_server).filter_by(name=_name).first()
##            m.name = _name,
            m.static_positions = _static_positions
            m.repeat = _repeat
            m.active = _active
            m.max_peers = int(_max_peers)
            m.ip = _ip
            m.port = int(_port)
            m.enable_um = _enable_um
            m.passphrase = str(_passphrase)
            m.group_hang_time = int(_group_hang_time)
            m.use_acl = _use_acl
            m.reg_acl = _reg_acl
            m.sub_acl = _sub_acl
            m.tg1_acl = _tg1_acl
            m.tg2_acl = _tg2_acl
            m.enable_unit = _enable_unit
##            m.server = _server
            m.notes = _notes
            m.public_list = _public
            m.other_options = _other_options
            db.session.commit()
        if _mode == 'OBP':
            # print(_enable_unit)
##            print(enable_unit)
            o = OBP.query.filter_by(server=_server).filter_by(name=_name).first()
            o.enabled = _active
            o.network_id = _network_id
            o.ip = _ip
            o.port = _port
            o.passphrase = _passphrase
            o.target_ip = _target_ip
            o.target_port = _target_port
            o.both_slots = _both_slots
            o.use_acl = _use_acl
            o.sub_acl = _sub_acl
            o.tg1_acl = _tg1_acl
            o.tg2_acl = _tg2_acl
            o.enable_unit = _enable_unit
            o.notes = _notes
            o.other_options = _other_options
            o.encryption_key = _encryption_key
            o.obp_encryption = _obp_encryption
            db.session.commit()
        if _mode == 'PROXY':
##            print(_int_start_port)
##            print(_int_stop_port)
            p = ProxyList.query.filter_by(server=_server).filter_by(name=_name).first()
            p.name = _name
            p.static_positions = _static_positions
            p.repeat = _repeat
            p.active = _active
            p.enable_um = _enable_um
            p.passphrase = _passphrase
            p.external_proxy = _external_proxy
            external_port = int(_port)
            p.group_hang_time = int(_group_hang_time)
            p.internal_start_port = _int_start_port
            p.internal_stop_port = _int_stop_port
            p.use_acl = _use_acl
            p.reg_acl = _reg_acl
            p.sub_acl = _sub_acl
            p.tg1_acl = _tg1_acl
            p.tg2_acl = _tg2_acl
            p.enable_unit = _enable_unit
            p.server = _server
            p.notes = _notes
            p.public_list = _public
            p.other_options = _other_options
            db.session.commit()
##            add_proxy = ProxyList(
##                name = _name,
##                static_positions = _static_positions,
##                repeat = _repeat,
##                active = _active,
##                enable_um = _enable_um,
##                passphrase = _passphrase,
##                external_proxy = _external_proxy,
##                group_hang_time = int(_group_hang_time),
##                internal_start_port = int(_int_start_port),
##                internal_stop_port = int(_int_stop_port),
##                use_acl = _use_acl,
##                reg_acl = _reg_acl,
##                sub_acl = _sub_acl,
##                tg1_acl = _tg1_acl,
##                tg2_acl = _tg2_acl,
##                enable_unit = _enable_unit,
##                server = _server,
##                notes = _notes
##                )
##            db.session.add(add_master)

    def add_master(_mode, _name, _server, _static_positions, _repeat, _active, _max_peers, _ip, _port, _enable_um, _passphrase, _group_hang_time, _use_acl, _reg_acl, _sub_acl, _tg1_acl, _tg2_acl, _enable_unit, _notes, _external_proxy, _int_start_port, _int_stop_port, _network_id, _target_ip, _target_port, _both_slots, _public, _other_options, _encryption_key, _obp_encryption):
        # print(_mode)
        if _mode == 'MASTER':
            add_master = MasterList(
                name = _name,
                static_positions = _static_positions,
                repeat = _repeat,
                active = _active,
                max_peers = int(_max_peers),
                ip = _ip,
                port = int(_port),
                enable_um = _enable_um,
                passphrase = _passphrase,
                group_hang_time = int(_group_hang_time),
                use_acl = _use_acl,
                reg_acl = _reg_acl,
                sub_acl = _sub_acl,
                tg1_acl = _tg1_acl,
                tg2_acl = _tg2_acl,
                enable_unit = _enable_unit,
                server = _server,
                notes = _notes,
                public_list = _public,
                other_options = _other_options
                )
            db.session.add(add_master)
            db.session.commit()
        if _mode == 'PROXY':
            add_proxy = ProxyList(
                name = _name,
                static_positions = _static_positions,
                repeat = _repeat,
                active = _active,
                enable_um = _enable_um,
                passphrase = _passphrase,
                external_proxy = _external_proxy,
                external_port = int(_port),
                group_hang_time = int(_group_hang_time),
                internal_start_port = int(_int_start_port),
                internal_stop_port = int(_int_stop_port),
                use_acl = _use_acl,
                reg_acl = _reg_acl,
                sub_acl = _sub_acl,
                tg1_acl = _tg1_acl,
                tg2_acl = _tg2_acl,
                enable_unit = _enable_unit,
                server = _server,
                notes = _notes,
                public_list = _public,
                other_options = _other_options
                )
            db.session.add(add_proxy)
            db.session.commit()
        if _mode == 'OBP':
                # print(_name)
                # print(_network_id)
                add_OBP = OBP(
                    name = _name,
                    enabled = _active,
                    network_id = _network_id, #
                    ip = _ip,
                    port = _port,
                    passphrase = _passphrase,
                    target_ip = _target_ip,#
                    target_port = _target_port,#
                    both_slots = _both_slots,#
                    use_acl = _use_acl,
                    sub_acl = _sub_acl,
                    tg_acl = _tg1_acl,
                    enable_unit = _enable_unit,
                    server = _server,
                    notes = _notes,
                    other_options = _other_options,
                    encryption_key = _encryption_key,
                    obp_encryption = _obp_encryption
                    )
                db.session.add(add_OBP)
                db.session.commit()

        
    def server_add(_name, _secret, _ip, _global_path, _global_ping_time, _global_max_missed, _global_use_acl, _global_reg_acl, _global_sub_acl, _global_tg1_acl, _global_tg2_acl, _ai_subscriber_file, _ai_try_download, _ai_path, _ai_peer_file, _ai_tgid_file, _ai_peer_url, _ai_subs_url, _ai_stale, _um_shorten_passphrase, _um_burn_file, _report_enable, _report_interval, _report_port, _report_clients, _unit_time, _notes, _dash_url, _public_notes, _other_options):
        add_server = ServerList(
        name = _name,
        secret = hashlib.sha256(_secret.encode()).hexdigest(),
##        public_list = _public_list,
        ip = _ip,
        global_path =_global_path,
        global_ping_time = _global_ping_time,
        global_max_missed = _global_max_missed,
        global_use_acl = _global_use_acl,
        global_reg_acl = _global_reg_acl,
        global_sub_acl = _global_sub_acl,
        global_tg1_acl = _global_tg1_acl,
        global_tg2_acl = _global_tg2_acl,
        ai_try_download = _ai_try_download,
        ai_path = _ai_path,
        ai_peer_file = _ai_peer_file,
        ai_subscriber_file = _ai_subscriber_file,
        ai_tgid_file = _ai_tgid_file,
        ai_peer_url = _ai_peer_url,
        ai_subs_url = _ai_subs_url,
        ai_stale = _ai_stale,
        # Pull from config file for now
##        um_append_int = db.Column(db.Integer(), primary_key=False, server_default='2')
        um_shorten_passphrase = _um_shorten_passphrase,
        um_burn_file = _um_burn_file,
        # Pull from config file for now
##        um_burn_int = db.Column(db.Integer(), primary_key=False, server_default='6')
        report_enable = _report_enable,
        report_interval = _report_interval,
        report_port = _report_port,
        report_clients = _report_clients,
        unit_time = int(_unit_time),
        notes = _notes,
        dash_url = _dash_url,
        public_notes = _public_notes,
        other_options = _other_options
        )
        db.session.add(add_server)
        db.session.commit()
    def peer_add(_mode, _name, _enabled, _loose, _ip, _port, _master_ip, _master_port, _passphrase, _callsign, _radio_id, _rx, _tx, _tx_power, _cc, _lat, _lon, _height, _loc, _desc, _slots, _url, _grp_hang, _xlx_mod, _opt, _use_acl, _sub_acl, _1_acl, _2_acl, _svr, _enable_unit, _notes, _other_options):
        if _mode == 'xlx':
            xlx_peer_add = xlxPeer(
                    name = _name,
                    enabled = _enabled,
                    loose = _loose,
                    ip = _ip,
                    port = _port,
                    master_ip = _master_ip,
                    master_port = _master_port,
                    passphrase = _passphrase,
                    callsign = _callsign,
                    radio_id = _radio_id,
                    rx_freq = _rx,
                    tx_freq = _tx,
                    tx_power = _tx_power,
                    color_code = _cc,
                    latitude = _lat,
                    longitude = _lon,
                    height = _height,
                    location = _loc,
                    description = _desc,
                    slots = _slots,
                    xlxmodule = _xlx_mod,
                    url = _url,
                    enable_unit = _enable_unit,
                    group_hangtime = _grp_hang,
                    use_acl = _use_acl,
                    sub_acl = _sub_acl,
                    tg1_acl = _1_acl,
                    tg2_acl = _2_acl,
                    server = _svr,
                    notes = _notes,
                    other_options = _other_options
                        )
            db.session.add(xlx_peer_add)
            db.session.commit()
        if _mode == 'mmdvm':
            mmdvm_peer_add = mmdvmPeer(
                    name = _name,
                    enabled = _enabled,
                    loose = _loose,
                    ip = _ip,
                    port = _port,
                    master_ip = _master_ip,
                    master_port = _master_port,
                    passphrase = _passphrase,
                    callsign = _callsign,
                    radio_id = _radio_id,
                    rx_freq = _rx,
                    tx_freq = _tx,
                    tx_power = _tx_power,
                    color_code = _cc,
                    latitude = _lat,
                    longitude = _lon,
                    height = _height,
                    location = _loc,
                    description = _desc,
                    slots = _slots,
                    url = _url,
                    enable_unit = _enable_unit,
                    group_hangtime = _grp_hang,
                    use_acl = _use_acl,
                    sub_acl = _sub_acl,
                    tg1_acl = _1_acl,
                    tg2_acl = _2_acl,
                    server = _svr,
                    notes = _notes,
                    other_options = _other_options
                        )
            db.session.add(mmdvm_peer_add)
            db.session.commit()
    def peer_edit(_mode, _server, _name, _enabled, _loose, _ip, _port, _master_ip, _master_port, _passphrase, _callsign, _radio_id, _rx, _tx, _tx_power, _cc, _lat, _lon, _height, _loc, _desc, _slots, _url, _grp_hang, _xlx_mod, _opt, _use_acl, _sub_acl, _1_acl, _2_acl, _enable_unit, _notes, _other_options):
##        print(_mode)
        if _mode == 'mmdvm':
##            print(_server)
##            print(_name)
##            print(_name)
##            s = mmdvmPeer.query.filter_by(server=_server).filter_by(name=_name).first()
            p = mmdvmPeer.query.filter_by(server=_server).filter_by(name=_name).first()
            p.enabled = _enabled
            p.loose = _loose
            p.ip = _ip
            p.port = _port
            p.master_ip = _master_ip
            p.master_port = _master_port
            p.passphrase = _passphrase
            p.callsign = _callsign
            p.radio_id = _radio_id
            p.rx_freq = _rx
            p.tx_freq = _tx
            p.tx_power = _tx_power
            p.color_code = _cc
            p.latitude = _lat
            p.longitude = _lon
            p.height = _height
            p.location = _loc
            p.description = _desc
            p.slots = _slots
            p.url = _url
            p.enable_unit = _enable_unit
            p.group_hangtime = _grp_hang
            p.options = _opt
            p.use_acl = _use_acl
            p.sub_acl = _sub_acl
            p.tg1_acl = _1_acl
            p.tg2_acl = _2_acl
            p.notes = _notes
            p.other_options = _other_options
        if _mode == 'xlx':
##            print(type(_server))
##            print(type(_name))
##            print(type(_enabled))
##            print((_enable_unit))
##            print(type(_use_acl))
####            print(_port)


##            s = mmdvmPeer.query.filter_by(server=_server).filter_by(name=_name).first()
            p = xlxPeer.query.filter_by(server=_server).filter_by(name=_name).first()
            # print(type(p.enable_unit))
            p.enabled = _enabled
            p.loose = _loose
            p.ip = _ip
            p.port = _port
            p.master_ip = _master_ip
            p.master_port = _master_port
            p.passphrase = _passphrase
            p.callsign = _callsign
            p.radio_id = _radio_id
            p.rx_freq = _rx
            p.tx_freq = _tx
            p.tx_power = _tx_power
            p.color_code = _cc
            p.latitude = _lat
            p.longitude = _lon
            p.height = _height
            p.location = _loc
            p.description = _desc
            p.slots = _slots
            p.url = _url
            p.options = _opt
            p.enable_unit = _enable_unit
            p.xlxmodule = _xlx_mod
            p.group_hangtime = _grp_hang
            p.use_acl = _use_acl
            p.sub_acl = _sub_acl
            p.tg1_acl = _1_acl
            p.tg2_acl = _2_acl
            p.notes = _notes
            p.other_options = _other_options
        db.session.commit()
            
            


# Test server configs

    @app.route('/manage_servers', methods=['POST', 'GET'])
    @login_required
    @roles_required('Admin')
    def edit_server_db():
        # Edit server
        if request.args.get('save_mode'):# == 'new' and request.form.get('server_name'):
##            _port = int(request.form.get('server_port'))
            _global_ping_time = int(request.form.get('ping_time'))
            _global_max_missed = int(request.form.get('max_missed'))
            _ai_stale = int(request.form.get('stale_days'))
            _report_interval = int(request.form.get('report_interval'))
            _report_port = int(request.form.get('report_port'))
            _global_use_acl = False
            _ai_try_download = False
            _um_shorten_passphrase = False
            _report_enabled = False
            if request.form.get('use_acl') == 'True':
                _global_use_acl = True
            if request.form.get('aliases_enabled') == 'True':
                _ai_try_download = True
            if request.form.get('um_shorten_passphrase') == 'True':
                _um_shorten_passphrase = True
            if request.form.get('report') == 'True':
                _report_enabled = True
##            if  request.form.get('public_list') == 'True':
##                public_list = True
##            else:
##                _global_use_acl = False
##                _ai_try_download = False
##                _um_shorten_passphrase = False
##                _report_enabled = False
##                public_list = False

            if request.args.get('save_mode') == 'new':
                if request.form.get('server_name') == '':
                    content = '''<h3 style="text-align: center;">Server can't have blank name.</h3>
<p style="text-align: center;">Redirecting in 3 seconds.</p>
<meta http-equiv="refresh" content="3; URL=manage_servers" />'''
                else:
                    server_add(request.form.get('server_name'), request.form.get('server_secret'), request.form.get('server_ip'), request.form.get('global_path'), _global_ping_time, _global_max_missed, _global_use_acl, request.form.get('reg_acl'), request.form.get('sub_acl'), request.form.get('global_ts1_acl'), request.form.get('global_ts2_acl'), request.form.get('sub_file'), _ai_try_download, request.form.get('aliases_path'), request.form.get('peer_file'), request.form.get('tgid_file'), request.form.get('peer_url'), request.form.get('sub_url'), _ai_stale, _um_shorten_passphrase, request.form.get('um_burn_file'), _report_enabled, _report_interval, _report_port, request.form.get('report_clients'), request.form.get('unit_time'), request.form.get('notes'), request.form.get('dash_url'), request.form.get('public_notes'), request.form.get('other_options'))
                    content = '''<h3 style="text-align: center;">Server saved.</h3>
    <p style="text-align: center;">Redirecting in 3 seconds.</p>
    <meta http-equiv="refresh" content="3; URL=manage_servers" />'''
            if request.args.get('save_mode') == 'edit':
##                print(_ai_try_download)
##                print(request.args.get('server'))
                server_edit(request.args.get('server'), request.form.get('server_secret'), request.form.get('server_ip'), request.form.get('global_path'), _global_ping_time, _global_max_missed, _global_use_acl, request.form.get('reg_acl'), request.form.get('sub_acl'), request.form.get('global_ts1_acl'), request.form.get('global_ts2_acl'), request.form.get('sub_file'), _ai_try_download, request.form.get('aliases_path'), request.form.get('peer_file'), request.form.get('tgid_file'), request.form.get('peer_url'), request.form.get('sub_url'), _ai_stale, _um_shorten_passphrase, request.form.get('um_burn_file'), _report_enabled, _report_interval, _report_port, request.form.get('report_clients'), request.form.get('unit_time'), request.form.get('notes'), request.form.get('dash_url'), request.form.get('public_notes'), request.form.get('other_options'))
                content = '''<h3 style="text-align: center;">Server changed.</h3>
<p style="text-align: center;">Redirecting in 3 seconds.</p>
<meta http-equiv="refresh" content="3; URL=manage_servers" />'''
        elif request.args.get('delete_server'):
            server_delete(request.args.get('delete_server'))
            content = '''<h3 style="text-align: center;">Server deleted.</h3>
<p style="text-align: center;">Redirecting in 3 seconds.</p>
<meta http-equiv="refresh" content="3; URL=manage_servers" />'''
        elif request.args.get('edit_server'):
            s = ServerList.query.filter_by(name=request.args.get('edit_server')).first()
            
            content = '''
<p style="text-align: center;">&nbsp;</p>

<p style="text-align: center;"><strong><a href="manage_servers?delete_server=''' + str(s.name) + '''">Delete server</a></strong></p>

<p style="text-align: center;"><strong><a href="/import_rules/''' + str(s.name) + '''">Import Rules</a></strong></p>

<form action="manage_servers?save_mode=edit&server=''' + str(s.name) + '''" method="post">
<p style="text-align: center;">&nbsp;</p>
<h3 style="text-align: center;"><strong>Server<br /></strong></h3>
<table style="width: 300px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td style="width: 30%;"><strong>&nbsp;Server Name:</strong></td>
<td style="width: 70%;">&nbsp;<strong>''' + str(s.name) + '''</strong></td>
</tr>
<tr>
<td style="width: 16.0381%;"><strong>&nbsp;Server Secret:</strong></td>
<td style="width: 78.7895%;">&nbsp;<input name="server_secret" type="text" value="" /></td>
</tr>
<tr>
<td style="width: 16.0381%;"><strong>&nbsp;Dashboard URL:</strong></td>
<td style="width: 78.7895%;">&nbsp;<input name="dash_url" type="text" value="''' + str(s.dash_url) + '''"/></td>
</tr>
<tr>
<td style="width: 16.0381%;"><strong>&nbsp;Host (IP/DNS, for listing on passphrase page):</strong></td>
<td style="width: 78.7895%;">&nbsp;<input name="server_ip" type="text" value="''' + str(s.ip) + '''"/></td>
</tr>

<tr>
<td style="width: 16.0381%;"><strong>&nbsp;Unit Call Timeout (minutes):</strong></td>
<td style="width: 78.7895%;">&nbsp;<input name="unit_time" type="text" value="''' + str(s.unit_time) + '''"/></td>
</tr>

<tr>
<td><strong>&nbsp;Misc Options:</strong></td>
<td>&nbsp;<textarea id="other_options" cols="50" name="other_options" rows="4">''' + str(s.other_options) + '''</textarea></td>
</tr>

<tr>
<td><strong>&nbsp;Notes:</strong></td>
<td>&nbsp;<textarea id="notes" cols="50" name="notes" rows="4">''' + str(s.notes) + '''</textarea></td>
</tr>
<tr>
<td><strong>&nbsp;Public Notes:</strong></td>
<td>&nbsp;<textarea id="public_notes" cols="50" name="public_notes" rows="4">''' + str(s.public_notes) + '''</textarea></td>
</tr>

</tbody>
</table>
<h3 style="text-align: center;"><strong>Global</strong></h3>
<table style="width: 300px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td><strong>&nbsp;Path:</strong></td>
<td>&nbsp;<input name="global_path" type="text" value="''' + str(s.global_path) + '''" /></td>
</tr>
<tr>
<td><strong>&nbsp;Ping Time:</strong></td>
<td>&nbsp;<input name="ping_time" type="text" value="''' + str(s.global_ping_time) + '''" /></td>
</tr>
<tr>
<td><strong>&nbsp;Max Missed:</strong></td>
<td>&nbsp;<input name="max_missed" type="text" value="''' + str(s.global_max_missed) + '''" /></td>
</tr>
<tr>
<td><strong>&nbsp;Use ACLs:</strong></td>
<td>&nbsp;<select name="use_acl">
<option selected="selected" value="''' + str(s.global_use_acl) + '''">Current: ''' + str(s.global_use_acl) + '''</option>
<option value="False">False</option>
<option value="True">True</option>

</select></td>
</tr>
<tr>
<td><strong>&nbsp;Regular ACLs:</strong></td>
<td>&nbsp;<input name="reg_acl" type="text" value="''' + str(s.global_reg_acl) + '''" /></td>
</tr>
<tr>
<td><strong>&nbsp;Subscriber ACSs:</strong></td>
<td>&nbsp;<input name="sub_acl" type="text" value="''' + str(s.global_sub_acl) + '''" /></td>
</tr>
<tr>
<td><strong>&nbsp;Timeslot 1 ACLs:</strong></td>
<td>&nbsp;<input name="global_ts1_acl" type="text" value="''' + str(s.global_tg1_acl) + '''" /></td>
</tr>
<tr>
<td><strong>&nbsp;Timeslot 2 ACLs:</strong></td>
<td>&nbsp;<input name="global_ts2_acl" type="text" value="''' + str(s.global_tg2_acl) + '''" /></td>
</tr>
</tbody>
</table>
<p style="text-align: center;">&nbsp;</p>
<h3 style="text-align: center;"><strong>Reports</strong></h3>
<table style="width: 300px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td><strong>&nbsp;Enable:</strong></td>
<td>&nbsp;<select name="report">
<option selected="selected" value="''' + str(s.report_enable) + '''">Current: ''' + str(s.report_enable) + '''</option>
<option value="False">False</option>
<option value="True">True</option>

</select></td>
</tr>
<tr>
<td><strong>&nbsp;Interval:</strong></td>
<td>&nbsp;<input name="report_interval" type="text" value="''' + str(s.report_interval) + '''" /></td>
</tr>
<tr>
<td><strong>&nbsp;Port:</strong></td>
<td>&nbsp;<input name="report_port" type="text" value="''' + str(s.report_port) + '''" /></td>
</tr>
<tr>
<td><strong>&nbsp;Clients:</strong></td>
<td>&nbsp;<input name="report_clients" type="text" value="''' + str(s.report_clients) + '''" /></td>
</tr>
</tbody>
</table>
<!--
<p style="text-align: center;">&nbsp;</p>
<h3 style="text-align: center;"><strong>Logger<br /></strong></h3>
<table style="width: 300px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td><strong>&nbsp;File:</strong></td>
<td>&nbsp;<input name="log_file" type="text" value="/tmp/hbnet.log" /></td>
</tr>
<tr>
<td><strong>&nbsp;Log Handler:</strong></td>
<td>&nbsp;<input name="log_hendelers" type="text" value="file" /></td>
</tr>
<tr>
<td><strong>&nbsp;Log Level:</strong></td>
<td>&nbsp;<input name="log_level" type="text" value="DEBUG" /></td>
</tr>
<tr>
<td><strong>&nbsp;Log Name:</strong></td>
<td>&nbsp;<input name="log_name" type="text" value="HBNet" /></td>
</tr>
</tbody>
</table>
-->
<p style="text-align: center;">&nbsp;</p>
<h3 style="text-align: center;"><strong>Aliases<br /></strong></h3>
<table style="width: 300px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td><strong>&nbsp;Download:</strong></td>
<td>&nbsp;<select name="aliases_enabled">
<option selected="selected" value="''' + str(s.ai_try_download) + '''">Current: ''' + str(s.ai_try_download) + '''</option>
<option value="False">False</option>
<option value="True">True</option>

</select></td>
</tr>
<tr>
<td><strong>&nbsp;Path:</strong></td>
<td>&nbsp;<input name="aliases_path" type="text" value="''' + str(s.ai_path) + '''" /></td>
</tr>
<tr>
<td><strong>&nbsp;Peer File:</strong></td>
<td>&nbsp;<input name="peer_file" type="text" value="''' + str(s.ai_peer_file) + '''" /></td>
</tr>
<tr>
<td><strong>&nbsp;Subscriber File:</strong></td>
<td>&nbsp;<input name="sub_file" type="text" value="''' + str(s.ai_subscriber_file) + '''" /></td>
</tr>
<tr>
<td><strong>&nbsp;Talkgroup ID File:</strong></td>
<td>&nbsp;<input name="tgid_file" type="text" value="''' + str(s.ai_tgid_file) + '''" /></td>
</tr>
<tr>
<td><strong>&nbsp;Peer URL:</strong></td>
<td>&nbsp;<input name="peer_url" type="text" value="''' + str(s.ai_peer_url) + '''" /></td>
</tr>
<tr>
<td><strong>&nbsp;Subscriber URL:</strong></td>
<td>&nbsp;<input name="sub_url" type="text" value="''' + str(s.ai_subs_url) + '''" /></td>
</tr>
<tr>
<td><strong>&nbsp;Stale time(days):</strong></td>
<td>&nbsp;<input name="stale_days" type="text" value="''' + str(s.ai_stale) + '''" /></td>
</tr>
</tbody>
</table>
  <br>
  <p style="text-align: center;">&nbsp;</p>
<h3 style="text-align: center;"><strong>User Manager<br /></strong></h3>
<table style="width: 300px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
</tr>
<tr>
<td style="width: 16.0381%;"><strong>&nbsp;Use short passphrase:</strong></td>
<td style="width: 78.7895%;"><select name="um_shorten_passphrase">
<option selected="selected" value="''' + str(s.um_shorten_passphrase) + '''">Current: ''' + str(s.um_shorten_passphrase) + '''</option>
<option value="False">False</option>
<option value="True">True</option>

</select></td>
</tr>
<tr>
<td style="width: 16.0381%;"><strong>&nbsp;Burned IDs File:</strong></td>
<td style="width: 78.7895%;">&nbsp;<input name="um_burn_file" type="text" value="''' + str(s.um_burn_file) + '''"/></td>
</tr>
</tbody>
</table>
<p style="text-align: center;">&nbsp;</p>
<p style="text-align: center;"><input type="submit" value="Save" /></form></p>
<p style="text-align: center;">&nbsp;</p>
'''
        # Add new server
        elif request.args.get('add'): # == 'yes':
            content = '''
<form action="manage_servers?save_mode=new" method="post">
  <p style="text-align: center;">&nbsp;</p>
<h3 style="text-align: center;"><strong>Server<br /></strong></h3>
<table style="width: 300px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td style="width: 30%;"><strong>&nbsp;Server Name:</strong></td>
<td style="width: 70%;">&nbsp;<input name="server_name" type="text" /></td>
</tr>
<tr>
<td style="width: 16.0381%;"><strong>&nbsp;Server Secret:</strong></td>
<td style="width: 78.7895%;">&nbsp;<input name="server_secret" type="text" value="secret_passphrase" /></td>
</tr>
<tr>
<td style="width: 30%;"><strong>&nbsp;Dashboard URL:</strong></td>
<td style="width: 70%;">&nbsp;<input name="dash_url" type="text" /></td>
</tr>
<tr>
<td style="width: 16.0381%;"><strong>&nbsp;Host (IP/DNS):</strong></td>
<td style="width: 78.7895%;">&nbsp;<input name="server_ip" type="text" /></td>
</tr>

<tr>
<td style="width: 16.0381%;"><strong>&nbsp;Unit Call Timeout (minutes):</strong></td>
<td style="width: 78.7895%;">&nbsp;<input name="unit_time" type="text" value="10080"/></td>
</tr>

<tr>
<td><strong>&nbsp;Misc Options:</strong></td>
<td>&nbsp;<textarea id="other_options" cols="50" name="other_options" rows="4"></textarea></td>
</tr>

<tr>
<td><strong>&nbsp;Notes (HTML OK):</strong></td>
<td>&nbsp;<textarea id="notes" cols="50" name="notes" rows="4"></textarea></td>
</tr>
<tr>
<td><strong>&nbsp;Public Notes (HTML OK):</strong></td>
<td>&nbsp;<textarea id="public_notes" cols="50" name="public_notes" rows="4"></textarea></td>
</tr>
</tbody>
</table>
<h3 style="text-align: center;"><strong>Global</strong></h3>
<table style="width: 300px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td><strong>&nbsp;Path:</strong></td>
<td>&nbsp;<input name="global_path" type="text" value="./" /></td>
</tr>
<tr>
<td><strong>&nbsp;Ping Time:</strong></td>
<td>&nbsp;<input name="ping_time" type="text" value="5" /></td>
</tr>
<tr>
<td><strong>&nbsp;Max Missed:</strong></td>
<td>&nbsp;<input name="max_missed" type="text" value="3" /></td>
</tr>
<tr>
<td><strong>&nbsp;Use ACLs:</strong></td>
<td>&nbsp;<select name="use_acl">
<option selected="selected" value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>
<tr>
<td><strong>&nbsp;Regular ACLs:</strong></td>
<td>&nbsp;<input name="reg_acl" type="text" value="PERMIT:ALL" /></td>
</tr>
<tr>
<td><strong>&nbsp;Subscriber ACSs:</strong></td>
<td>&nbsp;<input name="sub_acl" type="text" value="DENY:1" /></td>
</tr>
<tr>
<td><strong>&nbsp;Timeslot 1 ACLs:</strong></td>
<td>&nbsp;<input name="global_ts1_acl" type="text" value="PERMIT:ALL" /></td>
</tr>
<tr>
<td><strong>&nbsp;Timeslot 2 ACLs:</strong></td>
<td>&nbsp;<input name="global_ts2_acl" type="text" value="PERMIT:ALL" /></td>
</tr>
</tbody>
</table>
<p style="text-align: center;">&nbsp;</p>
<h3 style="text-align: center;"><strong>Reports</strong></h3>
<table style="width: 300px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td><strong>&nbsp;Enable:</strong></td>
<td>&nbsp;<select name="report">
<option selected="selected" value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>
<tr>
<td><strong>&nbsp;Interval:</strong></td>
<td>&nbsp;<input name="report_interval" type="text" value="60" /></td>
</tr>
<tr>
<td><strong>&nbsp;Port:</strong></td>
<td>&nbsp;<input name="report_port" type="text" value="4321" /></td>
</tr>
<tr>
<td><strong>&nbsp;Clients:</strong></td>
<td>&nbsp;<input name="report_clients" type="text" value="127.0.0.1" /></td>
</tr>
</tbody>
</table>
<!--
<p style="text-align: center;">&nbsp;</p>
<h3 style="text-align: center;"><strong>Logger<br /></strong></h3>
<table style="width: 300px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td><strong>&nbsp;File:</strong></td>
<td>&nbsp;<input name="log_file" type="text" value="/tmp/hbnet.log" /></td>
</tr>
<tr>
<td><strong>&nbsp;Log Handler:</strong></td>
<td>&nbsp;<input name="log_hendelers" type="text" value="file" /></td>
</tr>
<tr>
<td><strong>&nbsp;Log Level:</strong></td>
<td>&nbsp;<input name="log_level" type="text" value="DEBUG" /></td>
</tr>
<tr>
<td><strong>&nbsp;Log Name:</strong></td>
<td>&nbsp;<input name="log_name" type="text" value="HBNet" /></td>
</tr>
</tbody>
</table>
-->
<p style="text-align: center;">&nbsp;</p>
<h3 style="text-align: center;"><strong>Aliases<br /></strong></h3>
<table style="width: 300px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td><strong>&nbsp;Download:</strong></td>
<td>&nbsp;<select name="aliases_enabled">
<option selected="selected" value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>
<tr>
<td><strong>&nbsp;Path:</strong></td>
<td>&nbsp;<input name="aliases_path" type="text" value="./" /></td>
</tr>
<tr>
<td><strong>&nbsp;Peer File:</strong></td>
<td>&nbsp;<input name="peer_file" type="text" value="peer_ids.json" /></td>
</tr>
<tr>
<td><strong>&nbsp;Subscriber File:</strong></td>
<td>&nbsp;<input name="sub_file" type="text" value="subscriber_ids.json" /></td>
</tr>
<tr>
<td><strong>&nbsp;Talkgroup ID File:</strong></td>
<td>&nbsp;<input name="tgid_file" type="text" value="talkgroup_ids.json" /></td>
</tr>
<tr>
<td><strong>&nbsp;Peer URL:</strong></td>
<td>&nbsp;<input name="peer_url" type="text" value="https://www.radioid.net/static/rptrs.json" /></td>
</tr>
<tr>
<td><strong>&nbsp;Subscriber URL:</strong></td>
<td>&nbsp;<input name="sub_url" type="text" value="https://www.radioid.net/static/users.json" /></td>
</tr>
<tr>
<td><strong>&nbsp;Stale time(days):</strong></td>
<td>&nbsp;<input name="stale_days" type="text" value="7" /></td>
</tr>
</tbody>
</table>
  <br>
  <p style="text-align: center;">&nbsp;</p>
<h3 style="text-align: center;"><strong>User Manager<br /></strong></h3>
<table style="width: 300px; margin-left: auto; margin-right: auto;" border="1">
<tbody>

</tr>
<tr>
<td style="width: 16.0381%;"><strong>&nbsp;Use short passphrase:</strong></td>
<td style="width: 78.7895%;"><select name="um_shorten_passphrase">
<option selected="selected" value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>
<tr>
<td style="width: 16.0381%;"><strong>&nbsp;Burned IDs File:</strong></td>
<td style="width: 78.7895%;">&nbsp;<input name="um_burn_file" type="text" value="./burned_ids.txt"/></td>
</tr>
</tbody>
</table>
<p style="text-align: center;">&nbsp;</p>
<p style="text-align: center;"><input type="submit" value="Save" /></form></p>
<p style="text-align: center;">&nbsp;</p>
'''
        else:
            all_s = ServerList.query.all()
            p_list = '''
<h3 style="text-align: center;">View/Edit Servers</h3>

<table style="width: 400px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td style="text-align: center;"><strong><a href="manage_servers?add=new">Add Server Config</a></strong></td>
</tr>
</tbody>
</table>
        <p>&nbsp;</p>

<table style="width: 400px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<td style="text-align: center; width: 150px;"><h5><strong>Name</strong><h5></td>
<td style="text-align: center;"><h5><strong>Notes</strong><h5></td>

'''
            for s in all_s:
                try:
                    if time.time() - ping_list[s.name] < 30:
                        svr_status = '''<div class="alert alert-success">
          <strong><strong><a href="manage_servers?edit_server=''' + str(s.name) + '''">''' + str(s.name) + '''</a></strong>
           </div>'''
                    elif time.time() - ping_list[s.name] <= 300:
                        svr_status = '''<div class="alert alert-warning">
          <strong><strong><a href="manage_servers?edit_server=''' + str(s.name) + '''">''' + str(s.name) + '''</a></strong>
           </div>'''
                    elif time.time() - ping_list[s.name] > 300:
                        svr_status = '''<div class="alert alert-danger">
          <strong><strong><a href="manage_servers?edit_server=''' + str(s.name) + '''">''' + str(s.name) + '''</a></strong>
           </div>'''
                    else:
                        svr_status = '''<div class="alert alert-warning">
          <strong><strong><a href="manage_servers?edit_server=''' + str(s.name) + '''">''' + str(s.name) + '''</a></strong>
           </div>'''
                except:
                    svr_status = '''<div class="alert alert-warning">
          <strong><strong><a href="manage_servers?edit_server=''' + str(s.name) + '''">''' + str(s.name) + '''</a></strong>
           </div>'''
                p_list = p_list + '''
<tr>
<td style="text-align: center;">''' + svr_status + '''</td>
<td>''' + s.notes + '''</td>
</tr>\n
'''
            p_list = p_list + '''</tbody></table> '''
            content = p_list
        
        return render_template('flask_user_layout.html', markup_content = Markup(content))
    
    @app.route('/manage_peers', methods=['POST', 'GET'])
    @login_required
    @roles_required('Admin')
    def test_peer_db():
        if request.args.get('save_mode'):
            if request.form.get('enabled') == 'true':
                peer_enabled = True
##            if request.form.get('loose') == 'true':
##                peer_loose = True
            if request.form.get('use_acl') == 'true':
                use_acl = True
            if request.form.get('enable_unit') == 'True':
                unit_enabled = True
##            else:
##                peer_loose = False
            peer_enabled = False
            use_acl = False
            unit_enabled = False
            peer_loose = True
##            print(request.form.get('enable_unit'))
##            print(enable_unit)
            if request.form.get('name_text') == '':
                content = '''<h3 style="text-align: center;">Peer can't have blank name.</h3>
<p style="text-align: center;">Redirecting in 3 seconds.</p>
<meta http-equiv="refresh" content="3; URL=manage_masters" />'''
            else:
                if request.args.get('save_mode') == 'mmdvm_peer':
                    peer_add('mmdvm', request.form.get('name_text'), peer_enabled, peer_loose, request.form.get('ip'), request.form.get('port'), request.form.get('master_ip'), request.form.get('master_port'), request.form.get('passphrase'), request.form.get('callsign'), request.form.get('radio_id'), request.form.get('rx'), request.form.get('tx'), request.form.get('tx_power'), request.form.get('cc'), request.form.get('lat'), request.form.get('lon'), request.form.get('height'), request.form.get('location'), request.form.get('description'), request.form.get('slots'), request.form.get('url'), request.form.get('group_hangtime'), 'MMDVM', request.form.get('options'), use_acl, request.form.get('sub_acl'), request.form.get('tgid_ts1_acl'), request.form.get('tgid_ts2_acl'), request.form.get('server'), unit_enabled, request.form.get('notes'), request.form.get('other_options'))
                    content = '''<h3 style="text-align: center;">MMDVM PEER saved.</h3>
    <p style="text-align: center;">Redirecting in 3 seconds.</p>
    <meta http-equiv="refresh" content="3; URL=manage_peers" />'''
                if request.args.get('save_mode') == 'xlx_peer':
                    peer_add('xlx', request.form.get('name_text'), peer_enabled, peer_loose, request.form.get('ip'), request.form.get('port'), request.form.get('master_ip'), request.form.get('master_port'), request.form.get('passphrase'), request.form.get('callsign'), request.form.get('radio_id'), request.form.get('rx'), request.form.get('tx'), request.form.get('tx_power'), request.form.get('cc'), request.form.get('lat'), request.form.get('lon'), request.form.get('height'), request.form.get('location'), request.form.get('description'), request.form.get('slots'), request.form.get('url'), request.form.get('group_hangtime'), request.form.get('xlxmodule'), request.form.get('options'), use_acl, request.form.get('sub_acl'), request.form.get('tgid_ts1_acl'), request.form.get('tgid_ts2_acl'), request.form.get('server'), unit_enabled, request.form.get('notes'), request.form.get('other_options'))
                    content = '''<h3 style="text-align: center;">XLX PEER saved.</h3>
    <p style="text-align: center;">Redirecting in 3 seconds.</p>
    <meta http-equiv="refresh" content="3; URL=manage_peers" />'''
        elif request.args.get('add') == 'mmdvm' or request.args.get('add') == 'xlx':
            s = ServerList.query.all()
            if request.args.get('add') == 'mmdvm':
                mode = 'MMDVM'
                submit_link = 'manage_peers?save_mode=mmdvm_peer'
                xlx_module = ''
            if request.args.get('add') == 'xlx':
                xlx_module = '''
<tr>
<td style="width: 175.567px;"><strong>&nbsp;XLX Module:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="xlxmodule" type="text" value="" /></td>
</tr>
'''
                mode = 'XLX'
                submit_link = 'manage_peers?save_mode=xlx_peer'
            server_options = ''
            for i in s:
                server_options = server_options + '''<option value="''' + i.name + '''">''' + i.name + '''</option>\n'''
            content = '''
<p>&nbsp;</p>
<h2 style="text-align: center;"><strong>Add an ''' + mode + ''' peer</strong></h2>

<p style="text-align: center;"><strong>Notice:</strong> Before connecting this server to another network, such as Brandmeister, <strong>be sure you have permission</strong>. <br />Connecting servers together via PEER connection can cause problems such as audio looping. <br />OpenBridge connections are designed for server to server connections.</p>
<p>&nbsp;</p>

<form action="''' + submit_link + '''" method="post">
<table style="width: 600px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td style="width: 175.567px;"><strong>Assign to Server:</strong></td>
<td style="width: 399.433px;">&nbsp;<select name="server">
''' + server_options + '''
</select></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>Connection Name:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="name_text" type="text" value="" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Active:</strong></td>
<td style="width: 399.433px;">&nbsp;<select name="enabled">
<option value="true">True</option>
<option value="false">False</option>
</select></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;IP:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="ip" type="text" value="" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Port:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="port" type="text" value="54001" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Passphrase:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="passphrase" type="text" value="passw0rd" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Master IP:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="master_ip" type="text" value="IP.OF.MASTER.SERVER" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Master Port:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="master_port" type="text" value="54000" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Callsign:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="callsign" type="text" value="" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Radio ID:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="radio_id" type="text" value="123456789" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Transmit Frequency:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="tx" type="text" value="449000000" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Receive Frequency:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="rx" type="text" value="449000000" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Transmit Power:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="tx_power" type="text" value="25" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Color Code:</strong></td>
<td style="width: 399.433px;">&nbsp;<select name="cc">
<option value="0">0</option>
<option value="1">1</option>
<option value="2">2</option>
<option value="3">3</option>
<option value="4">4</option>
<option value="5">5</option>
<option value="6">6</option>
<option value="7">7</option>
<option value="8">8</option>
<option value="9">9</option>
<option value="10">10</option>
<option value="11">11</option>
<option value="12">12</option>
<option value="13">13</option>
<option value="14">14</option>
<option value="15">15</option>
</select></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Slots:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="slots" type="text" value="1" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Latitude:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="lat" type="text" value="38.0000" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Longitude:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="lon" type="text" value="-095.0000" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Height</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="height" type="text" value="50" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Location:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="location" type="text" value="Anywhere, USA" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Description:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="description" type="text" value="This is a cool repeater" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;URL:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="url" type="text" value="www.w1abc.org" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Group Hangtime:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="group_hangtime" type="text" value="5" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Options:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="options" type="text" value="" /></td>
</tr>
''' + xlx_module + '''
<tr>
<td><strong>&nbsp;Enable Unit Calls:</strong></td>
<td>&nbsp;<select name="enable_unit">
<option value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Use ACLs:</strong></td>
<td style="width: 399.433px;">&nbsp;<select name="use_acl">
<option selected="selected" value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Subscriber ACLs:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="sub_acl" type="text" value="DENY:1" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Talkgroup Slot 1 ACLs:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="tgid_ts1_acl" type="text" value="PERMIT:ALL" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Talkgroup Slot 2 ACLs:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="tgid_ts2_acl" type="text" value="PERMIT:ALL" /></td>
</tr>

<tr>
<td><strong>&nbsp;Misc Options:</strong></td>
<td>&nbsp;<textarea id="other_options" cols="50" name="other_options" rows="4"></textarea></td>
</tr>

<tr>
<td><strong>&nbsp;Notes:</strong></td>
<td>&nbsp;<textarea id="notes" cols="50" name="notes" rows="4"></textarea></td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<p style="text-align: center;"><input type="submit" value="Save" /></p></form>
'''

##        elif request.args.get('edit_server') and request.args.get('edit_peer') and request.args.get('mode') == 'mmdvm':
        elif request.args.get('delete_peer') and request.args.get('peer_server'):
            peer_delete(request.args.get('mode'), request.args.get('peer_server'), request.args.get('delete_peer'))
            content = '''<h3 style="text-align: center;">PEER deleted.</h3>
<p style="text-align: center;">Redirecting in 3 seconds.</p>
<meta http-equiv="refresh" content="3; URL=manage_peers" />'''
        elif request.args.get('edit_mmdvm') == 'save' or request.args.get('edit_xlx') == 'save':
            peer_enabled = False
            use_acl = False
            peer_loose = True
            unit_enabled = False
            if request.form.get('enabled') == 'true':
                peer_enabled = True
##            if request.form.get('loose') == 'true':
##                peer_loose = True
            if request.form.get('use_acl') == 'True':
                use_acl = True
            if request.form.get('enable_unit') == 'True':
                unit_enabled = True
##            else:
##                peer_loose = False
##            print((unit_enabled))
##            print(type(peer_enabled))
##            print(type(use_acl))
            if request.args.get('edit_mmdvm') == 'save':
                peer_edit('mmdvm', request.args.get('server'), request.args.get('name'), peer_enabled, peer_loose, request.form.get('ip'), request.form.get('port'), request.form.get('master_ip'), request.form.get('master_port'), request.form.get('passphrase'), request.form.get('callsign'), request.form.get('radio_id'), request.form.get('rx'), request.form.get('tx'), request.form.get('tx_power'), request.form.get('cc'), request.form.get('lat'), request.form.get('lon'), request.form.get('height'), request.form.get('location'), request.form.get('description'), request.form.get('slots'), request.form.get('url'), request.form.get('group_hangtime'), 'MMDVM', request.form.get('options'), use_acl, request.form.get('sub_acl'), request.form.get('tgid_ts1_acl'), request.form.get('tgid_ts2_acl'), unit_enabled, request.form.get('notes'), request.form.get('other_options'))
                content = '''<h3 style="text-align: center;">MMDVM PEER changed.</h3>
<p style="text-align: center;">Redirecting in 3 seconds.</p>
<meta http-equiv="refresh" content="3; URL=manage_peers" />'''
            if request.args.get('edit_xlx') == 'save':
                peer_edit('xlx', request.args.get('server'), request.args.get('name'), peer_enabled, peer_loose, request.form.get('ip'), request.form.get('port'), request.form.get('master_ip'), request.form.get('master_port'), request.form.get('passphrase'), request.form.get('callsign'), request.form.get('radio_id'), request.form.get('rx'), request.form.get('tx'), request.form.get('tx_power'), request.form.get('cc'), request.form.get('lat'), request.form.get('lon'), request.form.get('height'), request.form.get('location'), request.form.get('description'), request.form.get('slots'), request.form.get('url'), request.form.get('group_hangtime'), request.form.get('xlxmodule'),  request.form.get('options'), use_acl, request.form.get('sub_acl'), request.form.get('tgid_ts1_acl'), request.form.get('tgid_ts2_acl'), unit_enabled, request.form.get('notes'), request.form.get('other_options'))
                content = '''<h3 style="text-align: center;">XLX PEER changed.</h3>
<p style="text-align: center;">Redirecting in 3 seconds.</p>
<meta http-equiv="refresh" content="3; URL=manage_peers" />'''
        elif request.args.get('server') and request.args.get('peer_name') and request.args.get('mode'): # and request.args.get('edit_peer') and request.args.get('mode') == 'mmdvm':
            if request.args.get('mode') == 'mmdvm':
                p = mmdvmPeer.query.filter_by(server=request.args.get('server')).filter_by(name=request.args.get('peer_name')).first()
                xlx_module = ''
                mode = "MMDVM"
                form_submit = '''<form action="manage_peers?edit_mmdvm=save&server=''' + str(p.server) + '''&name=''' + str(p.name) + '''" method="post">'''
            if request.args.get('mode') == 'xlx':
                p = xlxPeer.query.filter_by(server=request.args.get('server')).filter_by(name=request.args.get('peer_name')).first()
                form_submit = '''<form action="manage_peers?edit_xlx=save&server=''' + str(p.server) + '''&name=''' + str(p.name) + '''" method="post">'''
                xlx_module = '''
<tr>
<td style="width: 175.567px;"><strong>&nbsp;XLX Module:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="xlxmodule" type="text" value="''' + str(p.xlxmodule) + '''" /></td>
</tr>
'''
                mode = "XLX"
            
            content = '''
<p>&nbsp;</p>
<h2 style="text-align: center;"><strong>View/Edit an ''' + mode + ''' peer</strong></h2>

<p style="text-align: center;"><strong><a href="manage_peers?peer_server=''' + str(p.server) + '''&delete_peer=''' + str(p.name) + '''&mode=''' + request.args.get('mode') + '''">Delete peer</a></strong></p>

''' + form_submit + '''
<table style="width: 600px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td style="width: 175.567px;"><strong>Connection Name: </strong></td>
<td style="width: 399.433px;">&nbsp;''' + str(p.name) + '''</td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Active:</strong></td>
<td style="width: 399.433px;">&nbsp;<select name="enabled">
<option value="''' + str(p.enabled) + '''" selected>Current: ''' + str(p.enabled) + '''</option>
<option value="true">True</option>
<option value="false">False</option>
</select></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;IP:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="ip" type="text" value="''' + str(p.ip) + '''" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Port:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="port" type="text" value="''' + str(p.port) + '''" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Passphrase:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="passphrase" type="text" value="''' + str(p.passphrase) + '''" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Master IP:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="master_ip" type="text" value="''' + str(p.master_ip) + '''" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Master Port:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="master_port" type="text" value="''' + str(p.master_port) + '''" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Callsign:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="callsign" type="text" value="''' + str(p.callsign) + '''" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Radio ID:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="radio_id" type="text" value="''' + str(p.radio_id) + '''" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Transmit Frequency:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="tx" type="text" value="''' + str(p.tx_freq) + '''" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Receive Frequency:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="rx" type="text" value="''' + str(p.rx_freq) + '''" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Transmit Power:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="tx_power" type="text" value="''' + str(p.tx_power) + '''" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Color Code:</strong></td>
<td style="width: 399.433px;">&nbsp;<select name="cc">
<option value="''' + str(p.color_code) + '''" selected>Current: ''' + str(p.color_code) + '''</option>
<option value="0">0</option>
<option value="1">1</option>
<option value="2">2</option>
<option value="3">3</option>
<option value="4">4</option>
<option value="5">5</option>
<option value="6">6</option>
<option value="7">7</option>
<option value="8">8</option>
<option value="9">9</option>
<option value="10">10</option>
<option value="11">11</option>
<option value="12">12</option>
<option value="13">13</option>
<option value="14">14</option>
<option value="15">15</option>
</select></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Slots:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="slots" type="text" value="''' + str(p.slots) + '''" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Latitude:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="lat" type="text" value="''' + str(p.latitude) + '''" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Longitude:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="lon" type="text" value="''' + str(p.longitude) + '''" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Height</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="height" type="text" value="''' + str(p.height) + '''" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Location:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="location" type="text" value="''' + str(p.location) + '''" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Description:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="description" type="text" value="''' + str(p.description) + '''" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;URL:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="url" type="text" value="''' + str(p.url) + '''" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Group Call Hangtime:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="group_hangtime" type="text" value="''' + str(p.group_hangtime) + '''" /></td>
</tr>
''' + xlx_module + '''
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Options:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="options" type="text" value="''' + str(p.options) + '''" /></td>
</tr>
<tr>
<td><strong>&nbsp;Enable Unit Calls:</strong></td>
<td>&nbsp;<select name="enable_unit">
<option selected="selected" value="''' + str(p.enable_unit) + '''">Current: ''' + str(p.enable_unit) + '''</option>
<option value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Use ACLs:</strong></td>
<td style="width: 399.433px;">&nbsp;<select name="use_acl">
<option selected="selected" value="''' + str(p.use_acl) + '''">Current: ''' + str(p.use_acl) + '''</option>
<option value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Subscriber ACLs:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="sub_acl" type="text" value="''' + str(p.sub_acl) + '''" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Talkgroup Slot 1 ACLs:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="tgid_ts1_acl" type="text" value="''' + str(p.tg1_acl) + '''" /></td>
</tr>
<tr>
<td style="width: 175.567px;"><strong>&nbsp;Talkgroup Slot 2 ACLs:</strong></td>
<td style="width: 399.433px;">&nbsp;<input name="tgid_ts2_acl" type="text" value="''' + str(p.tg2_acl) + '''" /></td>
</tr>

<tr>
<td><strong>&nbsp;Misc Options:</strong></td>
<td>&nbsp;<textarea id="other_options" cols="50" name="other_options" rows="4">''' + str(p.other_options) + '''</textarea></td>
</tr>

<tr>
<td><strong>&nbsp;Notes:</strong></td>
<td>&nbsp;<textarea id="notes" cols="50" name="notes" rows="4">''' + str(p.notes) + '''</textarea></td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<p style="text-align: center;"><input type="submit" value="Save" /></p></form>

<p>&nbsp;</p>
'''
        else:
            all_s = ServerList.query.all()
            p_list = ''
            for s in all_s:
                # print(s.name)
                p_list = p_list + '''
<h4 style="text-align: center;">Server: ''' + str(s.name) + '''</h4>
<table style="width: 400px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td style="text-align: center;"><strong>Name</strong></td>
<td style="text-align: center;"><strong>Mode</strong></td>
<td style="text-align: center;"><strong>Notes</strong></td>

</tr>\n
'''
                all_p = mmdvmPeer.query.filter_by(server=s.name).all()
                all_x = xlxPeer.query.filter_by(server=s.name).all()
                for p in all_p:
                    p_list = p_list + '''
<tr>
<td><a href="manage_peers?server=''' + str(s.name) + '''&amp;peer_name=''' + str(p.name) + '''&mode=mmdvm">''' + str(p.name) + '''</a></td>
<td>MMDVM</td>
<td>''' + p.notes + '''</td>

</tr>
'''
                for x in all_x:
                    p_list = p_list + '''
<tr>
<td><a href="manage_peers?server=''' + str(x.server) + '''&amp;peer_name=''' + str(x.name) + '''&mode=xlx">''' + str(x.name) + '''</a></td>
<td>XLX</td>
<td>''' + x.notes + '''</td>

</tr>
'''
                p_list = p_list + ''' </tbody></table>\n'''
            content = '''

<h3 style="text-align: center;">View/Edit Peers</h3>

<table style="width: 400px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td style="text-align: center;"><strong><a href="manage_peers?add=mmdvm">Add MMDVM peer</a></strong></td>
<td style="text-align: center;"><strong><a href="manage_peers?add=xlx">Add XLX peer</a></strong></td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>

''' + p_list

        return render_template('flask_user_layout.html', markup_content = Markup(content))

    
    @app.route('/manage_masters', methods=['POST', 'GET'])
    @login_required
    @roles_required('Admin')
    def manage_masters():
        #PROXY
        if request.args.get('proxy_save'):
            active = False
            use_acl = False
            enable_unit = False
            repeat = True
            aprs_pos = False
            enable_um = True
            external_proxy = False
            public = False
            if request.form.get('enable_um') == 'False':
                enable_um = False
            if request.form.get('aprs_pos') == 'True':
                aprs_pos = True
            if request.form.get('enabled') == 'True':
                active = True
            if request.form.get('use_acl') == 'True':
                use_acl = True
            if request.form.get('enable_unit') == 'True':
                enable_unit = True
            if request.form.get('repeat') == 'False':
                repeat = False
            if request.form.get('external_proxy') == 'True':
                external_proxy = True
            if request.form.get('public_list') == 'True':
                public = True
            if request.args.get('proxy_save') == 'add':
                if request.form.get('name_text') == '':
                    content = '''<h3 style="text-align: center;">PROXY can't have blank name.</h3>
<p style="text-align: center;">Redirecting in 3 seconds.</p>
<meta http-equiv="refresh" content="3; URL=manage_masters" />'''
                else:
                    add_master('PROXY', request.form.get('name_text'), request.form.get('server'), aprs_pos, repeat, active, 0, request.form.get('ip'), request.form.get('external_port'), enable_um, request.form.get('passphrase'), request.form.get('group_hangtime'), use_acl, request.form.get('reg_acl'), request.form.get('sub_acl'), request.form.get('ts1_acl'), request.form.get('ts2_acl'), enable_unit, request.form.get('notes'), external_proxy, request.form.get('int_port_start'), request.form.get('int_port_stop'), '', '', '', '', public, request.form.get('other_options'), '', '')
                    content = '''<h3 style="text-align: center;">PROXY saved.</h3>
    <p style="text-align: center;">Redirecting in 3 seconds.</p>
    <meta http-equiv="refresh" content="3; URL=manage_masters" />'''
            elif request.args.get('proxy_save') == 'edit':
##                print(request.args.get('name'))
                edit_master('PROXY', request.args.get('name'), request.args.get('server'), aprs_pos, repeat, active, 0, request.form.get('ip'), request.form.get('external_port'), enable_um, request.form.get('passphrase'), request.form.get('group_hangtime'), use_acl, request.form.get('reg_acl'), request.form.get('sub_acl'), request.form.get('ts1_acl'), request.form.get('ts2_acl'), enable_unit, request.form.get('notes'), external_proxy, request.form.get('int_port_start'), request.form.get('int_port_stop'), '', '', '', '', public, request.form.get('other_options'), '', '')
                content = '''<h3 style="text-align: center;">PROXY changed.</h3>
<p style="text-align: center;">Redirecting in 3 seconds.</p>
<meta http-equiv="refresh" content="3; URL=manage_masters" />'''
            elif request.args.get('proxy_save') == 'delete':
                master_delete('PROXY', request.args.get('server'), request.args.get('name'))
                content = '''<h3 style="text-align: center;">PROXY deleted.</h3>
<p style="text-align: center;">Redirecting in 3 seconds.</p>
<meta http-equiv="refresh" content="3; URL=manage_masters" />'''
        # OBP
        elif request.args.get('OBP_save'):
            enabled = False
            use_acl = False
            enable_unit = False
            both_slots = True
            obp_encryption = False
            if request.form.get('obp_encryption') == 'True':
                obp_encryption = True
            if request.form.get('enabled') == 'True':
                enabled = True
            if request.form.get('use_acl') == 'True':
                use_acl = True
            if request.form.get('enable_unit') == 'True':
                enable_unit = True
            if request.form.get('both_slots') == 'False':
                both_slots = False
            if request.args.get('OBP_save') == 'add':
                if request.form.get('name_text') == '':
                    content = '''<h3 style="text-align: center;">OpenBridge connection can't have blank name.</h3>
<p style="text-align: center;">Redirecting in 3 seconds.</p>
<meta http-equiv="refresh" content="3; URL=manage_masters" />'''
                else:
                    add_master('OBP', request.form.get('name_text'), request.form.get('server'), '', '', enabled, request.form.get('max_peers'), request.form.get('ip'), request.form.get('port'), '', request.form.get('passphrase'), request.form.get('group_hangtime'), use_acl, request.form.get('reg_acl'), request.form.get('sub_acl'), request.form.get('tg_acl'), '', enable_unit, request.form.get('notes'), '', '', '', request.form.get('network_id'), request.form.get('target_ip'), request.form.get('target_port'), both_slots, '', request.form.get('other_options'), request.form.get('encryption_key'), obp_encryption)
                    content = '''<h3 style="text-align: center;">OpenBridge connection saved.</h3>
    <p style="text-align: center;">Redirecting in 3 seconds.</p>
    <meta http-equiv="refresh" content="3; URL=manage_masters" />'''
            elif request.args.get('OBP_save') == 'edit':
                edit_master('OBP', request.args.get('name'), request.args.get('server'), '', '', enabled, request.form.get('max_peers'), request.form.get('ip'), request.form.get('port'), '', request.form.get('passphrase'), request.form.get('group_hangtime'), use_acl, request.form.get('reg_acl'), request.form.get('sub_acl'), request.form.get('tg_acl'), '', enable_unit, request.form.get('notes'), '', '', '', request.form.get('network_id'), request.form.get('target_ip'), request.form.get('target_port'), both_slots, '', request.form.get('other_options'), request.form.get('encryption_key'), obp_encryption)
                content = '''<h3 style="text-align: center;">OpenBridge connection changed.</h3>
<p style="text-align: center;">Redirecting in 3 seconds.</p>
<meta http-equiv="refresh" content="3; URL=manage_masters" />'''
            elif request.args.get('OBP_save') == 'delete':
                master_delete('OBP', request.args.get('server'), request.args.get('name'))
                content = '''<h3 style="text-align: center;">OpenBridge connection deleted.</h3>
<p style="text-align: center;">Redirecting in 3 seconds.</p>
<meta http-equiv="refresh" content="3; URL=manage_masters" />'''
        # MASTER
        elif request.args.get('master_save'):
            aprs_pos = False
            repeat = False
            active = False
            use_acl = False
            enable_um = False
            enable_unit = False
            public = False
            if request.form.get('aprs_pos') == 'True':
                aprs_pos = True
            if request.form.get('repeat') == 'True':
                repeat = True
            if request.form.get('enabled') == 'True':
                active = True
            if request.form.get('use_acl') == 'True':
                use_acl = True
            if request.form.get('enable_um') == 'True':
                enable_um = True
            if request.form.get('enable_unit') == 'True':
                enable_unit = True
            if request.form.get('public_list') == 'True':
                public = True
            if request.args.get('master_save') == 'add':
                if request.form.get('name_text') == '':
                    content = '''<h3 style="text-align: center;">MASTER can't have blank name.</h3>
<p style="text-align: center;">Redirecting in 3 seconds.</p>
<meta http-equiv="refresh" content="3; URL=manage_masters" />'''
                else:
                    add_master('MASTER', request.form.get('name_text'), request.form.get('server'), aprs_pos, repeat, active, request.form.get('max_peers'), request.form.get('ip'), request.form.get('port'), enable_um, request.form.get('passphrase'), request.form.get('group_hangtime'), use_acl, request.form.get('reg_acl'), request.form.get('sub_acl'), request.form.get('ts1_acl'), request.form.get('ts2_acl'), enable_unit, request.form.get('notes'), '', '', '', '', '', '', '', public, request.form.get('other_options'), '', '')
                    content = '''<h3 style="text-align: center;">MASTER saved.</h3>
    <p style="text-align: center;">Redirecting in 3 seconds.</p>
    <meta http-equiv="refresh" content="3; URL=manage_masters" />'''
            elif request.args.get('master_save') == 'edit':
                edit_master('MASTER', request.args.get('name'), request.args.get('server'), aprs_pos, repeat, active, request.form.get('max_peers'), request.form.get('ip'), request.form.get('port'), enable_um, request.form.get('passphrase'), request.form.get('group_hangtime'), use_acl, request.form.get('reg_acl'), request.form.get('sub_acl'), request.form.get('ts1_acl'), request.form.get('ts2_acl'), enable_unit, request.form.get('notes'), '', '', '', '', '', '', '', public, request.form.get('other_options'), '', '')
                content = '''<h3 style="text-align: center;">MASTER changed.</h3>
<p style="text-align: center;">Redirecting in 3 seconds.</p>
<meta http-equiv="refresh" content="3; URL=manage_masters" /> '''
            elif request.args.get('master_save') == 'delete':
                master_delete('MASTER', request.args.get('server'), request.args.get('name'))
                content = '''<h3 style="text-align: center;">MASTER deleted.</h3>
<p style="text-align: center;">Redirecting in 3 seconds.</p>
<meta http-equiv="refresh" content="3; URL=manage_masters" />'''
        elif request.args.get('add_OBP'):
            s = ServerList.query.all()
            server_options = ''
            for i in s:
                server_options = server_options + '''<option value="''' + i.name + '''">''' + i.name + '''</option>\n'''
            content = '''
<p>&nbsp;</p>

<h2 style="text-align: center;"><strong>Add an OpenBridge Connection</strong></h2>
<p>&nbsp;</p>

<form action="manage_masters?OBP_save=add" method="post">
<table style="width: 600px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td><strong>&nbsp;Name:</strong></td>
<td>&nbsp;<input name="name_text" type="text" value="" /></td>
</tr>
<tr>
<td style="width: 175.567px;">&nbsp;<strong>Assign to Server:</strong></td>
<td style="width: 399.433px;">&nbsp;<select name="server">''' + server_options + '''</select></td>
</tr>
<tr>
<td><strong>&nbsp;Active:</strong></td>
<td>&nbsp;<select name="enabled">
<option value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>
<tr>
<td><strong>&nbsp;IP:</strong></td>
<td>&nbsp;<input name="ip" type="text" value="" /></td>
</tr>
<tr>
<td><strong>&nbsp;Port:</strong></td>
<td>&nbsp;<input name="port" type="text" value="62035" /></td>
</tr>
<tr>
<td><strong>&nbsp;Passphrase:</strong></td>
<td>&nbsp;<input name="passphrase" type="text" value="passw0rd" /></td>
</tr>
<tr>
<td><strong>&nbsp;Network ID:</strong></td>
<td>&nbsp;<input name="network_id" type="text" value="123456789" /></td>
</tr>
<tr>
<td><strong>&nbsp;Target IP:</strong></td>
<td>&nbsp;<input name="target_ip" type="text" value="1.2.3.4" /></td>
</tr>
<tr>
<td><strong>&nbsp;Target Port:</strong></td>
<td>&nbsp;<input name="target_port" type="text" value="62035" /></td>
</tr>
<tr>
<td><strong>&nbsp;Use ACLs:</strong></td>
<td>&nbsp;<select name="use_acl">
<option selected="selected" value="True">Current - True</option>
<option value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>
<tr>
<td><strong>&nbsp;Subscriber ACLs:</strong></td>
<td>&nbsp;<input name="sub_acl" type="text" value="DENY:1" /></td>
</tr>
<tr>
<td><strong>&nbsp;Talkgroup ACLs:</strong></td>
<td>&nbsp;<input name="tg_acl" type="text" value="PERMIT:ALL" /></td>
</tr>
<tr>
<td><strong>&nbsp;Use Both Slots:</strong></td>
<td>&nbsp;<select name="both_slots">
<option selected="selected" value="False">Current - False</option>
<option value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>
<tr>
<td><strong>&nbsp;Enable Unit Calls:</strong></td>
<td>&nbsp;<select name="enable_unit">
<option value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>

<tr>
<td><strong>&nbsp;Use Encryption:</strong></td>
<td>&nbsp;<select name="obp_encryption">
<option selected="selected" value="False">Current - False</option>
<option value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>

<td><strong>&nbsp;Encryption_key:</strong></td>
<td>&nbsp;<input name="encryption_key" type="text" value="" /></td>
</tr>

<tr>
<td><strong>&nbsp;Misc Options:</strong></td>
<td>&nbsp;<textarea id="other_options" cols="50" name="other_options" rows="4"></textarea></td>
</tr>

<tr>
<td><strong>&nbsp;Notes:</strong></td>
<td>&nbsp;<textarea id="notes" cols="50" name="notes" rows="4"></textarea></td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<p style="text-align: center;"><input type="submit" value="Save" /></form></p>
<p>&nbsp;</p>

'''
        elif request.args.get('edit_proxy'):
            # print(request.args.get('server'))
            # print(request.args.get('edit_proxy'))
            p = ProxyList.query.filter_by(server=request.args.get('server')).filter_by(name=request.args.get('edit_proxy')).first()
            content = '''
<p>&nbsp;</p>

    <h2 style="text-align: center;"><strong>View/Edit Proxy</strong></h2>

   <p style="text-align: center;"><strong><a href="manage_masters?proxy_save=delete&server=''' + str(p.server) + '''&name=''' + str(p.name) + '''">Delete Proxy</a></strong></p>


<form action="manage_masters?proxy_save=edit&name=''' + str(p.name) + '''&server=''' + str(p.server) + '''" method="post">
<table style="width: 600px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td style="width: 189.383px;"><strong>&nbsp;Name:</strong></td>
<td style="width: 392.617px;">&nbsp;''' + str(p.name) + '''</td>
</tr>
<tr>
<td style="width: 189.383px;"><strong>&nbsp;Active:</strong></td>
<td style="width: 392.617px;">&nbsp;<select name="enabled">
<option selected="selected" value="''' + str(p.active) + '''">Current - ''' + str(p.active) + '''</option>
<option value="False">False</option>
<option value="True">True</option>

</select></td>
</tr>
<tr>
<td style="width: 189.383px;"><strong>&nbsp;Repeat:</strong></td>
<td style="width: 392.617px;">&nbsp;<select name="repeat">
<option selected="selected" value="''' + str(p.repeat) + '''">Current - ''' + str(p.repeat) + '''</option>
<option value="False">False</option>
<option value="True">True</option>

</select></td>
</tr>
<tr>
<td style="width: 189.383px;"><strong>&nbsp;External Proxy Script:</strong></td>
<td style="width: 392.617px;">&nbsp;<select name="external_proxy">
<option  value="True">True</option>
<option value="False">False</option>
<option selected="selected" value="''' + str(p.external_proxy) + '''">''' + str(p.external_proxy) + '''</option>
</select></td>
</tr>
<tr>
<td style="width: 189.383px;"><strong>&nbsp;Static APRS positions:</strong></td>
<td style="width: 392.617px;">&nbsp;<select name="aprs_pos">
<option selected="selected" value="''' + str(p.static_positions) + '''">Current - ''' + str(p.static_positions) + '''</option>
<option value="True">True</option>
<option value="False">False</option>

</select></td>
</tr>
<tr>
<td style="width: 189.383px;"><strong>&nbsp;User Manager for login:</strong></td>
<td style="width: 392.617px;">&nbsp;<select name="enable_um">
<option selected="selected" value="''' + str(p.enable_um) + '''">Current - ''' + str(p.enable_um) + '''</option>
<option value="False">False</option>
<option value="True">True</option>

</select></td>
</tr>

<tr>
<td style="width: 189.383px;"><strong>&nbsp;External Port:</strong></td>
<td style="width: 392.617px;">&nbsp;<input name="external_port" type="text" value="''' + str(p.external_port) + '''" /></td>
</tr>
  <tr>
<td style="width: 189.383px;"><strong>&nbsp;Internal Port Start:</strong></td>
<td style="width: 392.617px;">&nbsp;<input name="int_port_start" type="text" value="''' + str(p.internal_start_port) + '''" /></td>
</tr>
    <tr>
<td style="width: 189.383px;"><strong>&nbsp;Internal Port Stop:</strong></td>
<td style="width: 392.617px;">&nbsp;<input name="int_port_stop" type="text" value="''' + str(p.internal_stop_port) + '''" /></td>
</tr>
<tr>
<td style="width: 189.383px;"><strong>&nbsp;Passphrase:</strong></td>
<td style="width: 392.617px;">&nbsp;<input name="passphrase" type="text" value="''' + str(p.passphrase) + '''" /></td>
</tr>
<tr>
<td style="width: 189.383px;"><strong>&nbsp;Group Hangtime:</strong></td>
<td style="width: 392.617px;">&nbsp;<input name="group_hangtime" type="text" value="''' + str(p.group_hang_time) + '''" /></td>
</tr>
<tr>
<td style="width: 189.383px;"><strong>&nbsp;Use ACLs:</strong></td>
<td style="width: 392.617px;">&nbsp;<select name="use_acl">
<option value="''' + str(p.use_acl) + '''">Current - ''' + str(p.use_acl) + '''</option>
<option value="False">False</option>
</select></td>
</tr>
<tr>
<td style="width: 189.383px;"><strong>&nbsp;Register ACLs:</strong></td>
<td style="width: 392.617px;">&nbsp;<input name="reg_acl" type="text" value="''' + str(p.reg_acl) + '''" /></td>
</tr>
<tr>
<td style="width: 189.383px;"><strong>&nbsp;Subscriber ACLs:</strong></td>
<td style="width: 392.617px;">&nbsp;<input name="sub_acl" type="text" value="''' + str(p.sub_acl) + '''" /></td>
</tr>
<tr>
<td style="width: 189.383px;"><strong>&nbsp;Talkgroup Slot 1 ACLs:</strong></td>
<td style="width: 392.617px;">&nbsp;<input name="ts1_acl" type="text" value="''' + str(p.tg1_acl) + '''" /></td>
</tr>
<tr>
<td style="width: 189.383px;"><strong>&nbsp;Talkgroup Slot 2 ACLs:</strong></td>
<td style="width: 392.617px;">&nbsp;<input name="ts2_acl" type="text" value="''' + str(p.tg2_acl) + '''" /></td>
</tr>
<tr>
<td style="width: 189.383px;"><strong>&nbsp;Enable Unit Calls:</strong></td>
<td style="width: 392.617px;">&nbsp;<select name="enable_unit">
<option value="''' + str(p.enable_unit) + '''">Current - ''' + str(p.enable_unit) + '''</option>
<option value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>
<tr>
<td><strong>&nbsp;Public List:</strong></td>
<td>&nbsp;<select name="public_list">
<option selected="selected" value="''' + str(p.public_list) + '''">Current - ''' + str(p.public_list) + '''</option>
<option value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>

<tr>
<td><strong>&nbsp;Misc Options:</strong></td>
<td>&nbsp;<textarea id="other_options" cols="50" name="other_options" rows="4">''' + str(p.other_options) + '''</textarea></td>
</tr>

<tr>
<td style="width: 189.383px;"><strong>&nbsp;Notes:</strong></td>
<td style="width: 392.617px;">&nbsp;<textarea id="notes" cols="50" name="notes" rows="4">''' + str(p.notes) + '''</textarea></td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<input type="submit" value="Save" /></form>
<p>&nbsp;</p>
'''
            
        elif request.args.get('add_proxy'):
            s = ServerList.query.all()
            server_options = ''
            for i in s:
                server_options = server_options + '''<option value="''' + i.name + '''">''' + i.name + '''</option>\n'''
            content = '''
<p>&nbsp;</p>

<h2 style="text-align: center;"><strong>Add a PROXY</strong></h2>
<p>&nbsp;</p>

<form action="manage_masters?proxy_save=add" method="post">
<table style="width: 600px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td style="width: 189.383px;"><strong>Assign to Server:</strong></td>
<td style="width: 392.617px;">&nbsp;<select name="server">''' + server_options + '''</select></td>
</tr>
<tr>
<td style="width: 189.383px;"><strong>&nbsp;Name:</strong></td>
<td style="width: 392.617px;">&nbsp;<input name="name_text" type="text" value="" /></td>
</tr>
<tr>
<td style="width: 189.383px;"><strong>&nbsp;Active:</strong></td>
<td style="width: 392.617px;">&nbsp;<select name="enabled">
<option selected="selected" value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>
<tr>
<td style="width: 189.383px;"><strong>&nbsp;Repeat:</strong></td>
<td style="width: 392.617px;">&nbsp;<select name="repeat">
<option selected="selected" value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>
<tr>
<td style="width: 189.383px;"><strong>&nbsp;External Proxy Script:</strong></td>
<td style="width: 392.617px;">&nbsp;<select name="external_proxy">
<option  value="True">True</option>
<option selected="selected" value="False">False</option>
</select></td>
</tr>
<tr>
<td style="width: 189.383px;"><strong>&nbsp;Static APRS positions:</strong></td>
<td style="width: 392.617px;">&nbsp;<select name="aprs_pos">
<option selected="selected" value="False">False</option>
<option value="True">True</option>
</select></td>
</tr>
<tr>
<td style="width: 189.383px;"><strong>&nbsp;User Manager for login:</strong></td>
<td style="width: 392.617px;">&nbsp;<select name="enable_um">
<option selected="selected" value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>
<tr>
<td style="width: 189.383px;"><strong>&nbsp;IP:</strong></td>
<td style="width: 392.617px;">&nbsp;<input name="ip" type="text" value="" /></td>
</tr>
<tr>
<td style="width: 189.383px;"><strong>&nbsp;External Port:</strong></td>
<td style="width: 392.617px;">&nbsp;<input name="external_port" type="text" value="62032" /></td>
</tr>
  <tr>
<td style="width: 189.383px;"><strong>&nbsp;Internal Port Start (lower than stop port):</strong></td>
<td style="width: 392.617px;">&nbsp;<input name="int_port_start" type="text" value="53000" /></td>
</tr>
    <tr>
<td style="width: 189.383px;"><strong>&nbsp;Internal Port Stop:</strong></td>
<td style="width: 392.617px;">&nbsp;<input name="int_port_stop" type="text" value="53010" /></td>
</tr>
<tr>
<td style="width: 189.383px;"><strong>&nbsp;Passphrase:</strong></td>
<td style="width: 392.617px;">&nbsp;<input name="passphrase" type="text" value="passw0rd" /></td>
</tr>
<tr>
<td style="width: 189.383px;"><strong>&nbsp;Group Hangtime:</strong></td>
<td style="width: 392.617px;">&nbsp;<input name="group_hangtime" type="text" value="5" /></td>
</tr>
<tr>
<td style="width: 189.383px;"><strong>&nbsp;Use ACLs:</strong></td>
<td style="width: 392.617px;">&nbsp;<select name="use_acl">
<option value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>
<tr>
<td style="width: 189.383px;"><strong>&nbsp;Register ACLs:</strong></td>
<td style="width: 392.617px;">&nbsp;<input name="reg_acl" type="text" value="DENY:1" /></td>
</tr>
<tr>
<td style="width: 189.383px;"><strong>&nbsp;Subscriber ACLs:</strong></td>
<td style="width: 392.617px;">&nbsp;<input name="sub_acl" type="text" value="DENY:1" /></td>
</tr>
<tr>
<td style="width: 189.383px;"><strong>&nbsp;Talkgroup Slot 1 ACLs:</strong></td>
<td style="width: 392.617px;">&nbsp;<input name="ts1_acl" type="text" value="PERMIT:ALL" /></td>
</tr>
<tr>
<td style="width: 189.383px;"><strong>&nbsp;Talkgroup Slot 2 ACLs:</strong></td>
<td style="width: 392.617px;">&nbsp;<input name="ts2_acl" type="text" value="PERMIT:ALL" /></td>
</tr>
<tr>
<td style="width: 189.383px;"><strong>&nbsp;Enable Unit Calls:</strong></td>
<td style="width: 392.617px;">&nbsp;<select name="enable_unit">
<option value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>
<tr>
<td><strong>&nbsp;Public List:</strong></td>
<td>&nbsp;<select name="public_list">
<option value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>

<tr>
<td><strong>&nbsp;Misc Options:</strong></td>
<td>&nbsp;<textarea id="other_options" cols="50" name="other_options" rows="4"></textarea></td>
</tr>

<tr>
<td style="width: 189.383px;"><strong>&nbsp;Notes:</strong></td>
<td style="width: 392.617px;">&nbsp;<textarea id="notes" cols="50" name="notes" rows="4"></textarea></td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<p style="text-align: center;"><input type="submit" value="Save" /></form></p>
<p>&nbsp;</p>
'''
            

        elif request.args.get('add_master'):
            s = ServerList.query.all()
            server_options = ''
            for i in s:
                server_options = server_options + '''<option value="''' + i.name + '''">''' + i.name + '''</option>\n'''
            
            content = '''
<p>&nbsp;</p>
<h2 style="text-align: center;"><strong>Add an MASTER</strong></h2>
<p>&nbsp;</p>
<form action="manage_masters?master_save=add" method="post">
<table style="width: 600px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td style="width: 175.567px;"><strong>Assign to Server:</strong></td>
<td style="width: 399.433px;">&nbsp;<select name="server">''' + server_options + '''</select></td>
</tr>
<tr>
<td><strong>&nbsp;Name:</strong></td>
<td>&nbsp;<input name="name_text" type="text" value="" /></td>
</tr>
<tr>
<td><strong>&nbsp;Active:</strong></td>
<td>&nbsp;<select name="enabled">
<option selected="selected" value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>
<tr>
<td><strong>&nbsp;Repeat:</strong></td>
<td>&nbsp;<select name="repeat">
<option selected="selected" value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>
<tr>
<td><strong>&nbsp;Max Peers:</strong></td>
<td>&nbsp;<input name="max_peers" type="text" value="5" /></td>
</tr>
<tr>
<td><strong>&nbsp;Static APRS positions:</strong></td>
<td>&nbsp;<select name="aprs_pos">
<option selected="selected" value="False">False</option>
<option value="True">True</option>
</select></td>
</tr>
<tr>
<td><strong>&nbsp;User Manager for login:</strong></td>
<td>&nbsp;<select name="enable_um">
<option selected="selected" value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>
<tr>
<td><strong>&nbsp;IP:</strong></td>
<td>&nbsp;<input name="ip" type="text" value="" /></td>
</tr>
<tr>
<td><strong>&nbsp;PORT:</strong></td>
<td>&nbsp;<input name="port" type="text" value="62030" /></td>
</tr>
<tr>
<td><strong>&nbsp;Passphrase:</strong></td>
<td>&nbsp;<input name="passphrase" type="text" value="passw0rd" /></td>
</tr>
<tr>
<td><strong>&nbsp;Group Hangtime:</strong></td>
<td>&nbsp;<input name="group_hangtime" type="text" value="5" /></td>
</tr>
<tr>
<td><strong>&nbsp;Use ACLs:</strong></td>
<td>&nbsp;<select name="use_acl">
<option value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>
<tr>
<td><strong>&nbsp;Register ACLs:</strong></td>
<td>&nbsp;<input name="reg_acl" type="text" value="DENY:1" /></td>
</tr>
<tr>
<td><strong>&nbsp;Subscriber ACLs:</strong></td>
<td>&nbsp;<input name="sub_acl" type="text" value="DENY:1" /></td>
</tr>
<tr>
<td><strong>&nbsp;Talkgroup Slot 1 ACLs:</strong></td>
<td>&nbsp;<input name="ts1_acl" type="text" value="PERMIT:ALL" /></td>
</tr>
<tr>
<td><strong>&nbsp;Talkgroup Slot 2 ACLs:</strong></td>
<td>&nbsp;<input name="ts2_acl" type="text" value="PERMIT:ALL" /></td>
</tr>
<tr>
<td><strong>&nbsp;Enable Unit Calls:</strong></td>
<td>&nbsp;<select name="enable_unit">
<option value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>
<tr>
<td><strong>&nbsp;Public List:</strong></td>
<td>&nbsp;<select name="public_list">
<option value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>

<tr>
<td><strong>&nbsp;Misc Options:</strong></td>
<td>&nbsp;<textarea id="other_options" cols="50" name="other_options" rows="4"></textarea></td>
</tr>

<tr>
<td><strong>&nbsp;Notes:</strong></td>
<td>&nbsp;<textarea id="notes" cols="50" name="notes" rows="4"></textarea></td>
</tr>
</tbody>
</table>
<p style="text-align: center;">&nbsp;</p>
  <p style="text-align: center;"><input type="submit" value="Save" /></form></p>
<p style="text-align: center;">&nbsp;</p>
'''
        elif request.args.get('edit_OBP'):
##            print(request.args.get('server'))
##            print(request.args.get('edit_OBP'))
##            s = ServerList.query.all()
            o = OBP.query.filter_by(server=request.args.get('server')).filter_by(name=request.args.get('edit_OBP')).first()
##            print(o.notes)
            content = '''
<p>&nbsp;</p>
<h2 style="text-align: center;"><strong>View/Edit OpenBridge Connection</strong></h2>
<p style="text-align: center;"><strong><a href="manage_masters?OBP_save=delete&amp;server=''' + str(o.server) + '''&amp;name=''' + str(o.name) + '''">Delete OpenBridge Connection</a></strong></p>
<form action="manage_masters?OBP_save=edit&amp;server=''' + str(request.args.get('server')) + '''&amp;name=''' + str(o.name) + '''" method="post">
<table style="width: 600px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td><strong>&nbsp;Name:</strong></td>
<td>&nbsp;''' + str(o.name) + '''</td>
</tr>
<tr>
<td><strong>&nbsp;Active:</strong></td>
<td>&nbsp;<select name="enabled">
<option selected="selected" value="''' + str(o.enabled) + '''">Current - ''' + str(o.enabled) + '''</option>
<option value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>
<tr>
<td><strong>&nbsp;IP:</strong></td>
<td>&nbsp;<input name="ip" type="text" value="''' + str(o.ip) + '''" /></td>
</tr>
<tr>
<td><strong>&nbsp;Port:</strong></td>
<td>&nbsp;<input name="port" type="text" value="''' + str(o.port) + '''" /></td>
</tr>
<tr>
<td><strong>&nbsp;Passphrase:</strong></td>
<td>&nbsp;<input name="passphrase" type="text" value="''' + str(o.passphrase) + '''" /></td>
</tr>
<tr>
<td><strong>&nbsp;Network ID:</strong></td>
<td>&nbsp;<input name="network_id" type="text" value="''' + str(o.network_id) + '''" /></td>
</tr>
<tr>
<td><strong>&nbsp;Target IP:</strong></td>
<td>&nbsp;<input name="target_ip" type="text" value="''' + str(o.target_ip) + '''" /></td>
</tr>
<tr>
<td><strong>&nbsp;Target Port:</strong></td>
<td>&nbsp;<input name="target_port" type="text" value="''' + str(o.target_port) + '''" /></td>
</tr>
<tr>
<td><strong>&nbsp;Use ACLs:</strong></td>
<td>&nbsp;<select name="use_acl">
<option selected="selected" value="''' + str(o.use_acl) + '''">Current - ''' + str(o.use_acl) + '''</option>
<option value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>
<tr>
<td><strong>&nbsp;Subscriber ACLs:</strong></td>
<td>&nbsp;<input name="sub_acl" type="text" value="''' + str(o.sub_acl) + '''" /></td>
</tr>
<tr>
<td><strong>&nbsp;Talkgroup ACLs:</strong></td>
<td>&nbsp;<input name="tg_acl" type="text" value="''' + str(o.tg_acl) + '''" /></td>
</tr>
<tr>
<td><strong>&nbsp;Use Both Slots:</strong></td>
<td>&nbsp;<select name="both_slots">
<option selected="selected" value="''' + str(o.both_slots) + '''">Current - ''' + str(o.both_slots) + '''</option>
<option value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>
<tr>
<td><strong>&nbsp;Enable Unit Calls:</strong></td>
<td>&nbsp;<select name="enable_unit">
<option selected="selected" value="''' + str(o.enable_unit) + '''">Current - ''' + str(o.enable_unit) + '''</option>
<option value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>

<tr>
<td><strong>&nbsp;Use Encryption:</strong></td>
<td>&nbsp;<select name="obp_encryption">
<option selected="selected" value="''' + str(o.obp_encryption) + '''">Current - ''' + str(o.obp_encryption) + '''</option>
<option value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>

<td><strong>&nbsp;Encryption_key:</strong></td>
<td>&nbsp;<input name="encryption_key" type="text" value="''' + str(o.encryption_key) + '''" /></td>
</tr>

<tr>
<td><strong>&nbsp;Misc Options:</strong></td>
<td>&nbsp;<textarea id="other_options" cols="50" name="other_options" rows="4">''' + str(o.other_options) + '''</textarea></td>
</tr>

<tr>
<td><strong>&nbsp;Notes:</strong></td>
<td>&nbsp;<textarea id="notes" cols="50" name="notes" rows="4">''' + str(o.notes) + '''</textarea></td>
</tr>
</tbody>
</table>
<p style="text-align: center;">&nbsp;</p>
<p style="text-align: center;"><input type="submit" value="Save" /></p>
</form>
<p>&nbsp;</p>

    '''
            
        elif request.args.get('edit_master'):
##            s = ServerList.query.all()
            m = MasterList.query.filter_by(server=request.args.get('server')).filter_by(name=request.args.get('edit_master')).first()
            
            content = '''
<p>&nbsp;</p>
<h2 style="text-align: center;"><strong>View/Edit a MASTER</strong></h2>
<p style="text-align: center;"><strong><a href="manage_masters?master_save=delete&amp;server=''' + str(m.server) + '''&amp;name=''' + str(m.name) + '''">Delete MASTER</a></strong></p>
<form action="manage_masters?master_save=edit&amp;server=''' + request.args.get('server') + '''&amp;name=''' + request.args.get('edit_master') + '''" method="post">
<table style="width: 600px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td><strong>&nbsp;Name:</strong></td>
<td>&nbsp;''' + str(m.name) + '''</td>
</tr>
<tr>
<td><strong>&nbsp;Active:</strong></td>
<td>&nbsp;<select name="enabled">
<option selected="selected" value="''' + str(m.active) + '''">Current - ''' + str(m.active) + '''</option>
<option value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>
<tr>
<td><strong>&nbsp;Repeat:</strong></td>
<td>&nbsp;<select name="repeat">
<option selected="selected" value="''' + str(m.repeat) + '''">Current - ''' + str(m.repeat) + '''</option>
<option value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>
<tr>
<td><strong>&nbsp;Max Peers:</strong></td>
<td>&nbsp;<input name="max_peers" type="text" value="''' + str(m.max_peers) + '''" /></td>
</tr>
<tr>
<td><strong>&nbsp;Static APRS positions:</strong></td>
<td>&nbsp;<select name="aprs_pos">
<option selected="selected" value="''' + str(m.static_positions) + '''">Current - ''' + str(m.static_positions) + '''</option>
<option value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>
<tr>
<td><strong>&nbsp;User Manager for login:</strong></td>
<td>&nbsp;<select name="enable_um">
<option selected="selected" value="''' + str(m.enable_um) + '''">Current - ''' + str(m.enable_um) + '''</option>
<option value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>
<tr>
<td><strong>&nbsp;IP:</strong></td>
<td>&nbsp;<input name="ip" type="text" value="''' + str(m.ip) + '''" /></td>
</tr>
<tr>
<td><strong>&nbsp;PORT:</strong></td>
<td>&nbsp;<input name="port" type="text" value="''' + str(m.port) + '''" /></td>
</tr>
<tr>
<td><strong>&nbsp;Passphrase:</strong></td>
<td>&nbsp;<input name="passphrase" type="text" value="''' + str(m.passphrase) + '''" /></td>
</tr>
<tr>
<td><strong>&nbsp;Group Hangtime:</strong></td>
<td>&nbsp;<input name="group_hangtime" type="text" value="''' + str(m.group_hang_time) + '''" /></td>
</tr>
<tr>
<td><strong>&nbsp;Use ACLs:</strong></td>
<td>&nbsp;<select name="use_acl">
<option selected="selected" value="''' + str(m.use_acl) + '''">Current - ''' + str(m.use_acl) + '''</option>
<option value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>
<tr>
<td><strong>&nbsp;Register ACLs:</strong></td>
<td>&nbsp;<input name="reg_acl" type="text" value="''' + str(m.reg_acl) + '''" /></td>
</tr>
<tr>
<td><strong>&nbsp;Subscriber ACLs:</strong></td>
<td>&nbsp;<input name="sub_acl" type="text" value="''' + str(m.sub_acl) + '''" /></td>
</tr>
<tr>
<td><strong>&nbsp;Talkgroup Slot 1 ACLs:</strong></td>
<td>&nbsp;<input name="ts1_acl" type="text" value="''' + str(m.tg1_acl) + '''" /></td>
</tr>
<tr>
<td><strong>&nbsp;Talkgroup Slot 2 ACLs:</strong></td>
<td>&nbsp;<input name="ts2_acl" type="text" value="''' + str(m.tg1_acl) + '''" /></td>
</tr>
<tr>
<td><strong>&nbsp;Enable Unit Calls:</strong></td>
<td>&nbsp;<select name="enable_unit">
<option selected="selected" value="''' + str(m.enable_unit) + '''">Current - ''' + str(m.enable_unit) + '''</option>
<option value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>
<tr>
<td><strong>&nbsp;Public List:</strong></td>
<td>&nbsp;<select name="public_list">
<option selected="selected" value="''' + str(m.public_list) + '''">Current - ''' + str(m.public_list) + '''</option>
<option value="True">True</option>
<option value="False">False</option>
</select></td>
</tr>

<tr>
<td><strong>&nbsp;Misc Options:</strong></td>
<td>&nbsp;<textarea id="other_options" cols="50" name="other_options" rows="4">''' + str(m.other_options) + '''</textarea></td>
</tr>

<tr>
<td><strong>&nbsp;Notes:</strong></td>
<td>&nbsp;<textarea id="notes" cols="50" name="notes" rows="4">''' + str(m.notes) + '''</textarea></td>
</tr>
</tbody>
</table>
<p style="text-align: center;">&nbsp;</p>
<p style="text-align: center;"><input type="submit" value="Save" /></form></p>
<p>&nbsp;</p>
'''
##        elif not request.args.get('edit_master') and not request.args.get('edit_OBP') and not request.args.get('add_OBP') and not request.args.get('add_master'):
##            content = 'jglkdjklsd'
        else:
        #elif not request.args.get('add_proxy') or not request.args.get('add_OBP') or not request.args.get('add_master'): # or not request.args.get('proxy_save') or not request.args.get('master_save') or not request.args.get('OBP_save'):
            all_s = ServerList.query.all()
            m_list = ''
            for s in all_s:
##                print(s.name)
                m_list = m_list + '''
<h4 style="text-align: center;">Server: ''' + str(s.name) + '''</h4>
<table style="width: 400px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td style="text-align: center;"><strong>Name</strong></td>
<td style="text-align: center;"><strong>Mode</strong></td>
<td style="text-align: center;"><strong>Notes</strong></td>

</tr>
'''
                all_m = MasterList.query.filter_by(server=s.name).all()
                all_p = ProxyList.query.filter_by(server=s.name).all()
                all_o = OBP.query.filter_by(server=s.name).all()
                for o in all_o:
                    m_list = m_list + '''
<tr>
<td><a href="manage_masters?server=''' + str(s.name) + '''&amp;edit_OBP=''' + str(o.name) + '''">''' + str(o.name) + '''</a></td>
<td>OpenBridge</td>
<td>''' + str(o.notes) + '''</td>

</tr>
'''
                for p in all_p:
                    m_list = m_list + '''
<tr>
<td><a href="manage_masters?server=''' + str(s.name) + '''&amp;edit_proxy=''' + str(p.name) + '''">''' + str(p.name) + '''</a></td>
<td>PROXY</td>
<td>''' + str(p.notes) + '''</td>

</tr>
'''
                for x in all_m:
                    m_list = m_list + '''
<tr>
<td><a href="manage_masters?server=''' + str(x.server) + '''&amp;edit_master=''' + str(x.name) + '''">''' + str(x.name) + '''</a></td>
<td>MASTER</td>
<td>''' + str(x.notes) + '''</td>

</tr>

'''
                m_list = m_list + ''' </tbody></table>\n'''
            content = '''

<h3 style="text-align: center;">View/Edit Masters</h3>

<table style="width: 400px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td style="text-align: center;"><strong><a href="manage_masters?add_master=yes">Add MASTER</a></strong></td>
<td style="text-align: center;"><strong><a href="manage_masters?add_proxy=yes">Add PROXY</a></strong></td>
<td style="text-align: center;"><strong><a href="manage_masters?add_OBP=yes">Add OpenBridge</a></strong></td>

</tr>
</tbody>
</table>
<p>&nbsp;</p>

<p style="text-align: center;"><a href="/OBP_key_gen"><button class="btn btn-primary" type="button">Generate OpenBridge Encryption Key</button></a></p>

<p>&nbsp;</p>

''' + m_list

        return render_template('flask_user_layout.html', markup_content = Markup(content))


    @app.route('/add_user', methods=['POST', 'GET'])
    @login_required
    @roles_required('Admin') 
    def add_admin():
        if request.method == 'GET':
            content = '''
<td><form action="add_user" method="POST">
<table style="margin-left: auto; margin-right: auto;">
<tbody>
<tr style="height: 51.1667px;">
<td style="height: 51.1667px; text-align: center;">
  <label for="username">Username:</label><br>
  <input type="text" id="username" name="username"><br>
</td></tr>

<tr style="height: 51.1667px;">
<td style="height: 51.1667px; text-align: center;">
  <label for="username">Password:</label><br>
  <input type="password" id="password" name="password" ><br>
</td></tr>

<tr style="height: 51.1667px;">
<td style="height: 51.1667px; text-align: center;">
  <label for="username">Email:</label><br>
  <input type="text" id="email" name="email" ><br>
</td></tr>

<tr style="height: 27px;">
<td style="text-align: center; height: 27px;"><input type="submit" value="Submit" /></td>
</tr>
</tbody>
</table>
</form></td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
'''
        elif request.method == 'POST' and request.form.get('username'):
            if not User.query.filter(User.username == request.form.get('username')).first():
                radioid_data = ast.literal_eval(get_ids(request.form.get('username')))
                user = User(
                    username=request.form.get('username'),
                    email=request.form.get('email'),
                    email_confirmed_at=datetime.datetime.utcnow(),
                    password=user_manager.hash_password(request.form.get('password')),
                    dmr_ids = str(radioid_data[0]),
                    initial_admin_approved = True,
                    first_name = str(radioid_data[1]),
                    last_name = str(radioid_data[2]),
                    city = str(radioid_data[3])
                    
                )
                
                db.session.add(user)
                u = User.query.filter_by(username=request.form.get('username')).first()
                user_role = UserRoles(
                    user_id=u.id,
                    role_id=2,
                    )
                db.session.add(user_role)
                db.session.commit()
                content = '''<p style="text-align: center;">Created user: <strong>''' + str(request.form.get('username')) + '''</strong></p>\n'''
            elif User.query.filter(User.username == request.form.get('username')).first():
                content = 'Existing user: ' + str(request.form.get('username') + '. New user not created.')
                
        return render_template('flask_user_layout.html', markup_content = Markup(content))

    @app.route('/manage_rules', methods=['POST', 'GET'])
    @login_required
    @roles_required('Admin')
    def manage_rules():
        
        if request.args.get('save_bridge') == 'save':
            public = False
            if request.form.get('public_list') == 'True':
                public = True
            if request.form.get('bridge_name') == '':
                    content = '''<h3 style="text-align: center;">Bridge can't have blank name.</h3>
<p style="text-align: center;">Redirecting in 3 seconds.</p>
<meta http-equiv="refresh" content="3; URL=manage_rules" />'''
            else:
                bridge_add(request.form.get('bridge_name'), request.form.get('description'), public, request.form.get('tg'))
                content = '''<h3 style="text-align: center;">Bridge (talkgroup) saved.</h3>
    <p style="text-align: center;">Redirecting in 3 seconds.</p>
    <meta http-equiv="refresh" content="3; URL=manage_rules" /> '''
        elif request.args.get('save_bridge') == 'edit':
            public = False
            if request.form.get('public_list') == 'True':
                public = True
            update_bridge_list(request.args.get('bridge'), request.form.get('description'), public, request.form.get('bridge_name'), request.form.get('tg'))
            content = '''<h3 style="text-align: center;">Bridge (talkgroup) changed.</h3>
<p style="text-align: center;">Redirecting in 3 seconds.</p>
<meta http-equiv="refresh" content="3; URL=manage_rules" /> '''
        elif request.args.get('save_bridge') == 'delete':
            bridge_delete(request.args.get('bridge'))
            content = '''<h3 style="text-align: center;">Bridge (talkgroup) deleted.</h3>
<p style="text-align: center;">Redirecting in 3 seconds.</p>
<meta http-equiv="refresh" content="3; URL=manage_rules" /> '''


        #Rules
        elif request.args.get('save_rule'):
##            public_list = False
            active = False
            if request.form.get('active_dropdown') == 'True':
                active = True
            if request.args.get('save_rule') == 'new':
                add_system_rule(request.form.get('bridge_dropdown'), request.form.get('system_text'), request.form.get('ts_dropdown'), request.form.get('tgid'), active, request.form.get('timer_time'), request.form.get('type_dropdown'), request.form.get('on'), request.form.get('off'), request.form.get('reset'), request.args.get('server'))
                content = '''<h3 style="text-align: center;">Bridge (talkgroup) rule saved.</h3>
<p style="text-align: center;">Redirecting in 3 seconds.</p>
<meta http-equiv="refresh" content="3; URL=manage_rules" /> '''
            elif request.args.get('save_rule') == 'edit':
                content = '''<h3 style="text-align: center;">Bridge (talkgroup) rule changed.</h3>
<p style="text-align: center;">Redirecting in 3 seconds.</p>
<meta http-equiv="refresh" content="3; URL=manage_rules" /> '''
            elif request.args.get('save_rule') == 'delete':
                # print(request.args.get('bridge'))
                # print(request.args.get('server'))
                if request.args.get('system'):
                    delete_system_rule(request.args.get('bridge'), request.args.get('server'), request.args.get('system'))
                else:
                    delete_system_bridge(request.args.get('bridge'), request.args.get('server'))
        
##                delete_system_rule(request.args.get('bridge'), request.args.get('server'), request.args.get('system'))
                content = '''<h3 style="text-align: center;">System rule deleted.</h3>
<p style="text-align: center;">Redirecting in 3 seconds.</p>
<meta http-equiv="refresh" content="3; URL=manage_rules" /> '''

        elif request.args.get('add_rule'):
##            svl = ServerList.query.all()
            bl = BridgeList.query.all() #filter(bridge_name== request.form.get('username')).all()
            all_o = OBP.query.filter_by(server=request.args.get('add_rule')).all()
            all_m = MasterList.query.filter_by(server=request.args.get('add_rule')).all()
            all_p = ProxyList.query.filter_by(server=request.args.get('add_rule')).all()
            m_l = mmdvmPeer.query.filter_by(server=request.args.get('add_rule')).all()
            x_l = xlxPeer.query.filter_by(server=request.args.get('add_rule')).all()
##            print(sl)
##            print(bl)
##            svl_option = ''
            bl_option = ''
            sl_option = ''
            for i in all_o:
                sl_option = sl_option + '''<option value="''' + str(i.name) + '''">''' + str(i.name) + '''</option>'''
            for i in all_m:
                sl_option = sl_option + '''<option value="''' + str(i.name) + '''">''' + str(i.name) + '''</option>'''
            for i in all_p:
                sl_option = sl_option + '''<option value="''' + str(i.name) + '''">''' + str(i.name) + '''</option>'''
            for i in m_l:
                sl_option = sl_option + '''<option value="''' + str(i.name) + '''">''' + str(i.name) + '''</option>'''
            for i in x_l:
                sl_option = sl_option + '''<option value="''' + str(i.name) + '''">''' + str(i.name) + '''</option>'''
            for i in bl:
                bl_option = bl_option + '''<option value="''' + str(i.bridge_name) + '''">''' + str(i.bridge_name) + '''</option>'''
            content = '''
<h3 style="text-align: center;">Add rule to server: ''' + request.args.get('add_rule') + '''</h3>

<form action="manage_rules?save_rule=new&server=''' + request.args.get('add_rule') + '''" method="post">
<p style="text-align: center;">&nbsp;</p>
<table style="margin-left: auto; margin-right: auto;" border="1" width="800">
<tbody>
<tr>
<td><strong>Bridge (Talkgroup): </strong><select name="bridge_dropdown">
''' + bl_option + '''
</select></td>
<td><strong>System: </strong><select name="system_text">
''' + sl_option + '''
</select></td>
<td><strong>Timeslot: </strong><select name="ts_dropdown">
<option selected="selected" value="1">1</option>
<option selected="selected" value="2">2</option>
</select></td>
<td><strong>Talkgroup number: </strong> <input name="tgid" type="text" /></td>
<td><strong>Activate on start:</strong> &nbsp;<select name="active_dropdown">
<option selected="selected" value="True">True</option>
<option selected="selected" value="False">False</option>
</select></td>
</tr>
<tr>
<td><strong>Timer Time (minutes): </strong> &nbsp;<input name="timer_time" type="text" value="0"/></td>
<td><strong>Timer Type: &nbsp;</strong><select name="type_dropdown">
<option selected="selected" value="NONE">None</option>
<option selected="selected" value="ON">On</option>
<option selected="selected" value="OFF">Off</option>
</select></td>
<td><strong>Trigger ON TGs: &nbsp;</strong> <input name="on" type="text" /></td>
<td><strong>Trigger OFF TGs:</strong> &nbsp;<input name="off" type="text" /></td>
<td><strong>Trigger Reset TGs: &nbsp; <input name="reset" type="text" /></strong></td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<p style="text-align: center;"><input type="submit" value="Add Rule" /></p>
</form>
<p>&nbsp;</p>

'''
        elif request.args.get('edit_rule') and request.args.get('bridge'):
            br = BridgeRules.query.filter_by(server=request.args.get('edit_rule')).filter_by(bridge_name=request.args.get('bridge')).all()
            print(br)
            br_view = '''<h3 style="text-align: center;">Rules for bridge  <span style="text-decoration: underline;">''' + request.args.get('bridge') + '''</span> on server <span style="text-decoration: underline;">''' + request.args.get('edit_rule') + '''</span>.</h3> '''
            for i in br:
                br_view = br_view + '''
<table style="margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
&nbsp;<td style="text-align: center;"><a href="manage_rules?save_rule=delete&server=''' + str(i.server) + '''&bridge=''' + str(i.bridge_name) + '''&system=''' + str(i.system_name) + '''">Delete SYSTEM Rule</a></td>
</tr>
<tr>
<td><form action="manage_rules?edit_rule=save&system=''' + str(i.system_name) + '''&server=''' + request.args.get('edit_rule') + '''&bridge_edit=''' + request.args.get('bridge') + '''" method="post" >
<p style="text-align: center;">&nbsp;</p>
<table style="margin-left: auto; margin-right: auto;" border="1" width="800">
<tbody>
<tr>
<td><strong>Bridge (Talkgroup): </strong>''' + str(i.bridge_name) + '''</td>
<td><strong>System: </strong>''' + str(i.system_name) + '''</td>
<td><strong>Timeslot: </strong><select name="ts_dropdown">
<option selected="selected" value="''' + str(i.ts) + '''">Current - ''' + str(i.ts) + '''</option>
<option  value="1">1</option>
<option  value="2">2</option>
</select></td>
<td><strong>Talkgroup number: </strong> <input name="tgid" type="text" value="''' + str(i.tg) + '''"/></td>
<td><strong>Activate on start:</strong> &nbsp;<select name="active_dropdown">
<option selected="selected" value="''' + str(i.active) + '''">Current - ''' + str(i.active) + '''</option>
<option  value="True">True</option>
<option  value="False">False</option>
</select></td>
</tr>
<tr>
<td><strong>Timer Time (minutes): </strong> &nbsp;<input name="timer_time" type="text" value="''' + str(i.timeout) + '''"/></td>
<td><strong>Timer Type: &nbsp;</strong><select name="type_dropdown">
<option selected="selected" value="''' + str(i.to_type) + '''">Current - ''' + str(i.to_type) + '''</option>
<option  value="NONE">None</option>
<option  value="ON">On</option>
<option  value="OFF">Off</option>
</select></td>
<td><strong>Trigger ON TGs: &nbsp;</strong> <input name="on" type="text" value="''' + str(i.on) + '''"/></td>
<td><strong>Trigger OFF TGs:</strong> &nbsp;<input name="off" type="text" value="''' + str(i.off) + '''"/></td>
<td><strong>Trigger Reset TGs:</strong> &nbsp; <input name="reset" type="text" value="''' + str(i.reset) + '''"/></td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<p style="text-align: center;"><input type="submit" value="Update Rule" /></p>
</form>
<p>&nbsp;</p>
</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>

'''
            content = br_view

        elif request.args.get('edit_rule') == 'save' and request.args.get('bridge_edit'):
##            public_list = False
            active = False
            if request.form.get('active_dropdown') == 'True':
                active = True
            edit_system_rule(request.args.get('bridge_edit'), request.args.get('system'), request.form.get('ts_dropdown'), request.form.get('tgid'), active, request.form.get('timer_time'), request.form.get('type_dropdown'), request.form.get('on'), request.form.get('off'), request.form.get('reset'), request.args.get('server'))
            content = '''<h3 style="text-align: center;">System rule changed.</h3>
<p style="text-align: center;">Redirecting in 3 seconds.</p>
<meta http-equiv="refresh" content="3; URL=manage_rules" /> '''
        
        elif request.args.get('add_bridge'):
            s = ServerList.query.all()
##            server_options = ''
##            for i in s:
##                server_options = server_options + '''<option value="''' + i.name + '''">''' + i.name + '''</option>\n'''

            content = '''
<p>&nbsp;</p>
<h2 style="text-align: center;"><strong>Add a Talk Group</strong></h2>
<form action="manage_rules?save_bridge=save" method="POST">
<table style="width: 200px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr style="height: 51.1667px;">
<td style="height: 51.1667px; text-align: center;"><label for="bridge_name">Name:</label><br /> <input id="bridge_name" name="bridge_name" type="text" /><p>&nbsp;</p>
</td>
</tr>

<tr style="height: 51.1667px;">
<td style="height: 51.1667px; text-align: center;"><label for="tg">Talk Group ID:</label><br /> <input id="tg" name="tg" type="text" value = "1234"/><p>&nbsp;</p>
</td>
</tr>

<tr style="height: 51.1667px;">
<td style="height: 51.1667px; text-align: center;"><label for="description">Description (HTML OK):</label><br /> <textarea id="notes" cols="30" name="description" rows="4"></textarea></td>
</tr>
<tr style="height: 51.1667px;">
<td style="height: 51.1667px; text-align: center;"><label for="public_list">Public List:</label><br /><select name="public_list">
<option selected="selected" value="True">True</option>
<option value="False">False</option>
</select><p>&nbsp;</p>
</td>
</tr>
<tr style="height: 27px;">
<td style="text-align: center; height: 27px;">
<p>&nbsp;</p>

<p><input type="submit" value="Submit" /></p>
</td>
</tr>
</tbody>
</table>
</form>
'''
        elif request.args.get('edit_bridge'):
            b = BridgeList.query.filter_by(bridge_name=request.args.get('edit_bridge')).first()
##            s = ServerList.query.all()
##            server_options = ''
##            for i in s:
##                server_options = server_options + '''<option value="''' + i.name + '''">''' + i.name + '''</option>\n'''

            content = '''
<p>&nbsp;</p>
<h2 style="text-align: center;"><strong>Edit a Talk Group</strong></h2>
<p style="text-align: center;"><strong><a href="manage_rules?bridge=''' + request.args.get('edit_bridge') + '''&save_bridge=delete">Delete Talk Group</a></strong></p>
<p>&nbsp;</p>

<form action="manage_rules?save_bridge=edit&bridge=''' + request.args.get('edit_bridge') + '''" method="POST">
<table style="width: 200px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr style="height: 51.1667px;">
<td style="height: 51.1667px; text-align: center;"><label for="bridge_name">Name:</label><br /> <input id="bridge_name" name="bridge_name" type="text" value = "''' + str(b.bridge_name) + '''"/><p>&nbsp;</p>
</td>
</tr>

<tr style="height: 51.1667px;">
<td style="height: 51.1667px; text-align: center;"><label for="tg">Talk Group ID:</label><br /> <input id="tg" name="tg" type="text" value = "''' + str(b.tg) + '''"/><p>&nbsp;</p>
</td>
</tr>

<tr style="height: 51.1667px;">
<td style="height: 51.1667px; text-align: center;"><label for="description">Description (HTML OK):</label><br /> <textarea id="notes" cols="30" name="description" rows="4">''' + str(b.description) + '''</textarea></td>
</tr>
<tr style="height: 51.1667px;">
<td style="height: 51.1667px; text-align: center;"><label for="public_list">Public List:</label><br /><select name="public_list">
<option selected="selected" value="''' + str(b.public_list) + '''">Current - ''' + str(b.public_list) + '''</option>
<option value="False">False</option>
<option value="True">True</option>

</select><p>&nbsp;</p>
</td>
</tr>
<tr style="height: 27px;">
<td style="text-align: center; height: 27px;">
<p>&nbsp;</p>

<p><input type="submit" value="Submit" /></p>
</td>
</tr>
</tbody>
</table>
</form>
'''
        else:
            all_b = BridgeList.query.all()
            s = ServerList.query.all()
            b_list = '''
<h3 style="text-align: center;">View/Edit Bridges (Talk Groups)</h3>

<table style="width: 400px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td style="text-align: center;"><strong><a href="manage_rules?add_bridge=yes">Add Bridge</a></strong></td>

</tr>
</tbody>
</table>
<p>&nbsp;</p>

<table style="width: 700px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td style="text-align: center; width: 187px;"><strong>Name</strong></td>
<td style="text-align: center; width: 61.55px;"><strong>Public</strong></td>
<td style="text-align: center; width: 227.45px;"><strong>Description</strong></td>
<td style="text-align: center; width: 88px;"><strong>TGID</strong></td>

</tr>
'''
            for i in all_b:
                b_list = b_list + '''
<tr>
<td style="text-align: center;"><a href="manage_rules?edit_bridge=''' + str(i.bridge_name) + '''">''' + str(i.bridge_name) + '''</a>
<td style="text-align: center;">''' + str(i.public_list) + '''</td>
<td style="text-align: center;">''' + str(re.sub('<[^>]*>|\s\s+', ' ', i.description))[:50] + '''...</td>
<td style="text-align: center;">''' + str(i.tg) + '''</td>

</tr>
'''
            b_list = b_list + '''</tbody></table>
<h3 style="text-align: center;">View/Edit Rules</h3>

'''
            r_list = ''
            for i in s:
                # print(i)
                r_list = r_list + '''
<table style="width: 500px; margin-left: auto; margin-right: auto;" border="1">
  <tbody>
    <tr>
<td style="text-align: center;"><strong>Add a rule to server: <a href="manage_rules?add_rule=''' + str(i.name) + '''">''' + str(i.name) + '''</a></strong></td> 
      </tr>
  </tbody>
</table>
<table style="width: 500px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td style="text-align: center;"><strong>Bridge Name</strong></td>
<td style="text-align: center;"><strong>-</strong></td>
<td style="text-align: center;"><strong>-</strong></td>
</tr>'''
                br = BridgeRules.query.filter_by(server=i.name).all()
                temp_list = []
                for x in br:  #.filter_by(bridge_name=request.args.get('bridge')).all()
                    if x.bridge_name in temp_list:
                        pass
                    else:
                        temp_list.append(x.bridge_name)
                        r_list = r_list + '''
<tr>
<td style="text-align: center;">''' + str(x.bridge_name) + '''</td>
<td style="text-align: center;"><a href="manage_rules?edit_rule=''' + str(i.name) + '''&bridge=''' + str(x.bridge_name) + '''">Edit Bridge Rules</a></td>
<td style="text-align: center;"><a href="manage_rules?save_rule=delete&server=''' + str(i.name) + '''&bridge=''' + str(x.bridge_name) + '''">Delete Bridge from this server</a></td>
</tr>
'''
                r_list = r_list + '''</tbody></table><p>&nbsp;</p>'''
            content = b_list + r_list + '''</tbody></table>'''
            
        return render_template('flask_user_layout.html', markup_content = Markup(content))

    @login_required
    @roles_required('Admin')
    @app.route('/OBP_key_gen')
    def obp_key_gen():
        key = Fernet.generate_key()
##        content = str(key)[2:-1]
        content = '''
<h3 style="text-align: center;">Generate OpenBridge Encryption Key</h3>
<p>&nbsp;</p>
<p style="text-align: center;">Both ends of the OpenBridge connection must share this same key.</p>
<p>&nbsp;</p>
<table style="width: 500px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td style="text-align: center;">KEY: (Copy and Paste)</td>
</tr>
<tr>
<td style="text-align: center;"><strong>''' + str(key)[2:-1] + '''</strong></td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
'''
        
        return render_template('flask_user_layout.html', markup_content = Markup(content))

    
    @app.route('/aprs')
    def data_dash():

##        dev_loc = GPS_LocLog.query.order_by(time).limit(3).all()
        dev_loc = GPS_LocLog.query.order_by(GPS_LocLog.time.desc()).limit(20).all()
        content = ''
        dev_lst = []
        for i in dev_loc:
            if i.callsign not in dev_lst:
                dev_lst.append(i.callsign)
                content = content + '''
    <tr>
    <td style="text-align: center;"><a href="https://hbnet.xyz"target="_blank"><strong>''' + i.callsign + '''</strong></a></td>
    <td style="text-align: center;"><strong>&nbsp;''' + i.lat + '''&nbsp;</strong></td>
    <td style="text-align: center;"><strong>&nbsp;''' + i.lon + '''&nbsp;</strong></td>
    <td style="text-align: center;">&nbsp;''' + str(i.time.strftime(time_format)) + '''&nbsp;</td>
    </tr>
'''
##        content = dev_loc

        return render_template('aprs_page.html', markup_content = Markup(content))

    @app.route('/svr', methods=['POST'])
    def auth():
        hblink_req = request.json
        print((hblink_req))
        if hblink_req['secret'] in shared_secrets():
            try:
                if hblink_req['ping']:
                    ping_list[hblink_req['ping']] = time.time()
                    response = ''
            except:
                pass
            if 'login_id' in hblink_req and 'login_confirmed' not in hblink_req:
                if type(hblink_req['login_id']) == int:
                    if authorized_peer(hblink_req['login_id'])[0]:
##                        print(active_tgs)
                        if isinstance(authorized_peer(hblink_req['login_id'])[1], int) == True:
                            authlog_add(hblink_req['login_id'], hblink_req['login_ip'], hblink_req['login_server'], authorized_peer(hblink_req['login_id'])[2], gen_passphrase(hblink_req['login_id']), 'Attempt')
##                            active_tgs[hblink_req['login_server']][hblink_req['system']] = [{'1':[]}, {'2':[]}, {'SYSTEM': ''}, {'peer_id':hblink_req['login_id']}]
                            response = jsonify(
                                    allow=True,
                                    mode='normal',
                                    )
                        elif authorized_peer(hblink_req['login_id'])[1] == '':
                            authlog_add(hblink_req['login_id'], hblink_req['login_ip'], hblink_req['login_server'], authorized_peer(hblink_req['login_id'])[2], 'Config Passphrase: ' + legacy_passphrase, 'Attempt')
##                            active_tgs[hblink_req['login_server']][hblink_req['system']] = [{'1':[]}, {'2':[]}, {'SYSTEM': ''}, {'peer_id':hblink_req['login_id']}]
                            response = jsonify(
                                    allow=True,
                                    mode='legacy',
                                    )
                        elif authorized_peer(hblink_req['login_id'])[1] != '' or isinstance(authorized_peer(hblink_req['login_id'])[1], int) == False:
                            authlog_add(hblink_req['login_id'], hblink_req['login_ip'], hblink_req['login_server'], authorized_peer(hblink_req['login_id'])[2], authorized_peer(hblink_req['login_id'])[1], 'Attempt')
##                            active_tgs[hblink_req['login_server']][hblink_req['system']] = [{'1':[]}, {'2':[]}, {'SYSTEM': ''}, {'peer_id':hblink_req['login_id']}]
                            # print(authorized_peer(hblink_req['login_id']))
                            response = jsonify(
                                    allow=True,
                                    mode='override',
                                    value=authorized_peer(hblink_req['login_id'])[1]
                                        )
                        try:
                            active_tgs[hblink_req['login_server']][hblink_req['system']] = [{'1':[]}, {'2':[]}, {'SYSTEM': ''}, {'peer_id':hblink_req['login_id']}]
##                            print('Restart ' + hblink_req['login_server'] + ' please.')
                        except:
##                            active_tgs[hblink_req['login_server']] = {}
                            pass
                    elif authorized_peer(hblink_req['login_id'])[0] == False:
##                        print('log fail')
                        authlog_add(hblink_req['login_id'], hblink_req['login_ip'], hblink_req['login_server'], 'Not Registered', '-', 'Failed')
                        response = jsonify(
                                    allow=False)
                elif not type(hblink_req['login_id']) == int:
                    user = hblink_req['login_id']
                    u = User.query.filter_by(username=user).first()
                    
                    if not u:
                        msg = jsonify(auth=False,
                                              reason='User not found')
                        response = make_response(msg, 401)
                    if u:
                        u_role = UserRoles.query.filter_by(user_id=u.id).first()
                        password = user_manager.verify_password(hblink_req['password'], u.password)
                        if u_role.role_id == 2:
                            role = 'user'
                        if u_role.role_id == 1:
                            role = 'admin'
                        if password:
                            response = jsonify(auth=True, role=role)
                        else:
                            msg = jsonify(auth=False,
                                              reason='Incorrect password')
                            response = make_response(msg, 401)
                            
            elif 'login_id' in hblink_req and 'login_confirmed' in hblink_req:
                if hblink_req['old_auth'] == True:
                    authlog_add(hblink_req['login_id'], hblink_req['login_ip'], hblink_req['login_server'], authorized_peer(hblink_req['login_id'])[2], 'CONFIG, NO UMS', 'Confirmed')
                else:
                    authlog_add(hblink_req['login_id'], hblink_req['login_ip'], hblink_req['login_server'], authorized_peer(hblink_req['login_id'])[2], 'USER MANAGER', 'Confirmed')
                response = jsonify(
                                logged=True
                                    )
            elif 'burn_list' in hblink_req: # ['burn_list']: # == 'burn_list':
                response = jsonify(
                                burn_list=get_burnlist()
                                    )
            elif 'loc_callsign' in hblink_req:
                if hblink_req['lat'] == '*' and hblink_req['lon'] == '*':
                    del peer_locations[hblink_req['dmr_id']]
                else:
                    peer_locations[hblink_req['dmr_id']] = [hblink_req['loc_callsign'], hblink_req['lat'], hblink_req['lon'], hblink_req['url'], hblink_req['description'], hblink_req['loc'], hblink_req['software']]
                response = ''
            elif 'dashboard' in hblink_req:
                if 'lat' in hblink_req:
                    # Assuming this is a GPS loc
                    dash_loc_add(hblink_req['call'], hblink_req['lat'], hblink_req['lon'], hblink_req['comment'], hblink_req['dmr_id'], hblink_req['dashboard'])
                    trim_dash_loc()
                    response = 'yes'
                    
                    

            elif 'get_config' in hblink_req:
                if hblink_req['get_config']: 
                    active_tgs[hblink_req['get_config']] = {}
                    ping_list[hblink_req['get_config']] = time.time()
##                    print(active_tgs)
    ##                try:
##                    print(get_peer_configs(hblink_req['get_config']))

                    print(masters_get(hblink_req['get_config']))
                    response = jsonify(
                            config=server_get(hblink_req['get_config']),
                            peers=get_peer_configs(hblink_req['get_config']),
                            masters=masters_get(hblink_req['get_config']),
    ##                        OBP=get_OBP(hblink_req['get_config'])

                            )
    ##                except:
    ##                    message = jsonify(message='Config error')
    ##                    response = make_response(message, 401)
            elif 'get_rules' in hblink_req:
                if hblink_req['get_rules']: # == 'burn_list':
                    
    ##                try:
                    response = jsonify(
                            rules=generate_rules(hblink_req['get_rules']),
    ##                        OBP=get_OBP(hblink_req['get_config'])

                            )
    ##                except:
    ##                    message = jsonify(message='Config error')
    ##                    response = make_response(message, 401)

#################### Work in progress ###########################33
##            elif 'update_tg' in hblink_req:
##                if hblink_req['update_tg']:
##                    print(hblink_req)
####                    print(hblink_req['data'][0]['SYSTEM'])
##                    if 'on' == hblink_req['mode']:
####                        try:
##                              if hblink_req['dmr_id'] == 0:
##                                print('id 0')
####                                print(active_tgs)
##                                for system in active_tgs[hblink_req['update_tg']].items():
##    ##                                print(system)
##    ##                                print('sys')
##                                    if system[0] == hblink_req['data'][0]['SYSTEM']:
##                                        print(active_tgs[hblink_req['update_tg']][hblink_req['data'][0]['SYSTEM']][0]['1'])
####                                        print(hblink_req['data'][2]['tg'])
##                                        print('---------')
##                                        print(active_tgs[hblink_req['update_tg']][hblink_req['data'][0]['SYSTEM']][1]['2'])
##        ##                                print(hblink_req['data'][1]['ts'])
##                                        if hblink_req['data'][1]['ts'] == 1:
##        ####                                  print(active_tgs[hblink_req['update_tg']][system[0]][0]['1'])
##
##                                            if active_tgs[hblink_req['update_tg']][hblink_req['data'][0]['SYSTEM']][0]['1'] == hblink_req['data'][2]['tg']:
##                                                pass
##                                            else:
##                                                active_tgs[hblink_req['update_tg']][hblink_req['data'][0]['SYSTEM']][0]['1'].append(hblink_req['data'][2]['tg'])
##        ####                                    active_tgs[hblink_req['update_tg']][system[0]][0]['1'].append(0)
##                                        if hblink_req['data'][1]['ts'] == 2:
##                                            if active_tgs[hblink_req['update_tg']][hblink_req['data'][0]['SYSTEM']][1]['2'] == hblink_req['data'][2]['tg']:
##                                                pass
##        ####                                    print(active_tgs[hblink_req['update_tg']][system[0]][1]['2'])
##                                            else:
##                                                active_tgs[hblink_req['update_tg']][hblink_req['data'][0]['SYSTEM']][1]['2'].append(hblink_req['data'][2]['tg'])
##                              else:
##                                  try:
##                                    print('---------on------------')
##                                    print(hblink_req['data'])
##                                    print(active_tgs[hblink_req['update_tg']])
##                                    print(hblink_req['data'][2]['ts2'])
##                                    print('-----------------------')
##        ##                        active_tgs[hblink_req['update_tg']][hblink_req['data'][0]['SYSTEM']][2]['SYSTEM'] = hblink_req['data'][0]['SYSTEM']
##        ####                        active_tgs[hblink_req['update_tg']][hblink_req['dmr_id']].update({hblink_req['data'][0]['SYSTEM']: [{1:[hblink_req['data'][1]['ts1']]}, {2:[hblink_req['data'][2]['ts2']]}]}) #.update({[hblink_req['dmr_id']]:hblink_req['data']})
##                                    if hblink_req['data'][1]['ts1'] not in active_tgs[hblink_req['update_tg']][hblink_req['data'][0]['SYSTEM']][0]['1']:
##                                        active_tgs[hblink_req['update_tg']][hblink_req['data'][0]['SYSTEM']][0]['1'].append(hblink_req['data'][1]['ts1'])
##                                        active_tgs[hblink_req['update_tg']][hblink_req['data'][0]['SYSTEM']][2]['SYSTEM'] = hblink_req['data'][0]['SYSTEM']
##                                    if hblink_req['data'][2]['ts2'] not in active_tgs[hblink_req['update_tg']][hblink_req['data'][0]['SYSTEM']][1]['2']:
##                                        print('---0---')
##                                        print(hblink_req['data'][0]['SYSTEM'])
##                                        active_tgs[hblink_req['update_tg']][hblink_req['data'][0]['SYSTEM']][2]['SYSTEM'] = hblink_req['data'][0]['SYSTEM']
##                                        active_tgs[hblink_req['update_tg']][hblink_req['data'][0]['SYSTEM']][1]['2'].append(hblink_req['data'][2]['ts2'])
####                                        print('append')
##        ####                                    active_tgs[hblink_req['update_tg']][system[0]][1]['2'].append(0)
##        ##                        print(hblink_req['data'][0]['SYSTEM'])
##
##    ##                            print(active_tgs[hblink_req['update_tg']][hblink_req['data'][0]['SYSTEM']])
##    ##                            print(active_tgs[hblink_req['update_tg']][hblink_req['data'][0]['SYSTEM']][2]['2'])
##    ##                            print(hblink_req['data'][1]['ts2'])
##        ##                        print(active_tgs[hblink_req['update_tg']])
##                                  except:
####                                      active_tgs[hblink_req['update_tg']] = {}
##                                      pass
##                                
####                        except:
####                            pass
##
##                            
##                    elif 'off' == hblink_req['mode']:
##                        print('off')
##                        for system in active_tgs[hblink_req['update_tg']].items():
##                            print(system)
##                            if system[0] == hblink_req['data'][0]['SYSTEM']:
##                                print('yes it is')
######                                print(system[0])
######                                print(active_tgs[hblink_req['update_tg']][system[0]])
##                                if hblink_req['data'][1]['ts'] == 1:
######                                    print(active_tgs[hblink_req['update_tg']][system[0]][0]['1'])
##                                    active_tgs[hblink_req['update_tg']][hblink_req['data'][0]['SYSTEM']][0]['1'].remove(hblink_req['data'][2]['tg'])
######                                    active_tgs[hblink_req['update_tg']][system[0]][0]['1'].append(0)
##                                if hblink_req['data'][1]['ts'] == 2:
######                                    print(active_tgs[hblink_req['update_tg']][system[0]][1]['2'])
##                                    active_tgs[hblink_req['update_tg']][hblink_req['data'][0]['SYSTEM']][1]['2'].remove(hblink_req['data'][2]['tg'])
######                                    active_tgs[hblink_req['update_tg']][system[0]][1]['2'].append(0)
##
##                                    
##    
####                            print()
####                            print(system)
####                            print(system[1][2]['SYSTEM'])
####                        print('off')
####                        print(hblink_req['data'][1]['ts'])
####                        print(hblink_req['data'][2]['tg'])
##                print(active_tgs)
##                response = 'got it'
        else:
            message = jsonify(message='Authentication error')
            response = make_response(message, 401)
        return response



    return app


if __name__ == '__main__':
    app = create_app()
    app.run(debug = True, port=hws_port, host=hws_host)
