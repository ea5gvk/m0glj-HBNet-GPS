# HBLink User Managment Server

from flask import Flask, render_template_string, request, make_response, jsonify, render_template, Markup, flash, redirect, url_for, current_app
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


try:
    from gen_script_template import gen_script
except:
    pass

import os, ast
##import hb_config

script_links = {}

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
        username = db.Column(db.String(100, collation='NOCASE'), nullable=False, unique=True)
        password = db.Column(db.String(255), nullable=False, server_default='')
        email_confirmed_at = db.Column(db.DateTime())
        email = db.Column(db.String(255, collation='NOCASE'), nullable=False, unique=True)
        
        # User information
        first_name = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        last_name = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        dmr_ids = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        city = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        notes = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
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
        dmr_id = db.Column(db.Integer(), unique=True, primary_key=True)
        version = db.Column(db.Integer(), primary_key=True)
    class AuthLog(db.Model):
        __tablename__ = 'auth_log'
        login_dmr_id = db.Column(db.Integer(), primary_key=True)
        login_time = db.Column(db.DateTime(), primary_key=True)
        peer_ip = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        server_name = db.Column(db.Integer(), primary_key=True)
        login_auth_method = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        portal_username = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        login_type = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
    class mmdvmPeer(db.Model):
        __tablename__ = 'MMDVM_peers'
        id = db.Column(db.Integer(), primary_key=True)
        name = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        enabled = db.Column(db.Boolean(), nullable=False, server_default='1')
        loose = db.Column(db.Boolean(), nullable=False, server_default='1')
        ip = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='127.0.0.1')
        port = db.Column(db.Integer(), primary_key=False)
        master_ip = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        master_port = db.Column(db.Integer(), primary_key=False)
        passphrase = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        callsign = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        radio_id = db.Column(db.Integer(), primary_key=False)
        rx_freq = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        tx_freq = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        tx_power = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        color_code = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        latitude = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        longitude = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        height = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        location = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        description = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        slots = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        url = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        software_id = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        package_id = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        group_hangtime = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        options = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        use_acl = db.Column(db.Boolean(), nullable=False, server_default='0')
        sub_acl = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        tg1_acl = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        tg2_acl = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        server = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
    class xlxPeer(db.Model):
        __tablename__ = 'XLX_peers'
        id = db.Column(db.Integer(), primary_key=True)
        name = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        enabled = db.Column(db.Boolean(), nullable=False, server_default='1')
        loose = db.Column(db.Boolean(), nullable=False, server_default='1')
        ip = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='127.0.0.1')
        port = db.Column(db.Integer(), primary_key=False)
        master_ip = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        master_port = db.Column(db.Integer(), primary_key=False)
        passphrase = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        callsign = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        radio_id = db.Column(db.Integer(), primary_key=False)
        rx_freq = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        tx_freq = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        tx_power = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        color_code = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        latitude = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        longitude = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        height = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        location = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        description = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        slots = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        url = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        software_id = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        package_id = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        group_hangtime = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        xlxmodule = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        options = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        use_acl = db.Column(db.Boolean(), nullable=False, server_default='0')
        sub_acl = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        tg1_acl = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        tg2_acl = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        server = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
    class ServerList(db.Model):
        __tablename__ = 'server_list'
        name = db.Column(db.String(100, collation='NOCASE'), unique=True, primary_key=True)
        secret = db.Column(db.String(255), nullable=False, server_default='')
        public_list = db.Column(db.Boolean(), nullable=False, server_default='1')
        id = db.Column(db.Integer(), primary_key=False)
        ip = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        port = db.Column(db.Integer(), primary_key=False)
        global_path = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='./')
        global_ping_time = db.Column(db.Integer(), primary_key=False)
        global_max_missed = db.Column(db.Integer(), primary_key=False)
        global_use_acl = db.Column(db.Boolean(), nullable=False, server_default='1')
        global_reg_acl = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='PERMIT:ALL')
        global_sub_acl = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='DENY:1')
        global_tg1_acl = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='PERMIT:ALL')
        global_tg2_acl = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='PERMIT:ALL')
        ai_try_download = db.Column(db.Boolean(), nullable=False, server_default='1')
        ai_path = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='./')
        ai_peer_file = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='peer_ids.json')
        ai_subscriber_file = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='subscriber_ids.json')
        ai_tgid_file = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='talkgroup_ids.json')
        ai_peer_url = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='https://www.radioid.net/static/rptrs.json')
        ai_subs_url = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='https://www.radioid.net/static/users.json')
        ai_stale = db.Column(db.Integer(), primary_key=False, server_default='7')
        # Pull from config file for now
##        um_append_int = db.Column(db.Integer(), primary_key=False, server_default='2')
        um_shorten_passphrase = db.Column(db.Boolean(), nullable=False, server_default='0')
        um_burn_file = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='./burned_ids.txt')
        # Pull from config file for now
##        um_burn_int = db.Column(db.Integer(), primary_key=False, server_default='6')
        report_enable = db.Column(db.Boolean(), nullable=False, server_default='1')
        report_interval = db.Column(db.Integer(), primary_key=False, server_default='60')
        report_port = db.Column(db.Integer(), primary_key=False, server_default='4321')
        report_clients =db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='127.0.0.1')
        unit_time = db.Column(db.Integer(), primary_key=False, server_default='10080')

    class MasterList(db.Model):
        __tablename__ = 'master_list'
        id = db.Column(db.Integer(), primary_key=True)
        name = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        static_positions = db.Column(db.Boolean(), nullable=False, server_default='0')
        repeat = db.Column(db.Boolean(), nullable=False, server_default='1')
        active = db.Column(db.Boolean(), nullable=False, server_default='1')
        max_peers = db.Column(db.Integer(), primary_key=False, server_default='10')
        ip = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        port = db.Column(db.Integer(), primary_key=False)
        enable_um = db.Column(db.Boolean(), nullable=False, server_default='1')
        passphrase = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        group_hang_time = db.Column(db.Integer(), primary_key=False, server_default='5')
        use_acl = db.Column(db.Boolean(), nullable=False, server_default='1')
        reg_acl = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        sub_acl = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        tg1_acl = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        tg2_acl = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        enable_unit = db.Column(db.Boolean(), nullable=False, server_default='1')
        server = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        notes = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')

    class ProxyList(db.Model):
        __tablename__ = 'proxy_list'
        id = db.Column(db.Integer(), primary_key=True)
        name = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        static_positions = db.Column(db.Boolean(), nullable=False, server_default='0')
        repeat = db.Column(db.Boolean(), nullable=False, server_default='1')
        enable_um = db.Column(db.Boolean(), nullable=False, server_default='1')
        passphrase = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        external_proxy = db.Column(db.Boolean(), nullable=False, server_default='0')
        group_hang_time = db.Column(db.Integer(), primary_key=False)
        internal_start_port = db.Column(db.Integer(), primary_key=False)
        internal_stop_port = db.Column(db.Integer(), primary_key=False)
        use_acl = db.Column(db.Boolean(), nullable=False, server_default='1')
        reg_acl = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        sub_acl = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        tg1_acl = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        tg2_acl = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        server = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        notes = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        
    class BridgeRules(db.Model):
        __tablename__ = 'bridge_rules'
        id = db.Column(db.Integer(), primary_key=True)
        bridge_name = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        system_name = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        ts = db.Column(db.Integer(), primary_key=False)
        tg = db.Column(db.Integer(), primary_key=False)
        active = db.Column(db.Boolean(), nullable=False, server_default='1')
        timeout = db.Column(db.Integer(), primary_key=False)
        to_type = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        on = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        off = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        reset = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        server_list = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        description = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        public_list = db.Column(db.Boolean(), nullable=False, server_default='0')

    class ExcludeUnit(db.Model):
        __tablename__ = 'exclude_unit'
        id = db.Column(db.Integer(), primary_key=True)
        system_name = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')
        server = db.Column(db.String(100, collation='NOCASE'), nullable=False, server_default='')


        
       
        


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
                if not user.initial_admin_approved:
                        flash('<strong>You account is waiting for approval from an administrator. See <a href="/help">the Help page</a> for more information. You will receive an email when your account is approved.</strong>', 'success')

                if user:
                    # Log user in
                    safe_next_url = self.make_safe_url(login_form.next.data)
                    return self._do_login_user(user, safe_next_url, login_form.remember_me.data)

            # Render form
            self.prepare_domain_translations()
            template_filename = self.USER_LOGIN_AUTH0_TEMPLATE if self.USER_ENABLE_AUTH0 else self.USER_LOGIN_TEMPLATE
            return render_template(template_filename,
                          form=login_form,
                          login_form=login_form,
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
            notes='Default admin account created during installation.'
        )
        user.roles.append(Role(name='Admin'))
        user.roles.append(Role(name='User'))
        db.session.add(user)
        db.session.commit()

    # Query radioid.net for list of DMR IDs, then add to DB
    @user_registered.connect_via(app)
    def _after_user_registered_hook(sender, user, **extra):
        edit_user = User.query.filter(User.username == user.username).first()
        radioid_data = ast.literal_eval(get_ids(user.username))
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
        print(b_list)
        burned = False
        for ui in b_list.items():
            print(ui)
            #print(b_list)
            if ui[0] == trimmed_id:
                if ui[0] != 0:
                    calc_passphrase = base64.b64encode(bytes.fromhex(str(hex(libscrc.ccitt((_new_peer_id) + b_list[trimmed_id].to_bytes(2, 'big') + burn_int.to_bytes(2, 'big') + append_int.to_bytes(2, 'big') + bytes.fromhex(str(hex(libscrc.posix((_new_peer_id) + b_list[trimmed_id].to_bytes(2, 'big') + burn_int.to_bytes(2, 'big') + append_int.to_bytes(2, 'big'))))[2:].zfill(8)))))[2:].zfill(4)) + (_new_peer_id) + b_list[trimmed_id].to_bytes(2, 'big') + burn_int.to_bytes(2, 'big') + append_int.to_bytes(2, 'big') + bytes.fromhex(str(hex(libscrc.posix((_new_peer_id) + b_list[trimmed_id].to_bytes(2, 'big') + burn_int.to_bytes(2, 'big') + append_int.to_bytes(2, 'big'))))[2:].zfill(8)))
                    burned = True
        if burned == False:
            calc_passphrase = base64.b64encode(bytes.fromhex(str(hex(libscrc.ccitt((_new_peer_id) + append_int.to_bytes(2, 'big') + bytes.fromhex(str(hex(libscrc.posix((_new_peer_id) + append_int.to_bytes(2, 'big'))))[2:].zfill(8)))))[2:].zfill(4)) + (_new_peer_id) + append_int.to_bytes(2, 'big') + bytes.fromhex(str(hex(libscrc.posix((_new_peer_id) + append_int.to_bytes(2, 'big'))))[2:].zfill(8)))
        if use_short_passphrase == True:
            return str(calc_passphrase)[-9:-1]
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
        #content = Markup('<strong>Index</strong>')
        return render_template('index.html') #, markup_content = content)
    
    @app.route('/help')
    def help_page():
        #content = Markup('<strong>Index</strong>')

        return render_template('help.html')

    @app.route('/generate_passphrase/pi-star', methods = ['GET'])
    @login_required
    def gen_pi_star():
        try:
            u = current_user
    ##        print(u.username)
            id_dict = ast.literal_eval(u.dmr_ids)
            #u = User.query.filter_by(username=user).first()
    ##        print(user_id)
    ##        print(request.args.get('mode'))
    ##        if request.args.get('mode') == 'generated':
            content = '''
<table style="width: 800px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td>
<h2 style="text-align: center;"><strong>Pi-Star Instructions</strong></h2>
<p>&nbsp;</p>
<p><strong>1</strong>: Log into your Pi-Star device. <br /><strong>2</strong>: Change to Read-Write mode of the device by issuing the command:<u></u></p>
<pre><u><strong>rpi-rw</strong></u></pre>
<p><strong><br />3a: Change to the root user by issuing the command:<u></u></strong></p>
<pre>sudo su -</pre>
<p><strong><u></u> <br />3b: Now type <u>pwd</u> and verify you get a return indicating you are in the /root directory. If you are in the wrong directory, it is because you're not following the instructions and syntax above! This is a show stopper, and your attempt to load the files correctly, will fail !<br /><br />4: Issue one of the commands below for the chosen DMR ID:</strong></p>
<p>Note: Link can be used only once. To run the script again, simply reload the page and paste a new command into the command line.</p>

'''
            for i in id_dict.items():
                #if i[1] == '':
                link_num = str(random.randint(1,99999999)).zfill(8) + str(time.time()) + str(random.randint(1,99999999)).zfill(8)
                script_links[i[0]] = link_num
                content = content + '''\n
        <p style="text-align: center;">DMR ID: <strong>''' + str(i[0]) + '''</strong>:</p>
        <p style="text-align: center;"><strong><pre>bash <(curl -s "<a href="''' + str(url) + '/get_script?dmr_id=' + str(i[0]) + '&number=' + str(link_num) + '''">''' + str(url) + '/get_script?dmr_id=' + str(i[0]) + '&number=' + str(link_num) + '''</a>")</pre></strong></p>
        <p>&nbsp;</p>
    '''
                #else:
                #    content = content + '''\n<p style="text-align: center;">Error</p>'''
            content = content + '''\n<p><strong> <br />5: When asked for server ports, use the information above to populate the correct fields. <br />6: Reboot your Pi-Star device</strong></p>
</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>'''
        except:
            content = Markup('<strong>No DMR IDs found or other error.</strong>')
        
            
        #return str(content)
        return render_template('flask_user_layout.html', markup_content = Markup(content))
        

    
    @app.route('/generate_passphrase', methods = ['GET'])
    @login_required
    def gen():
        #print(str(gen_passphrase(3153591))) #(int(i[0])))
        try:
            #content = Markup('<strong>The HTML String</strong>')
            #user_id = request.args.get('user_id')
            u = current_user
    ##        print(u.username)
            id_dict = ast.literal_eval(u.dmr_ids)
            #u = User.query.filter_by(username=user).first()
    ##        print(user_id)
    ##        print(request.args.get('mode'))
    ##        if request.args.get('mode') == 'generated':
            #print(id_dict)
            content = '\n'
            for i in id_dict.items():
                if isinstance(i[1], int) == True and i[1] != 0:
                    link_num = str(random.randint(1,99999999)).zfill(8) + str(time.time()) + str(random.randint(1,99999999)).zfill(8)
                    script_links[i[0]] = link_num
                    #print(script_links)
                    content = content + '''\n
<table style="width: 300px;" border="1">
<tbody>
<tr>
<td>
            <p style="text-align: center;">Your passphrase for <strong>''' + str(i[0]) + '''</strong>:</p>
            <p style="text-align: center;">Copy and paste: <strong>''' + str(gen_passphrase(int(i[0]))) + '''</strong></p>
<hr />

            <p style="text-align: center;">Phonetically spelled: <span style="text-decoration: underline;"><em>''' + convert_nato(str(gen_passphrase(int(i[0])))) + '''</em></span></p>

</td>
</tr>
</tbody>
</table>
            <p>&nbsp;</p>
        '''
                elif i[1] == 0:
                    link_num = str(random.randint(1,99999999)).zfill(8) + str(time.time()) + str(random.randint(1,99999999)).zfill(8)
                    script_links[i[0]] = link_num
                    #print(script_links)
                    content = content + '''\n
<table style="width: 300px;" border="1">
<tbody>
<tr>
<td>
            <p style="text-align: center;">Your passphrase for <strong>''' + str(i[0]) + '''</strong>:</p>
            <p style="text-align: center;">Copy and paste: <strong>''' + str(gen_passphrase(int(i[0]))) + '''</strong></p>
<hr />

            <p style="text-align: center;">Phonetically spelled: <span style="text-decoration: underline;"><em>''' + convert_nato(str(gen_passphrase(int(i[0])))) + '''</em></span></p>

</td>
</tr>
</tbody>
</table>
            <p>&nbsp;</p>
        '''
                elif i[1] == '':
                    content = content + '''
<table style="width: 300px;" border="1">
<tbody>
<tr>
<td>
<p style="text-align: center;">Your passphrase for <strong>''' + str(i[0]) + '''</strong>:</p>
<p style="text-align: center;">Copy and paste: <strong>''' + legacy_passphrase + '''</strong></p>
<hr />
<p style="text-align: center;">Phonetically spelled: <span style="text-decoration: underline;"><em>''' + convert_nato(legacy_passphrase) + '''</em></span></p>
</td>
</tr>
</tbody>
</table>
            <p>&nbsp;</p>'''
                else:
                    content = content + '''
<table style="width: 300px;" border="1">
<tbody>
<tr>
<td>
<p style="text-align: center;">Your passphrase for <strong>''' + str(i[0]) + '''</strong>:</p>
<p style="text-align: center;">Copy and paste: <strong>''' + str(i[1]) + '''</strong></p>
<hr />
<p style="text-align: center;">Phonetically spelled: <span style="text-decoration: underline;"><em>''' + convert_nato(str(i[1])) + '''</em></span></p>
</td>
</tr>
</tbody>
</table>
            <p>&nbsp;</p>
'''
            #content = content + '\n\n' + str(script_links[i[0]])
        except:
            content = Markup('<strong>No DMR IDs found or other error.</strong>')
        
            
        #return str(content)
        return render_template('view_passphrase.html', markup_content = Markup(content))

##    # The Members page is only accessible to authenticated users via the @login_required decorator
##    @app.route('/members')
##    @login_required    # User must be authenticated
##    def member_page():
##        content = 'Mem only'
##        return render_template('flask_user_layout.html', markup_content = content)
    
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
<p>Updating your information from <a href="https://www.radioid.net/">RadioID.net</a> will <strong>overwrite any custom authentication passphrases</strong>, your city, and name in the database. Are you sure you want to continue?</p>
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
        wait_list = '''<h2 style="text-align: center;"><strong>Users waiting for approval:</strong></h2><p>&nbsp;</p><table style="width: 700px; margin-left: auto; margin-right: auto;" border="1">
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
            msg = Message(recipients=[edit_user.email],
                          subject='Account Approval - ' + title,
                          body='''You are receiving this message because an administrator has approved your account. You may now login and view your MMDVM passphrase(s).''')
            mail.send(msg)
            content = '''<p style="text-align: center;">User approved: <strong>''' + str(request.args.get('callsign')) + '''</strong></p>\n'''
            
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
                print(i[1])
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
<td>&nbsp;''' + confirm_link + '''&nbsp; <br /><p style="text-align: center;"><strong>Email confirmed: ''' + str(u.email_confirmed_at) + '''</strong></p></td>
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
  <input type="text" id="email" name="email" value="''' + u.email + '''"><br>
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
        #print(u.dmr_ids)

        if authorized_peer(dmr_id)[1] == 0:
            passphrase = gen_passphrase(dmr_id)
        elif authorized_peer(dmr_id)[1] != 0 and isinstance(authorized_peer(dmr_id)[1], int) == True:
            passphrase = gen_passphrase(dmr_id)
        elif authorized_peer(dmr_id)[1] == '':
            passphrase = legacy_passphrase
            print(passphrase)
        elif authorized_peer(dmr_id)[1] != '' or authorized_peer(dmr_id)[1] != 0:
            passphrase = authorized_peer(dmr_id)[1]
        #try:
        if dmr_id in script_links and number == float(script_links[dmr_id]):
            script_links.pop(dmr_id)
            return str(gen_script(dmr_id, passphrase))
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
                a = AuthLog.query.filter_by(portal_username=request.args.get('portal_username')).order_by(AuthLog.login_time.desc()).all()
                g_arg = request.args.get('portal_username')
                f_link = '''    <p style="text-align: center;"><strong><a href="auth_log?flush_user_db=true&portal_username=''' + request.args.get('portal_username') + '''">Flush auth log for: ''' + request.args.get('portal_username') + '''</a></strong></p>'''
            elif request.args.get('dmr_id'):
##                s_filter = login_dmr_id=request.args.get('dmr_id')
                a = AuthLog.query.filter_by(login_dmr_id=request.args.get('dmr_id')).order_by(AuthLog.login_time.desc()).all()
                g_arg = request.args.get('dmr_id')
                f_link = '''<p style="text-align: center;"><strong><a href="auth_log?flush_dmr_id_db=true&dmr_id=''' + request.args.get('dmr_id') + '''">Flush auth log for: ''' + request.args.get('dmr_id') + '''</a></strong></p>'''
##            print(s_filter)
##            a = AuthLog.query.filter_by(s_filter).order_by(AuthLog.login_dmr_id.desc()).all()

            content = '''
    <p>&nbsp;</p>
    <p style="text-align: center;"><strong>Log for: ''' + g_arg + '''</strong></p>

    ''' + f_link + '''
    
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
    <td style="text-align: center;">&nbsp;<a href=auth_log?portal_username="''' + i.portal_username + '''">''' + i.portal_username + '''</a>&nbsp;</td>
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
    <p style="text-align: center;"><strong><a href="auth_log?flush_db_mmdvm=true&mmdvm_server=''' + request.args.get('mmdvm_server') + '''">Flush authentication log for server: ''' + request.args.get('mmdvm_server') + '''</a></strong></p>
    <p style="text-align: center;"><strong>Log for MMDVM server: ''' + request.args.get('mmdvm_server') + '''</strong></p>

    
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
    <p style="text-align: center;"><strong><a href="auth_log?flush_db_ip=true&peer_ip=''' + request.args.get('peer_ip') + '''">Flush authentication log for IP: ''' + request.args.get('peer_ip') + '''</a></strong></p>
    <p style="text-align: center;"><strong>Log for IP address: ''' + request.args.get('peer_ip') + '''</strong></p>

    
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
    <p style="text-align: center;"><strong><a href="auth_log?flush_db=true">Flush entire authentication log</a></strong></p>
    <p style="text-align: center;"><strong><a href="auth_log?portal_username=Not Registered">Un-registered authentication attempts</a></strong></p>
    <p style="text-align: center;"><strong>Authentication log by DMR ID</strong></p>

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


    @app.route('/test')
    def test_peer():
        #user = User(
       #     username='admin3',
       #     email_confirmed_at=datetime.datetime.utcnow(),
       #     password=user_manager.hash_password('admin'),
       # )
        #user.roles.append(Role(name='Admin'))
        #user.roles.append(Role(name='User'))
        #user.add_roles('Admin')
        #db.session.add(user)
        #db.session.commit()
        u = User.query.filter_by(username='kf7eel').first()
        #u = Role.query.all()
##        u = User.query.filter(User.dmr_ids.contains('3153591')).first()
        #u = User.query.all()
##        #tu = User.query().all()
####        print((tu.dmr_ids))
####        #print(tu.dmr_ids)
####        return str(tu.dmr_ids) #str(get_ids('kf7eel'))
##        login_passphrase = ast.literal_eval(u.dmr_ids)
##        print('|' + login_passphrase[3153591] + '|')
##        #print(u.dmr_ids)
##        #tu.dmr_ids = 'jkgfldj'
##        #db.session.commit()
##        return str(u.dmr_ids)
##        u = User.query.filter(User.dmr_ids.contains('3153591')).first()
##        #tu = User.query.all()
##        #tu = User.query().all()
####        print((tu.dmr_ids))
####        #print(tu.dmr_ids)
####        return str(tu.dmr_ids) #str(get_ids('kf7eel'))
##        print(u)
##        login_passphrase = ast.literal_eval(u.dmr_ids)
##        
##        #tu.dmr_ids = 'jkgfldj'
##        #db.session.commit()
##        return str([u.is_active, login_passphrase[3153591]])
        #edit_user = User.query.filter(User.username == 'bob').first()
        #edit_user.active = False
        
        #db.session.commit()
        #print((current_user.has_roles('Admin')))
        #u.roles.append(Role(name='Admin'))
        #print((current_user.has_roles('Admin')))
        #db.session.commit()
        #db.session.add(u)
        #db.session.commit()
##        admin_role = UserRoles(
##            user_id=3,
##            role_id=1,
##            )
##        user_role = UserRoles(
##            user_id=3,
##            role_id=2,
##            )
##        db.session.add(user_role)
##        db.session.add(admin_role)
##        db.session.commit()
        #print(role)
##        for i in u:
##            print(i.username)
        #u = User.query.filter_by(username='kf7eel').first()
        #print(u.id)
        #u_role = UserRoles.query.filter_by(user_id=u.id).first()
        #if u_role.role_id == 2:
        #    print('userhasjkdhfdsejksfdahjkdhjklhjkhjkl')
##        print(u.has_roles('Admin'))
        #u_role.role_id = 1
        #print(u)
       # for i in u:
            ##print(i.initial_admin_approved)
            #if not i.initial_admin_approved:
                #print(i.username)
        #    print(i)
        #u_role = UserRoles.query.filter_by(id=2).first().role_id
        #u_role = 1
       # db.session.commit()
        #u_role = UserRoles.query.filter_by(id=u.id).first().role_id
        #print(u_role)
        #return str(u)
##        if not u.active:
##            flash('We come in peace', 'success')
##        content = 'hello'
       #add
##        burn_list = BurnList(
##            dmr_id=3153595,
##            version=1,
##            )
##        db.session.add(burn_list)
##        db.session.commit()
##
       #generate dict
##        b = BurnList.query.all()
##        print(b)
##        burn_dict = {}
##        for i in b:
##            print(i.dmr_id)
##            burn_dict[i.dmr_id] = i.version
##        content = burn_dict
##        # delete
####        delete_b = BurnList.query.filter_by(dmr_id=3153591).first()
####        db.session.delete(delete_b)
####        db.session.commit()
##        a = AuthLog.query.all()
##        print(a)
##        authlog_flush()
        peer_delete('mmdvm', 1)
        return render_template('flask_user_layout.html', markup_content = Markup(content))
    
    def get_peer_configs(_server_name):
        mmdvm_pl = mmdvmPeer.query.filter_by(server=_server_name).all()
        xlx_pl = xlxPeer.query.filter_by(server=_server_name).all()
##        print(mmdvm_pl)
        peer_config_list = {}
        for i in mmdvm_pl:
##            print(i)
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
                        'PASSPHRASE': bytes((i.passphrase), 'utf-8'),
                        'CALLSIGN': bytes((i.callsign).ljust(8)[:8], 'utf-8'),
                        'RADIO_ID': int(i.radio_id), #int(i.radio_id).to_bytes(4, 'big'),
                        'RX_FREQ': bytes((i.rx_freq).ljust(9)[:9], 'utf-8'),
                        'TX_FREQ': bytes((i.tx_freq).ljust(9)[:9], 'utf-8'),
                        'TX_POWER': bytes((i.tx_power).rjust(2,'0'), 'utf-8'),
                        'COLORCODE': bytes((i.color_code).rjust(2,'0'), 'utf-8'),
                        'LATITUDE': bytes((i.latitude).ljust(8)[:8], 'utf-8'),
                        'LONGITUDE': bytes((i.longitude).ljust(9)[:9], 'utf-8'),
                        'HEIGHT': bytes((i.height).rjust(3,'0'), 'utf-8'),
                        'LOCATION': bytes((i.location).ljust(20)[:20], 'utf-8'),
                        'DESCRIPTION': bytes((i.description).ljust(19)[:19], 'utf-8'),
                        'SLOTS': bytes((i.slots), 'utf-8'),
                        'URL': bytes((i.url).ljust(124)[:124], 'utf-8'),
                        'SOFTWARE_ID': bytes((i.software_id).ljust(40)[:40], 'utf-8'),
                        'PACKAGE_ID': bytes((i.package_id).ljust(40)[:40], 'utf-8'),
                        'GROUP_HANGTIME': i.group_hangtime,
                        'OPTIONS':  b''.join([b'Type=HBlink;', bytes(i.options, 'utf-8')]),
                        'USE_ACL': i.use_acl,
                        'SUB_ACL': i.sub_acl,
                        'TG1_ACL': i.tg1_acl,
                        'TG2_ACL': i.tg2_acl
                    }})
            for i in xlx_pl:
                            peer_config_list.update({i: {
                        'MODE': 'XLX',
                        'ENABLED': i.enabled,
                        'LOOSE': i.loose,
                        'SOCK_ADDR': (gethostbyname(i.ip), i.port),
                        'IP': i.ip,
                        'PORT': i.port,
                        'MASTER_SOCKADDR': (gethostbyname(i.master_ip), i.master_port),
                        'MASTER_IP': i.master_ip,
                        'MASTER_PORT': i.master_port,
                        'PASSPHRASE': bytes((i.passphrase), 'utf-8'),
                        'CALLSIGN': bytes((i.callsign).ljust(8)[:8], 'utf-8'),
                        'RADIO_ID': int(i.radio_id),
                        'RX_FREQ': bytes((i.rx_freq).ljust(9)[:9], 'utf-8'),
                        'TX_FREQ': bytes((i.tx_freq).ljust(9)[:9], 'utf-8'),
                        'TX_POWER': bytes((i.tx_power).rjust(2,'0'), 'utf-8'),
                        'COLORCODE': bytes((i.color_code).rjust(2,'0'), 'utf-8'),
                        'LATITUDE': bytes((i.latitude).ljust(8)[:8], 'utf-8'),
                        'LONGITUDE': bytes((i.longitude).ljust(9)[:9], 'utf-8'),
                        'HEIGHT': bytes((i.height).rjust(3,'0'), 'utf-8'),
                        'LOCATION': bytes((i.location).ljust(20)[:20], 'utf-8'),
                        'DESCRIPTION': bytes((i.description).ljust(19)[:19], 'utf-8'),
                        'SLOTS': bytes((i.slots), 'utf-8'),
                        'URL': bytes((i.url).ljust(124)[:124], 'utf-8'),
                        'SOFTWARE_ID': bytes((i.software_id).ljust(40)[:40], 'utf-8'),
                        'PACKAGE_ID': bytes((i.package_id).ljust(40)[:40], 'utf-8'),
                        'GROUP_HANGTIME': i.group_hangtime,
                        'XLXMODULE': i.xlxmodule,
                        'OPTIONS':  b''.join([b'Type=HBlink;', bytes(i.options, 'utf-8')]),
                        'USE_ACL': i.use_acl,
                        'SUB_ACL': i.sub_acl,
                        'TG1_ACL': i.tg1_acl,
                        'TG2_ACL': i.tg2_acl
                    }})
            print((peer_config_list))
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

    def server_delete(_name):
        s = ServerList.query.filter_by(name=_name).first()
        db.session.delete(s)
        db.session.commit()
    def peer_delete(_mode, _server, _name):
        if _mode == 'mmdvm':
            p = mmdvmPeer.query.filter_by(server=_server).filter_by(name=_name).first()
        if _mode == 'xlx':
            p = xlxPeer.query.filter_by(server=_server).filter_by(name=_name).first()
        db.session.delete(p)
        db.session.commit()

    def shared_secrets():
        s = ServerList.query.all() #filter_by(name=_name).first()
        r_list = []
        for i in s:
            r_list.append(str(i.secret))
        return r_list

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
        s_config['USER_MANAGER'] = {}

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
        s_config['USER_MANAGER'].update({
                    'APPEND_INT': append_int,
                    'SHORTEN_PASSPHRASE': i.um_shorten_passphrase,
                    'BURN_FILE': i.um_burn_file,
                    'BURN_INT': burn_int,


                })
        print(s_config['REPORTS'])
        return s_config
    def masters_get(_name):
##        print(_name)
        #s = ServerList.query.filter_by(name=_name).first()
       # print(s.name)        
        i = MasterList.query.filter_by(server=_name).all()
        print('get masters')
        master_config_list = {}
##        master_config_list['SYSTEMS'] = {}
        print(i)
        for m in i:
            print (m.name)
            master_config_list.update({m.name: {
                'MODE': 'MASTER',
                'ENABLED': m.active,
                'STATIC_APRS_POSITION_ENABLED': m.static_positions,
                'REPEAT': m.repeat,
                'MAX_PEERS': m.max_peers,
                'IP': m.ip,
                'PORT': m.port,
                'PASSPHRASE': bytes(m.passphrase, 'utf-8'),
                'GROUP_HANGTIME': m.group_hang_time,
                'USE_ACL': m.use_acl,
                'REG_ACL': m.reg_acl,
                'SUB_ACL': m.sub_acl,
                'TG1_ACL': m.tg1_acl,
                'TG2_ACL': m.tg2_acl
            }})
            master_config_list[m.name].update({'PEERS': {}})
        print(master_config_list)
        return master_config_list
##        print(i.name)
##        s_config = {}
##        s_config['GLOBAL'] = {}
##        s_config['REPORTS'] = {}
##        s_config['ALIASES'] = {}
##        s_config['USER_MANAGER'] = {}
##
##        s_config['GLOBAL'].update({
##                    'PATH': i.global_path,
##                    'PING_TIME': i.global_ping_time,
##                    'MAX_MISSED': i.global_max_missed,
##                    'USE_ACL': i.global_use_acl,
##                    'REG_ACL': i.global_reg_acl,
##                    'SUB_ACL': i.global_sub_acl,
##                    'TG1_ACL': i.global_tg1_acl,
##                    'TG2_ACL': i.global_tg2_acl
##                })
##        
##        s_config['REPORTS'].update({
##                    'REPORT': i.report_enable,
##                    'REPORT_INTERVAL': i.report_interval,
##                    'REPORT_PORT': i.report_port,
##                    'REPORT_CLIENTS': i.report_clients.split(',')
##                })
##        s_config['ALIASES'].update({
##                    'TRY_DOWNLOAD':i.ai_try_download,
##                    'PATH': i.ai_path,
##                    'PEER_FILE': i.ai_peer_file,
##                    'SUBSCRIBER_FILE': i.ai_subscriber_file,
##                    'TGID_FILE': i.ai_tgid_file,
##                    'PEER_URL': i.ai_peer_url,
##                    'SUBSCRIBER_URL': i.ai_subs_url,
##                    'STALE_TIME': i.ai_stale * 86400,
##                })
##        s_config['USER_MANAGER'].update({
##                    'APPEND_INT': append_int,
##                    'SHORTEN_PASSPHRASE': i.um_shorten_passphrase,
##                    'BURN_FILE': i.um_burn_file,
##                    'BURN_INT': burn_int,
##
##
##                })
##        print(s_config['REPORTS'])
##        return s_config

    def server_edit(_name, _secret, _ip, _public_list, _port, _global_path, _global_ping_time, _global_max_missed, _global_use_acl, _global_reg_acl, _global_sub_acl, _global_tg1_acl, _global_tg2_acl, _ai_subscriber_file, _ai_try_download, _ai_path, _ai_peer_file, _ai_tgid_file, _ai_peer_url, _ai_subs_url, _ai_stale, _um_shorten_passphrase, _um_burn_file, _report_enable, _report_interval, _report_port, _report_clients, _unit_time):
        s = ServerList.query.filter_by(name=_name).first()
        print(_name)
        if _secret == '':
            s.secret = s.secret
        else:
            s.secret = hashlib.sha256(_secret.encode()).hexdigest()
        s.public_list = _public_list
        s.ip = _ip
        s.port = _port
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
        db.session.commit()
        
    def master_delete(_mode, _server, _name):
        if _mode == 'MASTER':
            m = MasterList.query.filter_by(server=_server).filter_by(name=_name).first()
        if _mode == 'PROXY':
            m = ProxyList.query.filter_by(server=_server).filter_by(name=_name).first()
        db.session.delete(m)
        db.session.commit()

    def edit_master(_mode, _name, _server, _static_positions, _repeat, _active, _max_peers, _ip, _port, _enable_um, _passphrase, _group_hang_time, _use_acl, _reg_acl, _sub_acl, _tg1_acl, _tg2_acl, _enable_unit, _notes, _external_proxy, _int_start_port, _int_stop_port):
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
            db.session.commit()
            add_proxy = ProxyList(
                name = _name,
                static_positions = _static_positions,
                repeat = _repeat,
                active = _active,
                enable_um = _enable_um,
                passphrase = _passphrase,
                external_proxy = _external_proxy,
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
                notes = _notes
                )
            db.session.add(add_master)
            db.session.commit()

    def add_master(_mode, _name, _server, _static_positions, _repeat, _active, _max_peers, _ip, _port, _enable_um, _passphrase, _group_hang_time, _use_acl, _reg_acl, _sub_acl, _tg1_acl, _tg2_acl, _enable_unit, _notes, _external_proxy, _int_start_port, _int_stop_port):
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
                notes = _notes
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
                notes = _notes
                )
            db.session.add(add_master)
            db.session.commit()

        
    def server_add(_name, _secret, _ip, _public_list, _port, _global_path, _global_ping_time, _global_max_missed, _global_use_acl, _global_reg_acl, _global_sub_acl, _global_tg1_acl, _global_tg2_acl, _ai_subscriber_file, _ai_try_download, _ai_path, _ai_peer_file, _ai_tgid_file, _ai_peer_url, _ai_subs_url, _ai_stale, _um_shorten_passphrase, _um_burn_file, _report_enable, _report_interval, _report_port, _report_clients, _unit_time):
        add_server = ServerList(
        name = _name,
        secret = hashlib.sha256(_secret.encode()).hexdigest(),
        public_list = _public_list,
        ip = _ip,
        port = _port,
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
        unit_time = int(_unit_time)
        )
        db.session.add(add_server)
        db.session.commit()
    def peer_add(_mode, _name, _enabled, _loose, _ip, _port, _master_ip, _master_port, _passphrase, _callsign, _radio_id, _rx, _tx, _tx_power, _cc, _lat, _lon, _height, _loc, _desc, _slots, _url, _grp_hang, _xlx_mod, _opt, _use_acl, _sub_acl, _1_acl, _2_acl, _svr):
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
                    software_id = 'HBNet',
                    package_id = 'v1',
                    group_hangtime = _grp_hang,
                    use_acl = _use_acl,
                    sub_acl = _sub_acl,
                    tg1_acl = _1_acl,
                    tg2_acl = _2_acl,
                    server = _svr
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
                    software_id = 'HBNet',
                    package_id = 'v1',
                    group_hangtime = _grp_hang,
                    use_acl = _use_acl,
                    sub_acl = _sub_acl,
                    tg1_acl = _1_acl,
                    tg2_acl = _2_acl,
                    server = _svr
                        )
            db.session.add(mmdvm_peer_add)
            db.session.commit()
    def peer_edit(_mode, _server, _name, _enabled, _loose, _ip, _port, _master_ip, _master_port, _passphrase, _callsign, _radio_id, _rx, _tx, _tx_power, _cc, _lat, _lon, _height, _loc, _desc, _slots, _url, _grp_hang, _xlx_mod, _opt, _use_acl, _sub_acl, _1_acl, _2_acl):
##        print(_mode)
        if _mode == 'mmdvm':
##            print(_server)
##            print(_name)
##            print(_name)
##            s = mmdvmPeer.query.filter_by(server=_server).filter_by(name=_name).first()
            p = mmdvmPeer.query.filter_by(server=_server).filter_by(name=_name).first()
            print(p)
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
            p.software_id = 'HBNet'
            p.package_id = 'v1'
            p.group_hangtime = _grp_hang
            p.use_acl = _use_acl
            p.sub_acl = _sub_acl
            p.tg1_acl = _1_acl
            p.tg2_acl = _2_acl
        db.session.commit()
            
            


# Test server configs

    @app.route('/manage_servers', methods=['POST', 'GET'])
    @login_required
    @roles_required('Admin')
    def edit_server_db():
        # Edit server
        if request.args.get('save_mode'):# == 'new' and request.form.get('server_name'):
            _port = int(request.form.get('server_port'))
            _global_ping_time = int(request.form.get('ping_time'))
            _global_max_missed = int(request.form.get('max_missed'))
            _ai_stale = int(request.form.get('stale_days'))
            _report_interval = int(request.form.get('report_interval'))
            _report_port = int(request.form.get('report_port'))
            if request.form.get('use_acl') == 'True':
                _global_use_acl = True
            if request.form.get('aliases_enabled') == 'True':
                _ai_try_download = True
            if request.form.get('um_shorten_passphrase') == 'True':
                _um_shorten_passphrase = True
            if request.form.get('report') == 'True':
                _report_enabled = True
            if  request.form.get('public_list') == 'True':
                public_list = True
            else:
                _global_use_acl = False
                _ai_try_download = False
                _um_shorten_passphrase = False
                _report_enabled = False
                public_list = False

            if request.args.get('save_mode') == 'new':
                print(request.form.get('unit_time'))
                server_add(request.form.get('server_name'), request.form.get('server_secret'), request.form.get('server_ip'), public_list, _port, request.form.get('global_path'), _global_ping_time, _global_max_missed, _global_use_acl, request.form.get('reg_acl'), request.form.get('sub_acl'), request.form.get('global_ts1_acl'), request.form.get('global_ts2_acl'), request.form.get('sub_file'), _ai_try_download, request.form.get('aliases_path'), request.form.get('peer_file'), request.form.get('tgid_file'), request.form.get('peer_url'), request.form.get('sub_url'), _ai_stale, _um_shorten_passphrase, request.form.get('um_burn_file'), _report_enabled, _report_interval, _report_port, request.form.get('report_clients'), request.form.get('unit_time'))
                content = 'attempt save'
            if request.args.get('save_mode') == 'edit':
##                print(request.args.get('server'))
                server_edit(request.args.get('server'), request.form.get('server_secret'), request.form.get('server_ip'), public_list, _port, request.form.get('global_path'), _global_ping_time, _global_max_missed, _global_use_acl, request.form.get('reg_acl'), request.form.get('sub_acl'), request.form.get('global_ts1_acl'), request.form.get('global_ts2_acl'), request.form.get('sub_file'), _ai_try_download, request.form.get('aliases_path'), request.form.get('peer_file'), request.form.get('tgid_file'), request.form.get('peer_url'), request.form.get('sub_url'), _ai_stale, _um_shorten_passphrase, request.form.get('um_burn_file'), _report_enabled, _report_interval, _report_port, request.form.get('report_clients'), request.form.get('unit_time'))
                content = 'attempt edit save'
        elif request.args.get('delete_server'):
            server_delete(request.args.get('delete_server'))
            content = 'deleted server'
            content = 'deleted ' + request.args.get('delete_server')
        elif request.args.get('edit_server'):
            s = ServerList.query.filter_by(name=request.args.get('edit_server')).first()
            
            content = '''
<p style="text-align: center;">&nbsp;</p>

<p style="text-align: center;"><strong><a href="manage_servers?delete_server=''' + str(s.name) + '''">Delete server</a></strong></p>

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
<td style="width: 16.0381%;"><strong>&nbsp;Host (IP/DNS, for listing on passphrase page):</strong></td>
<td style="width: 78.7895%;">&nbsp;<input name="server_ip" type="text" value="''' + str(s.ip) + '''"/></td>
</tr>
<tr>
<td style="width: 16.0381%;"><strong>&nbsp;Port (for listing on passphrase page):</strong></td>
<td style="width: 78.7895%;">&nbsp;<input name="server_port" type="text" value="''' + str(s.port) + '''"/></td>
</tr>
<tr>
<td style="width: 16.0381%;"><strong>&nbsp;Unit Call Timeout (minutes):</strong></td>
<td style="width: 78.7895%;">&nbsp;<input name="unit_time" type="text" value="''' + str(s.unit_time) + '''"/></td>
</tr>
<tr>
<td><strong>&nbsp;Public list:</strong></td>
<td>&nbsp;<select name="public_list">
<option selected="selected" value="''' + str(s.public_list) + '''">Current: ''' + str(s.public_list) + '''</option>
<option value="False">False</option>
<option value="True">True</option>

</select></td>
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
<option selected="selected" value="''' + str(s.report_enable) + '''">Current: ''' + str(s.report_enable) + '''</option>
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
<td style="width: 16.0381%;"><strong>&nbsp;Host (IP/DNS):</strong></td>
<td style="width: 78.7895%;">&nbsp;<input name="server_ip" type="text" /></td>
</tr>
<tr>
<td style="width: 16.0381%;"><strong>&nbsp;Port:</strong></td>
<td style="width: 78.7895%;">&nbsp;<input name="server_port" type="text" value="62032"/></td>
</tr>
<tr>
<td style="width: 16.0381%;"><strong>&nbsp;Unit Call Timeout (minutes):</strong></td>
<td style="width: 78.7895%;">&nbsp;<input name="unit_time" type="text" value="10080"/></td>
</tr>
<tr>
<td><strong>&nbsp;Public list:</strong></td>
<td>&nbsp;<select name="public_list">
<option selected="selected" value="True">True</option>
<option value="False">False</option>
</select></td>
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

<table style="width: 400px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<td style="text-align: center;"><h5><strong>Name</strong><h5></td>
'''
            for s in all_s:
                p_list = p_list + '''
<tr>
<td style="text-align: center;"><a href="manage_servers?edit_server=''' + str(s.name) + '''"><strong>''' + str(s.name) + '''</strong></a></td>
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
            else:
##                peer_loose = False
                peer_enabled = False
                use_acl = False
            peer_loose = True
            if request.args.get('save_mode') == 'mmdvm_peer':
                peer_add('mmdvm', request.form.get('name_text'), peer_enabled, peer_loose, request.form.get('ip'), request.form.get('port'), request.form.get('master_ip'), request.form.get('master_port'), request.form.get('passphrase'), request.form.get('callsign'), request.form.get('radio_id'), request.form.get('rx'), request.form.get('tx'), request.form.get('tx_power'), request.form.get('cc'), request.form.get('lat'), request.form.get('lon'), request.form.get('height'), request.form.get('location'), request.form.get('description'), request.form.get('slots'), request.form.get('url'), request.form.get('group_hangtime'), 'MMDVM', request.form.get('options'), use_acl, request.form.get('sub_acl'), request.form.get('tgid_ts1_acl'), request.form.get('tgid_ts2_acl'), request.form.get('server'))
                content = 'saved mmdvm peer'
            if request.args.get('save_mode') == 'xlx_peer':
                peer_add('xlx', request.form.get('name_text'), peer_enabled, peer_loose, request.form.get('ip'), request.form.get('port'), request.form.get('master_ip'), request.form.get('master_port'), request.form.get('passphrase'), request.form.get('callsign'), request.form.get('radio_id'), request.form.get('rx'), request.form.get('tx'), request.form.get('tx_power'), request.form.get('cc'), request.form.get('lat'), request.form.get('lon'), request.form.get('height'), request.form.get('location'), request.form.get('description'), request.form.get('slots'), request.form.get('url'), request.form.get('group_hangtime'), request.form.get('xlxmodule'), request.form.get('options'), use_acl, request.form.get('sub_acl'), request.form.get('tgid_ts1_acl'), request.form.get('tgid_ts2_acl'), request.form.get('server'))
                content = 'saved xlx peer'
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
<td style="width: 175.567px;"><strong>&nbsp;Use ACLs:</strong></td>
<td style="width: 399.433px;">&nbsp;<select name="use_acl">
<option selected="selected" value="true">True</option>
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
</tbody>
</table>
<p>&nbsp;</p>
<p style="text-align: center;"><input type="submit" value="Save" /></p></form>
'''

##        elif request.args.get('edit_server') and request.args.get('edit_peer') and request.args.get('mode') == 'mmdvm':
        elif request.args.get('delete_peer') and request.args.get('peer_server'):
            print(request.args.get('peer_server'))
            print(request.args.get('delete_peer'))
            peer_delete(request.args.get('mode'), request.args.get('peer_server'), request.args.get('delete_peer'))
            content = 'deleted peer'
        elif request.args.get('edit_mmdvm') == 'save':
##            print(request.form.get('enabled'))
            peer_enabled = False
            use_acl = False
            peer_loose = True
            if request.form.get('enabled') == 'true':
                peer_enabled = True
                print(request.form.get('enabled'))
                print('set to true')
##            if request.form.get('loose') == 'true':
##                peer_loose = True
            if request.form.get('use_acl') == 'True':
                use_acl = True
##            else:
##                peer_loose = False
##            print(peer_enabled)
            print(request.args.get('server'))
            print(request.args.get('name'))
            peer_edit('mmdvm', request.args.get('server'), request.args.get('name'), peer_enabled, peer_loose, request.form.get('ip'), request.form.get('port'), request.form.get('master_ip'), request.form.get('master_port'), request.form.get('passphrase'), request.form.get('callsign'), request.form.get('radio_id'), request.form.get('rx'), request.form.get('tx'), request.form.get('tx_power'), request.form.get('cc'), request.form.get('lat'), request.form.get('lon'), request.form.get('height'), request.form.get('location'), request.form.get('description'), request.form.get('slots'), request.form.get('url'), request.form.get('group_hangtime'), 'MMDVM', request.form.get('options'), use_acl, request.form.get('sub_acl'), request.form.get('tgid_ts1_acl'), request.form.get('tgid_ts2_acl'))
            content = 'save edit'
        elif request.args.get('server') and request.args.get('peer_name') and request.args.get('mode'): # and request.args.get('edit_peer') and request.args.get('mode') == 'mmdvm':
            if request.args.get('mode') == 'mmdvm':
                p = mmdvmPeer.query.filter_by(server=request.args.get('server')).filter_by(name=request.args.get('peer_name')).first()
                xlx_module = ''
                mode = "MMDVM"
            if request.args.get('mode') == 'xlx':
                p = xlxPeer.query.filter_by(server=request.args.get('server')).filter_by(name=request.args.get('peer_name')).first()
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

<form action="manage_peers?edit_mmdvm=save&server=''' + str(p.server) + '''&name=''' + str(p.name) + '''" method="post">
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
                print(s.name)
                p_list = p_list + '''
<h4 style="text-align: center;">Server: ''' + str(s.name) + '''</h4>
<table style="width: 400px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td style="text-align: center;"><strong>Name</strong></td>
<td style="text-align: center;"><strong>Mode</strong></td>
</tr>\n
'''
                all_p = mmdvmPeer.query.filter_by(server=s.name).all()
                all_x = xlxPeer.query.filter_by(server=s.name).all()
                for p in all_p:
                    p_list = p_list + '''
<tr>
<td><a href="manage_peers?server=''' + str(s.name) + '''&amp;peer_name=''' + str(p.name) + '''&mode=mmdvm">''' + str(p.name) + '''</a></td>
<td>MMDVM</td>
</tr>\n
'''
                for x in all_x:
                    p_list = p_list + '''
<tr>
<td><a href="manage_peers?server=''' + str(x.server) + '''&amp;peer_name=''' + str(x.name) + '''&mode=xlx">''' + str(x.name) + '''</a></td>
<td>XLX</td>
</tr>\n
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
    def manage_masters():
        if request.args.get('master_save'):
            aprs_pos = False
            repeat = False
            active = False
            use_acl = False
            enable_um = False
            enable_unit = False
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
            if request.args.get('master_save') == 'add':
                add_master('MASTER', request.form.get('name_text'), request.form.get('server'), aprs_pos, repeat, active, request.form.get('max_peers'), request.form.get('ip'), request.form.get('port'), enable_um, request.form.get('passphrase'), request.form.get('group_hangtime'), use_acl, request.form.get('reg_acl'), request.form.get('sub_acl'), request.form.get('ts1_acl'), request.form.get('ts2_acl'), enable_unit, request.form.get('notes'), '', '', '')
                content = 'saved master'
            elif request.args.get('master_save') == 'edit':
                edit_master('MASTER', request.args.get('name'), request.args.get('server'), aprs_pos, repeat, active, request.form.get('max_peers'), request.form.get('ip'), request.form.get('port'), enable_um, request.form.get('passphrase'), request.form.get('group_hangtime'), use_acl, request.form.get('reg_acl'), request.form.get('sub_acl'), request.form.get('ts1_acl'), request.form.get('ts2_acl'), enable_unit, request.form.get('notes'), '', '', '')
                content = 'maste edited'
            elif request.args.get('master_save') == 'delete':
                master_delete('MASTER', request.args.get('server'), request.args.get('name'))
                content = 'master deleted'
                print('delete')
        if request.args.get('add_master'):
            s = ServerList.query.all()
            server_options = ''
            for i in s:
                server_options = server_options + '''<option value="''' + i.name + '''">''' + i.name + '''</option>\n'''
            
            content = '''
        <form action = "manage_masters?master_save=add" method = "post">
        <table style="width: 60%;" margin-left: auto; margin-right: auto;" border="1">
        <tbody>
        <tr>
        <td style="width: 175.567px;"><strong>Assign to Server:</strong></td>
        <td style="width: 399.433px;">&nbsp;<select name="server">
        ''' + server_options + '''
        </select></td>
        </tr>
        
        <tr>
        <td><strong>&nbsp;Name:</strong></td>
        <td>&nbsp;<input name="name_text" type="text" value=""/></td>
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
        <option value="False">False</optio>
        </select></td>
        </tr>
        <tr>
        <td><strong>&nbsp;Max Peers:</strong></td>
        <td>&nbsp;<input name="max_peers" type="text" value="5"/></td>
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
        <td>&nbsp;<input name="ip" type="text" value=""/></td>
        </tr>
        <tr>
        <td><strong>&nbsp;PORT:</strong></td>
        <td>&nbsp;<input name="port" type="text" value=""/></td>
        </tr>
        <tr>
        <td><strong>&nbsp;Passphrase:</strong></td>
        <td>&nbsp;<input name="passphrase" type="text" value="passw0rd"/></td>
        </tr>
        <tr>
        <td><strong>&nbsp;Group Hangtime:</strong></td>
        <td>&nbsp;<input name="group_hangtime" type="text" value="5"/></td>
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
        <td>&nbsp;<input name="reg_acl" type="text" value="DENY:1"/></td>
        </tr>
        <tr>
        <td><strong>&nbsp;Subscriber ACLs:</strong></td>
        <td>&nbsp;<input name="sub_acl" type="text" value="DENY:1"/></td>
        </tr>
        <tr>
        <td><strong>&nbsp;Talkgroup Slot 1 ACLs:</strong></td>
        <td>&nbsp;<input name="ts1_acl" type="text" value="PERMIT:ALL"/></td>
        <tr>
        <td><strong>&nbsp;Talkgroup Slot 2 ACLs:</strong></td>
        <td>&nbsp;<input name="ts2_acl" type="text" value="PERMIT:ALL"/></td></td>
        </tr>

        <tr>
        <td><strong>&nbsp;Enable Unit Calls:</strong></td>
        <td>&nbsp;<select name="enable_unit">
        <option value="True">True</option>
        <option value="False">False</option>
        </select></td>
        </tr>

        <tr>
        <td><strong>&nbsp;Notes:</strong></td>
        <td>&nbsp;<textarea id="notes" name="notes" rows="4" cols="50"></textarea></td>
        </tr>

        </tbody>
        </table>
        <p>&nbsp;</p>
        <input type = "submit" value = "Save"/>
        </form>
        <p>&nbsp;</p>
'''
        elif request.args.get('edit_master'):
##            s = ServerList.query.all()
            m = MasterList.query.filter_by(server=request.args.get('server')).filter_by(name=request.args.get('edit_master')).first()
            
            content = '''

        <p>&nbsp;</p>
        <h2 style="text-align: center;"><strong>View/Edit a MASTER</strong></h2>

       <p style="text-align: center;"><strong><a href="manage_masters?master_save=delete&server=''' + str(m.server) + '''&name=''' + str(m.name) + '''">Delete MASTER</a></strong></p>

        <form action = "manage_masters?master_save=edit&server=''' + request.args.get('server') + '''&name=''' + request.args.get('edit_master') + '''" method = "post">
        <table style="width: 60%;" margin-left: auto; margin-right: auto;" border="1">
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
        <td>&nbsp;<input name="max_peers" type="text" value="''' + str(m.max_peers) + '''"/></td>
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
        <option selected="selected" value="''' + str(m.enable_um) + '''">Current - ''' + str(m.static_positions) + '''</option>
        <option value="True">True</option>
        <option value="False">False</option>
        </select></td>
        </tr>
        <tr>
        <td><strong>&nbsp;IP:</strong></td>
        <td>&nbsp;<input name="ip" type="text" value="''' + str(m.ip) + '''"/></td>
        </tr>
        <tr>
        <td><strong>&nbsp;PORT:</strong></td>
        <td>&nbsp;<input name="port" type="text" value="''' + str(m.port) + '''"/></td>
        </tr>
        <tr>
        <td><strong>&nbsp;Passphrase:</strong></td>
        <td>&nbsp;<input name="passphrase" type="text" value="''' + str(m.passphrase) + '''"/></td>
        </tr>
        <tr>
        <td><strong>&nbsp;Group Hangtime:</strong></td>
        <td>&nbsp;<input name="group_hangtime" type="text" value="''' + str(m.group_hang_time) + '''"/></td>
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
        <td>&nbsp;<input name="reg_acl" type="text" value="''' + str(m.reg_acl) + '''"/></td>
        </tr>
        <tr>
        <td><strong>&nbsp;Subscriber ACLs:</strong></td>
        <td>&nbsp;<input name="sub_acl" type="text" value="''' + str(m.sub_acl) + '''"/></td>
        </tr>
        <tr>
        <td><strong>&nbsp;Talkgroup Slot 1 ACLs:</strong></td>
        <td>&nbsp;<input name="ts1_acl" type="text" value="''' + str(m.tg1_acl) + '''"/></td>
        <tr>
        <td><strong>&nbsp;Talkgroup Slot 2 ACLs:</strong></td>
        <td>&nbsp;<input name="ts2_acl" type="text" value="''' + str(m.tg1_acl) + '''"/></td></td>
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
        <td><strong>&nbsp;Notes:</strong></td>
        <td>&nbsp;<textarea id="notes" name="notes" rows="4" cols="50">''' + str(m.notes) + '''</textarea></td>
        </tr>

        </tbody>
        </table>
        <p>&nbsp;</p>
        <input type = "submit" value = "Save"/>
        </form>
        <p>&nbsp;</p>
'''
        else:
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
</tr>\n
'''
                all_m = MasterList.query.filter_by(server=s.name).all()
                all_p = ProxyList.query.filter_by(server=s.name).all()
                for p in all_p:
                    m_list = m_list + '''
<tr>
<td><a href="manage_masterss?server=''' + str(s.name) + '''&amp;edit_proxy=''' + str(p.name) + '''">''' + str(p.name) + '''</a></td>
<td>PROXY</td>
</tr>\n
'''
                for x in all_m:
                    m_list = m_list + '''
<tr>
<td><a href="manage_masters?server=''' + str(x.server) + '''&amp;edit_master=''' + str(x.name) + '''">''' + str(x.name) + '''</a></td>
<td>MASTER</td>
</tr>\n
'''
                m_list = m_list + ''' </tbody></table>\n'''
            content = '''

<h3 style="text-align: center;">View/Edit Master Instances</h3>

<table style="width: 400px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td style="text-align: center;"><strong><a href="manage_masters?add_master=yes">Add MASTER</a></strong></td>
<td style="text-align: center;"><strong><a href="manage_masters?add_proxy=yes">Add PROXY</a></strong></td>
</tr>
</tbody>
</table>
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

    @app.route('/auth', methods=['POST'])
    def auth():
        hblink_req = request.json
        print((hblink_req))
        if hblink_req['secret'] in shared_secrets():
            if 'login_id' in hblink_req and 'login_confirmed' not in hblink_req:
                if type(hblink_req['login_id']) == int:
                    if authorized_peer(hblink_req['login_id'])[0]:
                        if isinstance(authorized_peer(hblink_req['login_id'])[1], int) == True:
                            authlog_add(hblink_req['login_id'], hblink_req['login_ip'], hblink_req['login_server'], authorized_peer(hblink_req['login_id'])[2], gen_passphrase(hblink_req['login_id']), 'Attempt')
                            response = jsonify(
                                    allow=True,
                                    mode='normal',
                                    )
                        elif authorized_peer(hblink_req['login_id'])[1] == '':
                            authlog_add(hblink_req['login_id'], hblink_req['login_ip'], hblink_req['login_server'], authorized_peer(hblink_req['login_id'])[2], 'Config Passphrase: ' + legacy_passphrase, 'Attempt')
                            response = jsonify(
                                    allow=True,
                                    mode='legacy',
                                    )
                        elif authorized_peer(hblink_req['login_id'])[1] != '' or isinstance(authorized_peer(hblink_req['login_id'])[1], int) == False:
                            authlog_add(hblink_req['login_id'], hblink_req['login_ip'], hblink_req['login_server'], authorized_peer(hblink_req['login_id'])[2], authorized_peer(hblink_req['login_id'])[1], 'Attempt')
                            print(authorized_peer(hblink_req['login_id']))
                            response = jsonify(
                                    allow=True,
                                    mode='override',
                                    value=authorized_peer(hblink_req['login_id'])[1]
                                        )
                    elif authorized_peer(hblink_req['login_id'])[0] == False:
                        print('log fail')
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
            elif hblink_req['get_config']: # == 'burn_list':
##                test_parsed = ast.literal_eval(os.popen('cat ./test_parsed.txt').read())
                
##                print((test_parsed))
##                try:
                response = jsonify(
                        config=server_get(hblink_req['get_config']),
                        peers=get_peer_configs(hblink_req['get_config']),
                        masters=masters_get(hblink_req['get_config']),

                        )
##                except:
##                    message = jsonify(message='Config error')
##                    response = make_response(message, 401)
                                    
     
        else:
            message = jsonify(message='Authentication error')
            response = make_response(message, 401)
        return response



    return app


if __name__ == '__main__':
    app = create_app()
    app.run(debug = True, port=ums_port, host=ums_host)
