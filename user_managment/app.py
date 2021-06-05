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

try:
    from gen_script_template import gen_script
except:
    pass

script_links = {}
mmdvm_logins = []

##def gen_passphrase(dmr_id):
##    _new_peer_id = bytes_4(int(str(dmr_id)[:7]))
##    b_list = create_app().get_burnlist()
##    print(_new_peer_id)
####    try:
##    #if get_burnlist()[_new_peer_id] != 0:
##    for ui in b_list:
##        if b_list != 0:
##            calc_passphrase = base64.b64encode(bytes.fromhex(str(hex(libscrc.ccitt((_new_peer_id) + get_burnlist()[_new_peer_id].to_bytes(2, 'big') + burn_int.to_bytes(2, 'big') + append_int.to_bytes(2, 'big') + bytes.fromhex(str(hex(libscrc.posix((_new_peer_id) + get_burnlist()[_new_peer_id].to_bytes(2, 'big') + burn_int.to_bytes(2, 'big') + append_int.to_bytes(2, 'big'))))[2:].zfill(8)))))[2:].zfill(4)) + (_new_peer_id) + get_burnlist()[_new_peer_id].to_bytes(2, 'big') + burn_int.to_bytes(2, 'big') + append_int.to_bytes(2, 'big') + bytes.fromhex(str(hex(libscrc.posix((_new_peer_id) + get_burnlist()[_new_peer_id].to_bytes(2, 'big') + burn_int.to_bytes(2, 'big') + append_int.to_bytes(2, 'big'))))[2:].zfill(8)))
####    except:
##        else:
##            calc_passphrase = base64.b64encode(bytes.fromhex(str(hex(libscrc.ccitt((_new_peer_id) + append_int.to_bytes(2, 'big') + bytes.fromhex(str(hex(libscrc.posix((_new_peer_id) + append_int.to_bytes(2, 'big'))))[2:].zfill(8)))))[2:].zfill(4)) + (_new_peer_id) + append_int.to_bytes(2, 'big') + bytes.fromhex(str(hex(libscrc.posix((_new_peer_id) + append_int.to_bytes(2, 'big'))))[2:].zfill(8)))
####    print(calc_passphrase)
##    if use_short_passphrase == True:
##        return str(calc_passphrase)[-9:-1]
##    elif use_short_passphrase ==False:
##        return str(calc_passphrase)[2:-1]
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
    <h4>&nbsp;Calculated Passphrase&nbsp;</h4>
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
    <h4>&nbsp;Calculated Passphrase&nbsp;</h4>
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
    <h4>&nbsp;Calculated Passphrase&nbsp;</h4>
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
            #a = AuthLog.query.all().order_by(AuthLog.login_dmr_id)
            #a = AuthLog.query.all()
            a = AuthLog.query.order_by(AuthLog.login_time.desc()).limit(300).all()
            recent_list = []
##            r = AuthLog.query.order_by(AuthLog.login_dmr_id.desc()).all()
            content = '''
    <p>&nbsp;</p>
    <p style="text-align: center;"><strong><a href="auth_log?flush_db=true">Flush entire authentication log</a></strong></p>
    <p style="text-align: center;"><strong>Auth log by DMR ID</strong></p>

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
    <h4>&nbsp;Calculated Passphrase&nbsp;</h4>
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
        return render_template('flask_user_layout.html', markup_content = Markup(content))

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
        if hblink_req['secret'] in shared_secrets:
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
            elif hblink_req['burn_list']: # == 'burn_list':
                response = jsonify(
                                burn_list=get_burnlist()
                                    )
     
        else:
            message = jsonify(message='Authentication error')
            response = make_response(message, 401)
        return response



    return app


if __name__ == '__main__':
    app = create_app()
    app.run(debug = True, port=ums_port, host=ums_host)
