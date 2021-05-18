# This file contains an example Flask-User application.
# To keep the example simple, we are applying some unusual techniques:
# - Placing everything in one file
# - Using class-based configuration (instead of file-based configuration)
# - Using string-based templates (instead of file-based templates)

from flask import Flask, render_template_string, request, make_response, jsonify, render_template, Markup
from flask_sqlalchemy import SQLAlchemy
from flask_user import login_required, UserManager, UserMixin, user_registered, roles_required
from flask_login import current_user
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
try:
    from gen_script_template import gen_script
except:
    pass


script_links = {}

def gen_passphrase(dmr_id):
    _new_peer_id = bytes_4(int(str(dmr_id)[:7]))
    calc_passphrase = base64.b64encode(bytes.fromhex(str(hex(libscrc.ccitt((_new_peer_id) + append_int.to_bytes(2, 'big') + bytes.fromhex(str(hex(libscrc.posix((_new_peer_id) + append_int.to_bytes(2, 'big'))))[2:].zfill(8)))))[2:].zfill(4)) + (_new_peer_id) + append_int.to_bytes(2, 'big') + bytes.fromhex(str(hex(libscrc.posix((_new_peer_id) + append_int.to_bytes(2, 'big'))))[2:].zfill(8)))
##    print(calc_passphrase)
    if use_short_passphrase == True:
        return str(calc_passphrase)[-9:-1]
    elif use_short_passphrase ==False:
        return str(calc_passphrase)[2:-1]
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
             id_list[i['id']] = ''
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
        #Used for initial approval
        initial_admin_approved = db.Column('admin_approved', db.Boolean(), nullable=False, server_default='1')
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

        
    user_manager = UserManager(app, db, User)


    # Create all database tables
    db.create_all()


    if not User.query.filter(User.username == 'admin').first():
        user = User(
            username='admin',
            email='admin@no.reply',
            email_confirmed_at=datetime.datetime.utcnow(),
            password=user_manager.hash_password('admin'),
            initial_admin_approved = True
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


    def update_from_radioid(callsign):
        edit_user = User.query.filter(User.username == callsign).first()
        edit_user.dmr_ids = str(ast.literal_eval(get_ids(callsign))[0])
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
            content = content + '''\n'<p><strong> <br />5: When asked for server ports, use the information above to populate the correct fields. <br />6: Reboot your Pi-Star device</strong></p>
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
                if i[1] == '':
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




    @app.route('/list_users')
    @roles_required('Admin')
    @login_required    # User must be authenticated
    def list_users():
        u = User.query.all()
        u_list = '''<h2 style="text-align: center;"><strong>List/edit users:</strong></h2><p>&nbsp;</p><p style="text-align: center;"><a href="edit_user"><strong>Enter Callsign</strong></a></p>  <p>&nbsp;</p><table style="width: 700px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td style="width: 107px; text-align: center;"><strong>Callsign</strong></td>
<td style="width: 107px; text-align: center;"><strong>Name</strong></td>
<td style="width: 226.683px; text-align: center;"><strong>Enabled</strong></td>
<td style="width: 522.317px; text-align: center;"><strong>DMR ID:Authentication Mechanism</strong></td>
</tr>'''
        for i in u:
            u_list = u_list + '''
<tr>
<td style="width: 107px;"><a href="''' + url + '/edit_user?callsign=' + str(i.username) +'''"><strong>''' + str(i.username) + '''</strong></a></td>
<td style="width: 226.683px; text-align: center;">''' + str(i.first_name) + ' ' + str(i.last_name) + '''</td>
<td style="width: 226.683px; text-align: center;">''' + str(i.active) + '''</td>
<td style="width: 522.317px;">''' + str(i.dmr_ids) + '''</td>
</tr>
'''+ '\n'
        content = u_list + '''</tbody>
                              </table>
                              <p>&nbsp;</p>'''
        return render_template('flask_user_layout.html', markup_content = Markup(content))
    
    @app.route('/approve_users', methods=['POST', 'GET'])
    @roles_required('Admin')    # Use of @roles_required decorator
    def approve_list():
        u = User.query.all()
        wait_list = '''<h2 style="text-align: center;"><strong>Users waiting for approval:</strong></h2><p>&nbsp;</p><table style="width: 700px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td style="width: 107px; text-align: center;"><strong>Callsign</strong></td>
<td style="width: 107px; text-align: center;"><strong>Name</strong></td>
<td style="width: 226.683px; text-align: center;"><strong>Enabled</strong></td>
<td style="width: 522.317px; text-align: center;"><strong>DMR ID:Authentication Mechanism</strong></td>
</tr>'''
        for i in u:
##            print(i.username)
##            print(i.initial_admin_approved)
            if i.initial_admin_approved == False:
                wait_list = wait_list+ '''
<tr>
<td style="width: 107px;"><a href="''' + url + '/edit_user?callsign=' + str(i.username) +'''&admin_approve=true"><strong>''' + str(i.username) + '''</strong></a></td>
<td style="width: 226.683px; text-align: center;">''' + str(i.first_name) + ' ' + str(i.last_name) + '''</td>
<td style="width: 226.683px; text-align: center;">''' + str(i.active) + '''</td>
<td style="width: 522.317px;">''' + str(i.dmr_ids) + '''</td>
</tr>
'''+ '\n'
            content = wait_list + '''</tbody>
                              </table>
                              <p>&nbsp;</p>'''
        return render_template('flask_user_layout.html', markup_content = Markup(content))
                

    
    # The Admin page requires an 'Admin' role.
    @app.route('/edit_user', methods=['POST', 'GET'])
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
##                    content = content + '''<p style="text-align: center;">User <strong>''' + str(user) + '''</strong> has been disabled.</p>\n'''
##            if user != edit_user.username:
##                #print(user)
##                #print(edit_user.username)
##                #print('new uname')
##                edit_user.username = user
            if request.form.get('email') != edit_user.email:
                edit_user.email = request.form.get('email')
                content = content + '''<p style="text-align: center;">Changed email for user: <strong>''' + str(user) + ''' to ''' + request.form.get('email') + '''</strong></p>\n'''
            if request.form.get('password') != '':
                edit_user.password = user_manager.hash_password(request.form.get('password'))
                content = content + '''<p style="text-align: center;">Changed password for user: <strong>''' + str(user) + '''</strong></p>\n'''
            if request.form.get('dmr_ids') != edit_user.dmr_ids:
                edit_user.dmr_ids = request.form.get('dmr_ids')
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


            content = '''
<p>&nbsp;</p>

<table style="width: 500px; margin-left: auto; margin-right: auto;" border="1">
<tbody>
<tr>
<td style="text-align: center;"><strong>First Name</strong></td>
<td style="text-align: center;"><strong>Last Name</strong></td>
</tr>
<tr>
<td>''' + u.first_name + '''</td>
<td>''' + u.last_name + '''</td>
</tr>
<tr>
<td style="text-align: center;"><strong>City</strong></td>
<td>''' + u.city + '''</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>

<p style="text-align: center;"><strong><a href="update_ids?callsign=''' + u.username + '''">Update user information from RadioID.net</a></strong></p>

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
<p style="text-align: center;"><a href="''' + url + '/edit_user?delete_user=true&callsign=' + str(u.username) + '''"><strong>Deleted user: <strong>''' + str(u.username) + '''</strong></strong></a></p>\n
''' + confirm_link + '''
<p>&nbsp;</p>
''' + role_link + '''
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
<td style="text-align: center; width: 70.8px;">''</td>
<td style="text-align: center; width: 103.45px;">0</td>
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

        if authorized_peer(dmr_id)[1] == '':
            passphrase = gen_passphrase(dmr_id)
        elif authorized_peer(dmr_id)[1] == 0:
            passphrase = legacy_passphrase
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
            return [u.is_active, login_passphrase[peer_id]]
        except:
            return [False]

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
        #u = User.query.filter_by(username='kf7eel').first()
        #u = Role.query.all()
##        u = User.query.filter(User.dmr_ids.contains('3153591')).first()
        u = User.query.all()
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
        print(u)
        for i in u:
            #print(i.initial_admin_approved)
            if not i.initial_admin_approved:
                print(i.username)
        #    print(i)
        #u_role = UserRoles.query.filter_by(id=2).first().role_id
        #u_role = 1
       # db.session.commit()
        #u_role = UserRoles.query.filter_by(id=u.id).first().role_id
        #print(u_role)
        return str(u)

    @app.route('/add_user', methods=['POST', 'GET'])
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
        #print((hblink_req))
        if hblink_req['secret'] in shared_secrets:
            if authorized_peer(hblink_req['id'])[0]:
                if authorized_peer(hblink_req['id'])[1] == 0:
                    response = jsonify(
                            allow=True,
                            mode='legacy',
                            )
                elif authorized_peer(hblink_req['id'])[1] == '':
                # normal
                    response = jsonify(
                            allow=True,
                            mode='normal',
                            )
                elif authorized_peer(hblink_req['id'])[1] != '' or authorized_peer(hblink_req['id'])[1] != 0:
                    response = jsonify(
                            allow=True,
                            mode='override',
                            value=auth_dict[hblink_req['id']]
                                )
            if authorized_peer(hblink_req['id'])[0] == False:
                response = jsonify(
                            allow=False)
        else:
            message = jsonify(message='Authentication error')
            response = make_response(message, 401)
            
        return response



    return app


if __name__ == '__main__':
    app = create_app()
    app.run(debug = True, port=ums_port, host=ums_host)
