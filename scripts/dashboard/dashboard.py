###############################################################################
#   HBLink - Copyright (C) 2020 Cortney T. Buffington, N0MJS <n0mjs@me.com>
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

'''
This is a web dashboard for the GPS/Data application.
'''

from flask import Flask, render_template, request, Response, Markup, jsonify, make_response
import ast, os
#from dashboard_settings import *
import folium
from folium.plugins import MarkerCluster
import re
from datetime import datetime
import argparse
from configparser import ConfigParser
from send_sms import *
import importlib.util
import requests



app = Flask(__name__)


tbl_hdr = '''
<table style="border-color: black; margin-left: auto; margin-right: auto;" border="2" cellspacing="6" cellpadding="2"><tbody>
'''
tbl_ftr = '''
</tbody>
</table>
'''

def get_loc_data():
    try:
        dash_loc = ast.literal_eval(os.popen('cat ' + loc_file).read())
        tmp_loc = ''
        loc_hdr = '''
    <tr>
    <td style="text-align: center;">
    <h2><strong>&nbsp;Callsign&nbsp;</strong></h2>
    </td>
    <td style="text-align: center;">
    <h2>&nbsp;<strong>Latitude</strong>&nbsp; </h2>
    </td>
    <td style="text-align: center;">
    <h2>&nbsp;<strong>Longitude</strong>&nbsp;</h2>
    </td>
    <td style="text-align: center;">
    <h2>&nbsp;<strong>Time</strong>&nbsp;</h2>
    </td>
    </tr>
    '''
        last_known_loc_list = []
        display_number = 15
        for e in dash_loc:
            if display_number == 0:
                break
            else:
                if e['call'] in last_known_loc_list:
                    pass
                if e['call'] not in last_known_loc_list:
                    if type(e['time']) == str:
                        loc_time = str(e['time'])
                    if type(e['time']) == int or type(e['time']) == float:
                        loc_time = datetime.fromtimestamp(e['time']).strftime(time_format)
                    last_known_loc_list.append(e['call'])
                    display_number = display_number - 1
                    tmp_loc = tmp_loc + '''<tr>
    <td style="text-align: center;"><a href="''' + dashboard_url + '''/view_map?track=''' + e['call'] + '''"target="_blank"><strong>''' + e['call'] + '''</strong></a></td>
    <td style="text-align: center;"><strong>&nbsp;''' + str(e['lat']) + '''&nbsp;</strong></td>
    <td style="text-align: center;"><strong>&nbsp;''' + str(e['lon']) + '''&nbsp;</strong></td>
    <td style="text-align: center;">&nbsp;''' + loc_time + '''&nbsp;</td>
    </tr>'''
        return str(str('<h1 style="text-align: center;">Last Known Location</h1>') + tbl_hdr + loc_hdr + tmp_loc + tbl_ftr)
    except:
       return str('<h1 style="text-align: center;">No data</h1>')


def get_bb_data():
    try:
        dash_bb = ast.literal_eval(os.popen('cat ' + bb_file).read())
        tmp_bb = ''
        
        bb_hdr = '''
    <tr>
    <td style="text-align: center;">
    <h2><strong>&nbsp;Callsign&nbsp;</strong></h2>
    </td>
    <td style="text-align: center;">
    <h2>&nbsp;<strong>ID</strong>&nbsp; </h2>
    </td>
    <td style="text-align: center;">
    <h2>&nbsp;<strong>Bulletin</strong>&nbsp;</h2>
    </td>
    <td style="text-align: center;">
    <h2>&nbsp;<strong>Time</strong>&nbsp;</h2>
    </td>
    </tr>
    '''
        display_number = 10
        
        for e in dash_bb:
            if display_number == 0:
                break
            else:
                if type(e['time']) == str:
                        loc_time = str(e['time'])
                if type(e['time']) == int or type(e['time']) == float:
                        loc_time = datetime.fromtimestamp(e['time']).strftime(time_format)
                display_number = display_number - 1
                tmp_bb = tmp_bb + '''<tr>
        <td style="text-align: center;"><strong>&nbsp;''' + e['call'] + '''&nbsp;</strong></td>
        <td style="text-align: center;">''' + str(e['dmr_id']) + '''</td>
        <td style="text-align: center;"><strong>&nbsp;''' + e['bulletin'] + '''&nbsp;</strong></td>
        <td style="text-align: center;">&nbsp;''' + loc_time + '''&nbsp;</td>
        </tr>'''

        return str('<h1 style="text-align: center;">Bulletin Board</h1>' + tbl_hdr + bb_hdr + tmp_bb + tbl_ftr)
    except:
        return str('<h1 style="text-align: center;">No data</h1>')

def check_emergency():
    # open emergency txt
    try:
        sos_file = ast.literal_eval(os.popen('cat ' + emergency_sos_file).read())
        if type(sos_file['time']) == str:
            loc_time = str(sos_file['time'])
        if type(sos_file['time']) == int or type(sos_file['time']) == float:
            loc_time = datetime.fromtimestamp(sos_file['time']).strftime(time_format)
        if '@NOTICE' in sos_file['message'] and '@SOS' not in sos_file['message']:
            notice_header = '<span style="background-color: #ffffff; color: #008000;">NOTICE:</span>'
        else:
            notice_header = '<span style="background-color: #ff0000; color: #ffffff;">EMERGENCY ACTIVATION</span>'
        value = Markup("""
            <h1 style="text-align: center;">""" +  notice_header  + """</h1>
            <table style="width: 441px; margin-left: auto; margin-right: auto;" border="3">
            <tbody>
            <tr>
            <td style="width: 78.3667px;"><span style="text-decoration: underline;"><strong>From:</strong></span></td>
            <td style="width: 345.633px; text-align: center;"><strong>""" + sos_file['call'] + """</strong> - """ + str(sos_file['dmr_id']) + """</td>
            </tr>
            <tr>
            <td style="width: 78.3667px;"><span style="text-decoration: underline;"><strong>Message:</strong></span></td>
            <td style="width: 345.633px; text-align: center;">""" + sos_file['message'] + """</td>
            </tr>
            <tr>
            <td style="width: 78.3667px;"><span style="text-decoration: underline;"><strong>Time:</strong></span></td>
            <td style="width: 345.633px; text-align: center;">""" + loc_time + """</td>
            </tr>
            </tbody>
            </table>
            <p>&nbsp;</p>
             <button onclick="window.open('view_map?track=""" + sos_file['call'] + """&reload=30','_blank' );" type="button" class="emergency_button"><h1>View Station on Map</h1></button>
             <p style="text-align: center;"><a href="https://aprs.fi/""" + sos_file['call'] + """"><strong>View on aprs.fi</strong></a></p> 
             <hr />

            """)
        return value
    except Exception as e:
        return ''

def aprs_to_latlon(x):
    degrees = int(x) // 100
    minutes = x - 100*degrees
    return degrees + minutes/60 

def user_setting_write(dmr_id, input_ssid, input_icon, input_comment, input_aprs):
    dmr_id = int(dmr_id)
    user_settings = ast.literal_eval(os.popen('cat ' + user_settings_file).read())
    new_dict = user_settings
    new_dict[dmr_id][1]['ssid'] = input_ssid
    new_dict[dmr_id][2]['icon'] = input_icon
    new_dict[dmr_id][3]['comment'] = input_comment
    if input_aprs == 'True':
        new_dict[dmr_id][5]['APRS'] = True
    if input_aprs == 'False':
        new_dict[dmr_id][5]['APRS'] = False
    #print(input_comment)
    #print(new_dict[dmr_id])
                        
    # Write modified dict to file
    with open(user_settings_file, 'w') as user_dict_file:
        user_dict_file.write(str(new_dict))
        user_dict_file.close()
        


def generate_apps():
    global access_systems, authorized_users
    mod = importlib.util.spec_from_file_location("rules_data", parser.get('GPS_DATA', 'RULES_PATH'))
    rules = importlib.util.module_from_spec(mod)
    mod.loader.exec_module(rules)
    local_apps = rules.local_apps
    authorized_users = rules.authorized_users

    #rules_data = ast.literal_eval(os.popen('cat ' + parser.get('GPS_DATA', 'RULES_PATH')).read())
    #rules_data
    public_systems_file = requests.get(parser.get('GPS_DATA', 'PUBLIC_APPS_LIST'))
    public_apps = ast.literal_eval(public_systems_file.text)
    access_systems = {}
    #combined = public_apps.items() + local_acess_systems.items()
    print(type(parser.get('GPS_DATA', 'USE_PUBLIC_APPS')))
    if parser.get('GPS_DATA', 'USE_PUBLIC_APPS') == 'True':
        for i in public_apps.items():
            key = str(i[0])
            access_systems[key] = i[1]
    for i in local_apps.items():
        key = str(i[0])
        access_systems[key] = i[1]
    print(access_systems)
    print(authorized_users)
    print(local_apps)
    #print(rules_data)
    
    #print(type(public_apps))
    #print(type(local_acess_systems))
    #print()
    #print(combined)
    #print(local_acess_systems.update(public_apps))
    #return access_systems

@app.route('/')
def index():
    value = Markup('<strong>The HTML String</strong>')
    #return get_data()
    return render_template('index.html', title = dashboard_title, dashboard_url = dashboard_url, logo = logo, emergency = check_emergency(), api = use_api)
@app.route('/bulletin_board')
def dash_bb():
    return get_bb_data()
    #return render_template('index.html', data = str(get_data()))
@app.route('/positions')
def dash_loc():
    return get_loc_data()

@app.route('/help/')
def help():
    #return get_data()
    return render_template('help.html', title = dashboard_title, dashboard_url = dashboard_url, logo = logo, description = description, api = use_api, data_call_type = data_call_type, data_call_id = data_call_id, aprs_ssid = aprs_ssid)
@app.route('/about/')
def about():
    #return get_data()
    return render_template('about.html', title = dashboard_title, dashboard_url = dashboard_url, logo = logo, contact_name = contact_name, api = use_api, contact_call = contact_call, contact_email = contact_email, contact_website = contact_website)

@app.route('/external_apps')
def external_apps():
    #access_systems = ast.literal_eval(os.popen('cat ' + access_systems_file).read())
    msg_lst = ''
    app_lst = ''
    for i_msg in access_systems.items():
        if i_msg[1]['mode'] == 'msg_xfer':
            msg_lst = msg_lst + ''' 
        <tr>
        <td style="text-align: center;">&nbsp;''' + i_msg[1]['network_name'] + '''</td>
        <td style="text-align: center;">&nbsp;<strong>?''' + str(i_msg[0]) + '''</strong></td>
        <td style="text-align: center;"><a href="''' + i_msg[1]['url'] + '''">''' + i_msg[1]['url'] + '''</a></td>
        </tr> '''
    for i_app in access_systems.items():
        if i_app[1]['mode'] == 'app':
            app_lst = app_lst + ''' 
        <tr>
        <td style="text-align: center;">&nbsp;''' + i_app[1]['app_name'] + '''</td>
        <td style="text-align: center;">&nbsp;<strong>?''' + str(i_app[0]) + '''</strong></td>
        <td style="text-align: center;"><a href="''' + i_app[1]['website'] + '''">''' + i_app[1]['website'] + '''</a></td>
        </tr> '''
    content = '''
    <p>&nbsp;</p>
    External applications and other HBLink networks that can be accessed via SMS from this gateway:
    <h2 style="text-align: center;">External Networks/Servers</h2>
    <table style="border-color: black; width: 600px; margin-left: auto; margin-right: auto;" border="3">
    <tbody>
    <tr>
    <td style="text-align: center;">
    <h3>Network/Server</h3>
    </td>
    <td style="text-align: center;">
    <h3>Shortcut</h3>
    </td>
    <td style="text-align: center;">
    <h3>URL</h3>
    </td>
    </tr>
    ''' + msg_lst + '''
    </tbody>
    </table>
    <p>&nbsp;</p>
    <h2 style="text-align: center;">&nbsp;External Applications</h2>
    <table style="border-color: black; width: 600px; margin-left: auto; margin-right: auto;" border="3">
    <tbody>
    <tr>
    <td style="text-align: center;">
    <h3>Application</h3>
    </td>
    <td style="text-align: center;">
    <h3>Shortcut</h3>
    </td>
    <td style="text-align: center;">
    <h3>Website</h3>
    </td>
    </tr>
    ''' + app_lst + '''
    </tbody>
    </table>
    <p>&nbsp;</p>
    '''
##    content = 'yo'
    return render_template('generic.html', title = dashboard_title, dashboard_url = dashboard_url, logo = logo, content = Markup(content), api = use_api)

@app.route('/view_map')
def view_map():
    reload_time = request.args.get('reload')
    track_call = request.args.get('track')
    map_size = request.args.get('map_size')
    user_loc = ast.literal_eval(os.popen('cat ' + loc_file).read())
    last_known_list = []
    coord_list = []
    try:
        if track_call:
            #folium_map = folium.Map(location=map_center, zoom_start=int(zoom_level))
            #marker_cluster = MarkerCluster().add_to(folium_map)
            for user_coord in user_loc:
                user_lat = aprs_to_latlon(float(re.sub('[A-Za-z]','', user_coord['lat'])))
                user_lon = aprs_to_latlon(float(re.sub('[A-Za-z]','', user_coord['lon'])))
                if type(user_coord['time']) == str:
                        loc_time = str(user_coord['time'])
                if type(user_coord['time']) == int or type(user_coord['time']) == float:
                        loc_time = datetime.fromtimestamp(user_coord['time']).strftime(time_format)
                if 'S' in user_coord['lat']:
                    user_lat = -user_lat
                if 'W' in user_coord['lon']:
                    user_lon = -user_lon
                loc_comment = ''
                if 'comment' in user_coord:
                    loc_comment = """
                <tr>
                <td style="text-align: center;">Comment:</td>
                </tr>
                <tr>
                <td style="text-align: center;"><strong>"""+ str(user_coord['comment']) +"""</strong></td>
                </tr>"""
                if user_coord['call'] not in last_known_list and user_coord['call'] == track_call:
                    folium_map = folium.Map(location=[user_lat, user_lon], tiles=map_theme, zoom_start=15)
                    marker_cluster = MarkerCluster().add_to(folium_map)
                    folium.Marker([user_lat, user_lon], popup="""<i>
                    <table style="width: 150px;">
                    <tbody>
                    <tr>
                    <td style="text-align: center;">Last Location:</td>
                    </tr>
                    <tr>
                    <td style="text-align: center;"><strong>"""+ str(user_coord['call']) +"""</strong></td>
                    </tr>
                    <tr>
                    <td style="text-align: center;"><em>"""+ loc_time +"""</em></td>
                    """ + loc_comment + """
                    </tr>
                    </tbody>
                    </table>
                    </i>
                    """, icon=folium.Icon(color="red", icon="record"), tooltip=str(user_coord['call'])).add_to(folium_map)
                    last_known_list.append(user_coord['call'])
                if user_coord['call'] in last_known_list and user_coord['call'] == track_call:
                    folium.CircleMarker([user_lat, user_lon], popup="""
                    <table style="width: 150px;">
                    <tbody>
                    <tr>
                    <td style="text-align: center;"><strong>""" + user_coord['call'] + """</strong></td>
                    </tr>
                    <tr>
                    <td style="text-align: center;"><em>""" + loc_time + """</em></td>
                    </tr>
                    </tbody>
                    </table>
                    """, tooltip=str(user_coord['call']), fill=True, fill_color="#3186cc", radius=4).add_to(marker_cluster)
            #return folium_map._repr_html_()
                if not reload_time:
                    reload_time = 120
            if not map_size:
                map_view = '''<table style="width: 1000px; height: 600px; margin-left: auto; margin-right: auto;" border="1">
                        <tbody>
                        <tr>
                        <td>
                        ''' + folium_map._repr_html_() + '''</td>
                        </tr>
                        </tbody>
                        </table>'''
            if map_size == 'full':
                map_view = folium_map._repr_html_()

            content = '''
                    <head>
                        <meta charset="UTF-8">
                        <meta http-equiv="refresh" content="''' + str(reload_time) + """" > 
                        <title>""" + dashboard_title + """ - Tracking """+ track_call + """</title>
                    </head>
                    <p style="text-align: center;"><strong>""" + dashboard_title + """ - Tracking """ + track_call + """</strong></p>
                    <p style="text-align: center;"><em>Page automatically reloads every """ + str(reload_time) + """ seconds.</em></p>
                    <p style="text-align: center;">
                        <select name="sample" onchange="location = this.value;">
                         <option value="view_map?track=""" + track_call + """&reload=120">2 Minutes</option>
                         <option value="view_map?track=""" + track_call + """&reload=">Don't Reload</option>
                         <option value="view_map?track=""" + track_call + """&reload=30">30 Seconds</option>
                         <option value="view_map?track=""" + track_call + """&reload=5">5 Minutes</option>
                         <option value="view_map?track=""" + track_call + """&reload=600">10 Minutes</option> 
                        </select> 
                    <p style="text-align: center;"><button onclick="self.close()">Close</button><!--<button onclick="history.back()">Back</button>-->
                    </p>
                     """ + map_view
            return render_template('generic.html', title = dashboard_title, logo = logo, content = Markup(content))
    except Exception as e:
        content = """<h1 style="text-align: center;">Station not found.</h1>
                  #<p style="text-align: center;"><button onclick="self.close()">Close Window</button>
                #</p>"""
        return render_template('generic.html', title = dashboard_title, dashboard_url = dashboard_url, logo = logo, content = Markup(content))

    if not track_call:
        folium_map = folium.Map(location=(map_center_lat, map_center_lon), tiles=map_theme, zoom_start=int(zoom_level))
        marker_cluster = MarkerCluster().add_to(folium_map)
        for user_coord in user_loc:
            user_lat = aprs_to_latlon(float(re.sub('[A-Za-z]','', user_coord['lat'])))
            user_lon = aprs_to_latlon(float(re.sub('[A-Za-z]','', user_coord['lon'])))
            if type(user_coord['time']) == str:
                    loc_time = str(user_coord['time'])
            if type(user_coord['time']) == int or type(user_coord['time']) == float:
                    loc_time = datetime.fromtimestamp(user_coord['time']).strftime(time_format)
            if 'S' in user_coord['lat']:
                user_lat = -user_lat
            if 'W' in user_coord['lon']:
                user_lon = -user_lon
            loc_comment = ''
            coord_list.append([user_lat, user_lon])
            if 'comment' in user_coord:
                loc_comment = """
            <tr>
            <td style="text-align: center;">Comment:</td>
            </tr>
            <tr>
            <td style="text-align: center;"><strong>"""+ str(user_coord['comment']) +"""</strong></td>
            </tr>"""
            if user_coord['call'] not in last_known_list:
                folium.Marker([user_lat, user_lon], popup="""<i>
                <table style="width: 150px;">
                <tbody>
                <tr>
                <td style="text-align: center;">Last Location:</td>
                </tr>
                <tr>
                <td style="text-align: center;"><strong>""" + user_coord['call'] + """</strong></td>
                </tr>
                <tr>
                <td style="text-align: center;"><em>""" + loc_time + """</em></td>
                </tr>
                """ + loc_comment + """
                <tr>
                <td style="text-align: center;"><strong><A href='""" + dashboard_url + """/view_map?track=""" + user_coord['call'] + """' target="_blank">Track Station</A></strong></td>
                </tr>
                </tbody>
                </table>

                </i>""", icon=folium.Icon(color="red", icon="record"), tooltip=str(user_coord['call'])).add_to(folium_map)
                last_known_list.append(user_coord['call'])
            if user_coord['call'] in last_known_list:
                if coord_list.count([user_lat, user_lon]) > 15:
                    pass
                else:
                    folium.CircleMarker([user_lat, user_lon], popup="""
                    <table style="width: 150px;">
                    <tbody>
                    <tr>
                    <td style="text-align: center;"><strong>""" + user_coord['call'] + """</strong></td>
                    </tr>
                    <tr>
                    <td style="text-align: center;"><em>""" + loc_time + """</em></td>
                    </tr>
                    </tbody>
                    </table>
                    """, tooltip=str(user_coord['call']), fill=True, fill_color="#3186cc", radius=4).add_to(marker_cluster)

        return folium_map._repr_html_()
    
@app.route('/map/')
def map():
    return render_template('map.html', title = dashboard_title, dashboard_url = dashboard_url, logo = logo, api = use_api)

@app.route('/user', methods = ['GET', 'POST'])
def user_settings():
    user_settings = ast.literal_eval(os.popen('cat ' + user_settings_file).read())
    user_id = request.args.get('user_id')
    if request.method == 'POST' and request.form.get('dmr_id'):
        if int(request.form.get('dmr_id')) in user_settings:
            user_id = request.form.get('dmr_id')
            ssid = user_settings[int(request.form.get('dmr_id'))][1]['ssid']
            icon = user_settings[int(request.form.get('dmr_id'))][2]['icon']
            comment = user_settings[int(request.form.get('dmr_id'))][3]['comment']
            pin = user_settings[int(request.form.get('dmr_id'))][4]['pin']
            aprs_msg_status = str(user_settings[int(request.form.get('dmr_id'))][5]['APRS'])
            
            if pin != '':
               
                if ssid == '':
                    ssid = aprs_ssid
                if icon == '':
                    icon = '\['
                if comment == '':
                    comment = default_comment + ' ' + user_id
                user_result = """
                Use this tool to change the stored APRS settings for your DMR ID. When a position is sent, the stored settings will be used to format the APRS packet. Leave field(s) blank for default value.
        <h2 style="text-align: center;">&nbsp;Modify Settings for ID: """ + user_id + """</h2>
        <form action="user" method="post">
        <table style="margin-left: auto; margin-right: auto; width: 419.367px;" border="1">
        <tbody>
        <tr>
        <td style="width: 82px;"><strong>Callsign:</strong></td>
        <td style="width: 319.367px; text-align: center;"><strong>""" + str(user_settings[int(user_id)][0]['call']) + """</strong></td>
        </tr>
        <tr>
        <td style="width: 82px;"><strong>SSID:</strong></td>
        <td style="width: 319.367px; text-align: center;"><input id="ssid" name="ssid" type="text" placeholder='""" + ssid + """' /></td>
        </tr>
        <tr>
        <td style="width: 82px;"><strong>Icon:</strong></td>
        <td style="width: 319.367px; text-align: center;"><input id="icon" name="icon" type="text" placeholder='""" + icon + """' /></td>
        </tr>
        <tr>
        <td style="width: 82px;"><strong>Comment:</strong></td>
        <td style="width: 319.367px; text-align: center;"><input id="comment" name="comment" type="text" placeholder='""" + comment + """'/></td>
        </tr>
        <tr>
        <td style="width: 82px;"><strong>APRS Messaging:</strong></td>
        <td style="width: 319.367px; text-align: center;"><select name="aprs" id="aprs">
          <option value='""" + aprs_msg_status + """' selected>""" + aprs_msg_status + """</option>
          <option value="True"> True (Enabled) </option>
          <option value="False"> False (Disabled) </option>
        </select>
        </td>
        </tr>
        <tr>
        <td style="width: 82px;"><strong>DMR ID:</strong></td>
        <td style="width: 319.367px; text-align: center;"><input id="dmr_id" name="dmr_id" type="text" value='""" + user_id + """'/></td>
        </tr>
        <tr>
        <td style="width: 82px;"><strong>PIN:</strong></td>
        <td style="width: 319.367px; text-align: center;"><input id="pin" name="pin" type="password" /></td>
        </tr>
        </tbody>
        </table>
        <p style="text-align: center;"><input type="submit" value="Submit" /></p>
        </form>
                        <p>&nbsp;</p>


        """
            if pin == '':
                user_result = """<h2 style="text-align: center;">No PIN set for """ + str(user_settings[int(user_id)][0]['call']) + """ - """ + request.form.get('dmr_id') + """</h2>
                <p style="text-align: center;"><button onclick="history.back()">Back</button>
                        </p>"""
        if int(request.form.get('dmr_id')) not in user_settings:
                user_result = """<h2 style="text-align: center;">DMR ID not found.</h2>
                <p style="text-align: center;"><button onclick="history.back()">Back</button>
                        </p>"""
    #if edit_user:
        
    if request.method == 'POST' and request.form.get('dmr_id') and request.form.get('pin'):
        if int(request.form.get('pin')) == pin:
            ssid = request.form.get('ssid')
            icon = request.form.get('icon')
            comment = request.form.get('comment')
            user_setting_write(request.form.get('dmr_id'), request.form.get('ssid'), request.form.get('icon'), request.form.get('comment'), request.form.get('aprs'))
            user_result = """<h2 style="text-align: center;">Changed settings for """  + str(user_settings[int(user_id)][0]['call']) + """ - """ + request.form.get('dmr_id') +  """</h2>
                <p style="text-align: center;"><button onclick="history.back()">Back</button>
                        </p>"""
        if int(request.form.get('pin')) != pin:
            user_result = """<h2 style="text-align: center;">Incorrect PIN.</h2>
                <p style="text-align: center;"><button onclick="history.back()">Back</button>
                        </p>"""

    if request.method == 'GET' and not request.args.get('user_id'):
        user_result = """
        Use this tool to find, check, and change the stored APRS settings for your DMR ID. When a position is sent, the stored settings will be used to format the APRS packet.
<table style="width: 600px; margin-left: auto; margin-right: auto;" border="3">
<tbody>
<tr>
<td><form action="user" method="get">
<table style="margin-left: auto; margin-right: auto;">
<tbody>
<tr style="height: 62px;">
<td style="text-align: center; height: 62px;">
<h2><strong><label for="user_id">Look up DMR ID:</label></strong></h2>
</td>
</tr>
<tr style="height: 51.1667px;">
<td style="height: 51.1667px;"><input id="user_id" name="user_id" type="text" /></td>
</tr>
<tr style="height: 27px;">
<td style="text-align: center; height: 27px;"><input type="submit" value="Submit" /></td>
</tr>
</tbody>
</table>
</form></td>
<td><form action="user" method="post">
<table style="margin-left: auto; margin-right: auto;">
<tbody>
<tr style="height: 62px;">
<td style="text-align: center; height: 62px;">
<h2><strong><label for="dmr_id">Edit DMR ID:</label></strong></h2>
</td>
</tr>
<tr style="height: 51.1667px;">
<td style="height: 51.1667px;"><input id="dmr_id" name="dmr_id" type="text" /></td>
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


"""
    #else:
    if request.method == 'GET' and request.args.get('user_id'):
        try:
            call = user_settings[int(user_id)][0]['call']
            ssid = user_settings[int(user_id)][1]['ssid']
            icon = user_settings[int(user_id)][2]['icon']
            comment = user_settings[int(user_id)][3]['comment']
            aprs_msg_status = str(user_settings[int(user_id)][5]['APRS'])
            if ssid == '':
                ssid = aprs_ssid
            if icon == '':
                icon = '\['
            if comment == '':
                comment = default_comment + ' ' + user_id
            #for result in user_settings:
            #return user_settings[int(user_id)][0]
            #return user_id
            #return user_settings
            user_result =  """<h2 style="text-align: center;">&nbsp;Settings for ID: """ + user_id + """</h2>
                <table style="margin-left: auto; margin-right: auto; width: 419.367px;" border="1">
                <tbody>
                <tr>
                <td style="width: 82px;"><strong>Callsign:</strong></td>
                <td style="width: 319.367px; text-align: center;">""" + user_settings[int(user_id)][0]['call'] + """</td>
                </tr>
                <tr>
                <td style="width: 82px;"><strong>SSID:</strong></td>
                <td style="width: 319.367px; text-align: center;">""" + ssid + """</td>
                </tr>
                <tr>
                <td style="width: 82px;"><strong>Icon:</strong></td>
                <td style="width: 319.367px; text-align: center;">""" + icon + """</td>
                </tr>
                <tr>
                <td style="width: 82px;"><strong>Comment:</strong></td>
                <td style="width: 319.367px; text-align: center;">""" + comment + """</td>
                </tr>
                <tr>
                <td style="width: 82px;"><strong>APRS Messaging:</strong></td>
                <td style="width: 319.367px; text-align: center;">""" + aprs_msg_status + """</td>
                </tr>
                </tbody>
                </table>
                <p style="text-align: center;"><button onclick="history.back()">Back</button>
                                    </p>
                                     """
        except:
            user_result = '''<h2 style="text-align: center;">User ID not found.</h2>
                <p style="text-align: center;"><button onclick="history.back()">Back</button>
                        </p>'''
        
    return render_template('generic.html', title = dashboard_title, dashboard_url = dashboard_url, logo = logo, content = Markup(user_result), api = use_api)

@app.route('/mailbox')
def mailbox():
    recipient = request.args.get('recipient')
    if not recipient:
        mail_content = """
        <p>The Mailbox is a place where users can leave messages via DMR SMS. A user can leave a message for someone else by sending a specially formatted SMS to <strong>""" + data_call_id + """</strong>.
        The message recipient can then use the mailbox to check for messages. You can also check for APRS mesages addressed to your DMR radio. Enter your call sign (without APRS SSID) below to check for messages. See the <a href='""" + dashboard_url + """/help'>help</a> page for more information.</p>
        <form action="mailbox" method="get">
        <table style="margin-left: auto; margin-right: auto;">
        <tbody>
        <tr style="height: 62px;">
        <td style="text-align: center; height: 62px;">
        <h2><strong><label for="recipient">Callsign:</label></strong></h2>
        </td>
        </tr>
        <tr style="height: 51.1667px;">
        <td style="height: 51.1667px;"><input id="recipient" name="recipient" type="text" /></td>
        </tr>
        <tr style="height: 27px;">
        <td style="text-align: center; height: 27px;"><input type="submit" value="Submit" /></td>
        </tr>
        </tbody>
        </table>
        </form>
        <p>&nbsp;</p>

"""

    else:
        mailbox_file = ast.literal_eval(os.popen('cat ' + the_mailbox_file).read())
        mail_content = '<h2 style="text-align: center;">Messages for: ' + recipient.upper() + '''
        </h2>\n<p style="text-align: center;"><button onclick="history.back()">Back</button></p>\n
        <h4 style="text-align: center;"><a href="mailbox_rss?recipient=''' + recipient.upper() + '''"><em>Mailbox RSS Feed for ''' + recipient.upper() + '''</em></a><img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAB4AAAAeCAYAAAA7MK6iAAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAC4jAAAuIwF4pT92AAAAB3RJTUUH5QIcFBAOXAevLAAAAZZJREFUSMftlbtKA0EUhj8jWhi8gaIEC29oxEoRFESLgIXYiWVSKoj6CCrBBwj6CBHNE1hEWy21ETQqiIW1wXhPo81ZOBw2apbdVPvDsDPnP8M/5zKzECJEQKivYO8DFoAYEAGKtTpQEvhW4w3IA+tAVy2F9fgEskA8COHUL8LOKAMZoMmLQF0FewcwImmNAzPANBB18b0BFoGroNLfBiyLgI2+BMwF3XgNwCrwYsQ//BBPSRPdAoeybjE+A8ClS+Sjfnf1E5A2dW4FzoxfwWvD/XWd7oAxI24jz3gVnpS7eiEpt+KvQEL5D5qal/245zFgU+pnXzMd+Zrh9/3q5l7g3CXtTs0bgWvFffn5vDa7iKcVv2K4DS8i3cAOsAuMm8h12ovqqrVL/R3upFrRKPBgHgctvm0iSynuWNnf5bf6byy5dPKe4nukhg6XU9yW2TfsJlDpNCUX27OaP8pD4WBCzQtmX381EUeAI3Xqe6m5xoHpYAezJuJkNb9Fh0tI4+SlXhpTwJBaZ+XbCcwr+6kcPESI2uAHmAijFaMnEmYAAAAASUVORK5CYII=" /></h4>
        '''
        for messages in mailbox_file:
            if messages['recipient'] == recipient.upper():
                sender = """
                <tr>
                <td style="width: 63px;"><strong>DMR ID:</strong></td>
                <td style="width: 292.55px; text-align: center;">""" + str(messages['dmr_id']) + """</td>
                </tr>
                """
                if type(messages['time']) == str:
                    loc_time = str(messages['time'])
                if type(messages['time']) == int or type(messages['time']) == float:
                    loc_time = datetime.fromtimestamp(messages['time']).strftime(time_format)
                if type(messages['dmr_id']) == str:
                    sender = """
                <tr>
                <td style="width: 63px;"><strong>APRS Call:</strong></td>
                <td style="width: 292.55px; text-align: center;">""" + str(messages['dmr_id']) + """</td>
                </tr>
                """
                mail_content = mail_content + """
                <table style="margin-left: auto; margin-right: auto; width: 372.55px;" border="1">
                <tbody>
                <tr>
                <td style="width: 63px;"><strong>From:</strong></td>
                <td style="text-align: center; width: 292.55px;"><strong>""" + messages['call'] + """</strong></td>
                </tr>
                """ + sender + """
                <tr>
                <td style="width: 63px;"><strong>Time:</strong></td>
                <td style="width: 292.55px; text-align: center;">""" + loc_time + """</td>
                </tr>
                <tr>
                <td style="width: 63px;"><strong>Message:</strong></td>
                <td style="width: 292.55px; text-align: center;"><strong>""" + messages['message'] + """</strong></td>
                </tr>
                </tbody>
                </table>
                <p>&nbsp;</p>

                """
    return render_template('generic.html', title = dashboard_title, dashboard_url = dashboard_url, logo = logo, content = Markup(mail_content), api = use_api)


@app.route('/bulletin_rss.xml')
def bb_rss():
    try:
        dash_bb = ast.literal_eval(os.popen('cat ' + bb_file).read())
        post_data = ''
        rss_header = """<?xml version="1.0" encoding="UTF-8" ?>
        <rss version="2.0">
        <channel>
          <title>""" + dashboard_title + """ - Bulletin Board Feed</title>
          <link>""" + dashboard_url + """</link>
          <description>This is the Bulletin Board feed from """ + dashboard_title + """</description>"""
        for entry in dash_bb:
            if type(entry['time']) == str:
                loc_time = str(entry['time'])
            if type(entry['time']) == int or type(entry['time']) == float:
                loc_time = datetime.fromtimestamp(entry['time']).strftime(time_format)
            post_data = post_data + """
             <item>
                <title>""" + entry['call'] + ' - ' + str(entry['dmr_id']) + """</title>
                <link>""" + dashboard_url + """</link>
                <description>""" + entry['bulletin'] + """ - """ + loc_time + """</description>
                <pubDate>""" + datetime.fromtimestamp(entry['time']).strftime('%a, %d %b %y') +"""</pubDate>
             </item>
    """
        return Response(rss_header + post_data + "\n</channel>\n</rss>", mimetype='text/xml')
    except Exception as e:
        #return str('<h1 style="text-align: center;">No data</h1>')
        return str(e)

@app.route('/mailbox_rss')
def mail_rss():
    mailbox_file = ast.literal_eval(os.popen('cat ' + the_mailbox_file).read())
    post_data = ''
    recipient = request.args.get('recipient').upper()
    rss_header = """<?xml version="1.0" encoding="UTF-8" ?>
    <rss version="2.0">
    <channel>
      <title>""" + dashboard_title + """ - Mailbox Feed for """ + recipient + """</title>
      <link>""" + dashboard_url + """</link>
      <description>This is a Mailbox feed from """ + dashboard_title + """ for """ + recipient + """.</description>"""
    for entry in mailbox_file:
        if type(entry['time']) == str:
            loc_time = str(entry['time'])
        if type(entry['time']) == int or type(entry['time']) == float:
            loc_time = datetime.fromtimestamp(entry['time']).strftime(time_format)
        if entry['recipient'] == recipient:
            post_data = post_data + """
             <item>
                <title>""" + entry['call'] + ' - ' + str(entry['dmr_id']) + """</title>
                <link>""" + dashboard_url + """</link>
                <description>""" + entry['message'] + """ - """ + loc_time + """</description>
                <pubDate>""" + datetime.fromtimestamp(entry['time']).strftime('%a, %d %b %y') +"""</pubDate>
              </item>
    """
    return Response(rss_header + post_data + "\n</channel>\n</rss>", mimetype='text/xml')

@app.route('/api', methods=['GET'])
@app.route('/api/<api_mode>', methods=['POST'])
def api(api_mode=None):
    if request.method == 'GET':
        api_content = '<h3 style="text-align: center;"><strong>API Enabled: ' + str(use_api) + '</strong></h3>'
        return render_template('generic.html', title = dashboard_title, dashboard_url = dashboard_url, logo = logo, content = Markup(api_content), api = use_api)
    if use_api == 'True' or use_api == "true":
        #access_systems = ast.literal_eval(os.popen('cat ' + access_systems_file).read())
        #authorized_users = ast.literal_eval(os.popen('cat ' + authorized_users_file).read())
        api_data = request.json
        #print(type(api_data))
        #print((api_data))

        # Find out mode of JSON
    ##    try:
        # Filter msg_xfer
        if api_data['mode'] == 'msg_xfer':
            # Handle authorization
            if api_data['auth_type'] == 'private':
                #Authenticate
                if api_data['system_shortcut'] in authorized_users:
                    if api_data['credentials']['user'] == authorized_users[api_data['system_shortcut']]['user'] and api_data['credentials']['password'] == authorized_users[api_data['system_shortcut']]['password']:
                        print(api_data['credentials']['user'])
                        print(api_data['credentials']['password'])
                        for sms in api_data['data'].items():
                            sms_data = sms[1]
                            print((sms_data['destination_id']))
                            print((sms_data['source_id']))
                            print((sms_data['message']))
                            print((sms_data['slot']))
                            if sms_data['slot'] == 0:
                                send_slot = int(unit_sms_ts) - 1
                            if sms_data['slot'] == 1:
                                send_slot = 0
                            if sms_data['slot'] == 2:
                                send_slot = 1
                            send_sms(False, sms_data['destination_id'], sms_data['source_id'], 0000, 'unit', send_slot, sms_data['message'], que_dir)
                        return jsonify(
                            mode=api_data['mode'],
                            status='Generated SMS',
                        )
                    else:
                        message = jsonify(message='Authentication error')
                        return make_response(message, 401)
                else:
                    message = jsonify(message='System not authorized')
                    return make_response(message, 401)
            if api_data['auth_type'] == 'public':
##                auth_file = ast.literal_eval(os.popen('cat ' + auth_token_file).read())
##                for token in auth_file:
##                    print()
##                    print(token)
##                    print(api_data['auth_token'])
##                    print()
##                    if token == api_data['auth_token']:
##                        
##                        auth_file.remove(api_data['auth_token'])
##                        for i in api_data['data'].items():
##                            sms_data = i[1]
##                            if sms_data['slot'] == 0:
##                                send_slot = int(unit_sms_ts) - 1
##                            if sms_data['slot'] == 1:
##                                send_slot = 0
##                            if sms_data['slot'] == 2:
##                                send_slot = 1
##                            send_sms(False, sms_data['destination_id'], 0000, 0000, 'unit', send_slot, sms_data['message'])
##                        new_auth_file = auth_file
##                        with open(auth_token_file, 'w') as auth_token:
##                            auth_token.write(str(auth_file))
##                            auth_token.close()

                    return jsonify(
                            mode=api_data['mode'],
                            status='GNot implemented yet',
                        )
            else:
                message = jsonify(message='Not an authentication method')
                return make_response(message, 400)
        if api_data['mode'] == 'app':
            auth_file = ast.literal_eval(os.popen('cat ' + auth_token_file).read())
            print(auth_file)
            for token in auth_file:
                print()
                print(token)
                print(api_data['auth_token'])
                print()
                if token == api_data['auth_token']:
                    
                    auth_file.remove(api_data['auth_token'])
                    for i in api_data['data'].items():
                        sms_data = i[1]
                        if sms_data['slot'] == 0:
                            send_slot = int(unit_sms_ts) - 1
                        if sms_data['slot'] == 1:
                            send_slot = 0
                        if sms_data['slot'] == 2:
                            send_slot = 1
                        send_sms(False, sms_data['destination_id'], 0000, 0000, 'unit', send_slot, sms_data['message'], que_dir)
                    new_auth_file = auth_file
                    with open(auth_token_file, 'w') as auth_token:
                        auth_token.write(str(auth_file))
                        auth_token.close()
            
                    
                    return jsonify(
                            mode=api_data['mode'],
                            status='Token accepted, SMS generated',
                        )
##                if token != api_data['auth_token']:
##                    message = jsonify(message='Auth token not found')
##                    return make_response(message, 401)
                    
        else:
            message = jsonify(message='Mode not found')
            return make_response(message, 404)
    if use_api == "False" or use_api == "false":
            message = jsonify(message='API is disabled for this server')
            return make_response(message, 502)
    ##    except Exception as e:
    ##        message = jsonify(message='Error:' + str(e))
    ##        return make_response(message, 400)

#################### Run App ############################
if __name__ == '__main__':
    global use_api
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('-c', '--config', action='store', dest='CONFIG_FILE', help='/full/path/to/config.file (usually gps_data.cfg)')
    cli_args = arg_parser.parse_args()
    parser = ConfigParser()
    if not cli_args.CONFIG_FILE:
        print('\n\nMust specify a config file with -c argument.\n\n')
    parser.read(cli_args.CONFIG_FILE)
    ###### Definitions #####
    # Title of the Dashboard
    dashboard_title = parser.get('GPS_DATA', 'DASHBOARD_TITLE')
    # Logo used on dashboard page
    logo = parser.get('GPS_DATA', 'LOGO')
    dash_port = int(parser.get('GPS_DATA', 'DASH_PORT'))
    # IP to run server on
    dash_host = parser.get('GPS_DATA', 'DASH_HOST')
    #Description of dashboard to show on main page
    description = parser.get('GPS_DATA', 'DESCRIPTION')
    # The following will generate a help page for your users.

    # Data call type
    if parser.get('GPS_DATA', 'CALL_TYPE') == 'unit':
        data_call_type = 'Private Call'
    if parser.get('GPS_DATA', 'CALL_TYPE') == 'group':
        data_call_type = 'Group Call'
    if parser.get('GPS_DATA', 'CALL_TYPE') == 'both':
        data_call_type = 'Private or Group Call'
    # DMR ID of GPS/Data application
    data_call_id = parser.get('GPS_DATA', 'DATA_DMR_ID')
    # Default APRS ssid
    aprs_ssid = parser.get('GPS_DATA', 'USER_APRS_SSID')

    # Gateway contact info displayed on about page.
    contact_name = parser.get('GPS_DATA', 'CONTACT_NAME')
    contact_call = parser.get('GPS_DATA', 'CONTACT_CALL')
    contact_email = parser.get('GPS_DATA', 'CONTACT_EMAIL')
    contact_website = parser.get('GPS_DATA', 'CONTACT_WEBSITE')

    # Center dashboard map over these coordinates
    map_center_lat = float(parser.get('GPS_DATA', 'MAP_CENTER_LAT'))
    map_center_lon = float(parser.get('GPS_DATA', 'MAP_CENTER_LON'))
    zoom_level = int(parser.get('GPS_DATA', 'ZOOM_LEVEL'))
    map_theme = parser.get('GPS_DATA', 'MAP_THEME')

    # Time format for display
    time_format = parser.get('GPS_DATA', 'TIME_FORMAT')

    # RSS feed link, shows in the link section of each RSS item.
    dashboard_url = parser.get('GPS_DATA', 'DASHBOARD_URL')

    # Default APRS comment for users.
    default_comment = parser.get('GPS_DATA', 'USER_APRS_COMMENT')


    # DO NOT MODIFY BELOW HERE.
    bb_file = parser.get('GPS_DATA', 'BULLETIN_BOARD_FILE')
    loc_file = parser.get('GPS_DATA', 'LOCATION_FILE')
    emergency_sos_file = parser.get('GPS_DATA', 'EMERGENCY_SOS_FILE')
    the_mailbox_file = parser.get('GPS_DATA', 'MAILBOX_FILE')
    user_settings_file = parser.get('GPS_DATA', 'USER_SETTINGS_FILE')

    auth_token_file = parser.get('GPS_DATA', 'AUTHORIZED_TOKENS_FILE')
    use_api = parser.get('GPS_DATA', 'USE_API')
    #access_systems_file = parser.get('GPS_DATA', 'ACCESS_SYSTEMS_FILE')
    #authorized_users_file = parser.get('GPS_DATA', 'AUTHORIZED_USERS_FILE')

    que_dir = '/tmp/.hblink_data_que_' + str(parser.get('GPS_DATA', 'APRS_LOGIN_CALL').upper()) + '/'
    generate_apps()
    #Only create if API enabled
    if use_api == True:
        if Path(auth_token_file).is_file():
            pass
        else:
            Path(auth_token_file).touch()
            with open(auth_token_file, 'w') as auth_token:
                auth_token.write("[]")
                auth_token.close()
        if unit_sms_ts == 2:
            unit_sms_ts = 1
        if unit_sms_ts == 1:
            unit_sms_ts = 0
        try:
            #global authorized_users, other_systems
            #from authorized_apps import authorized_users, access_systems
            #access_systems = ast.literal_eval(os.popen('cat ' + access_systems_file).read())
            #authorized_users = ast.literal_eval(os.popen('cat ' + authorized_users_file).read())
            print('generaty')
        except Exception as e:
            print(e)

    # API settings
    #authorized_apps_file = parser.get('GPS_DATA', 'AUTHORIZED_APPS_FILE')
    # Default SMS TS for unit calls
    unit_sms_ts = parser.get('GPS_DATA', 'UNIT_SMS_TS')
    
    
    ########################
    
    app.run(debug = True, port=dash_port, host=dash_host)
