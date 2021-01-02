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

from flask import Flask, render_template
import ast, os
from dashboard_settings import *

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
        dash_loc = ast.literal_eval(os.popen('cat /tmp/gps_data_user_loc.txt').read())
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
    <h2>&nbsp;<strong>Local Time</strong>&nbsp;</h2>
    </td>
    </tr>
    '''
        for e in dash_loc:
            tmp_loc = tmp_loc + '''<tr>
    <td style="text-align: center;"><a href="https://aprs.fi/''' + e['call'] + '''"><strong>''' + e['call'] + '''</strong></a></td>
    <td style="text-align: center;"><strong>&nbsp;''' + str(e['lat']) + '''&nbsp;</strong></td>
    <td style="text-align: center;"><strong>&nbsp;''' + str(e['lon']) + '''&nbsp;</strong></td>
    <td style="text-align: center;">&nbsp;''' + e['time'] + '''&nbsp;</td>
    </tr>'''
        return str(str('<h1 style="text-align: center;">Positions Received</h1>') + tbl_hdr + loc_hdr + tmp_loc + tbl_ftr)
    except:
        return str('<h1 style="text-align: center;">No data</h1>')


def get_bb_data():
    try:
        dash_bb = ast.literal_eval(os.popen('cat /tmp/gps_data_user_bb.txt').read())
        tmp_bb = ''
        
        bb_hdr = '''
    <tr>
    <td style="text-align: center;">
    <h2><strong>&nbsp;Callsign&nbsp;</strong></h2>
    </td>
    <td style="text-align: center;">
    <h2>&nbsp;<strong>DMR ID</strong>&nbsp; </h2>
    </td>
    <td style="text-align: center;">
    <h2>&nbsp;<strong>Bulletin</strong>&nbsp;</h2>
    </td>
    <td style="text-align: center;">
    <h2>&nbsp;<strong>Local Time</strong>&nbsp;</h2>
    </td>
    </tr>
    '''
        
        for e in dash_bb:
            tmp_bb = tmp_bb + '''<tr>
    <td style="text-align: center;"><strong>&nbsp;''' + e['call'] + '''&nbsp;</strong></td>
    <td style="text-align: center;">''' + str(e['dmr_id']) + '''</td>
    <td style="text-align: center;"><strong>&nbsp;''' + e['bulliten'] + '''&nbsp;</strong></td>
    <td style="text-align: center;">&nbsp;''' + e['time'] + '''&nbsp;</td>
    </tr>'''

        return str('<h1 style="text-align: center;">Bulletin Board</h1>' + tbl_hdr + bb_hdr + tmp_bb + tbl_ftr)
    except:
        return str('<h1 style="text-align: center;">No data</h1>')

@app.route('/')
def index():
    #return get_data()
    return render_template('index.html', title = dashboard_title, logo = logo)
@app.route('/bulletin_board')
def dash_bb():
    return get_bb_data()
    #return render_template('index.html', data = str(get_data()))
@app.route('/positions')
def dash_loc():
    return get_loc_data()
    #return render_template('index.html', data = str(get_data()))
##@app.route('/<string:page_name>/')
##def render_static(page_name):
##    return render_template('%s.html' % page_name, title = dashboard_title, logo = logo, description = description)
@app.route('/help')
def help():
    #return get_data()
    return render_template('help.html', title = dashboard_title, logo = logo, description = description, data_call_type = data_call_type, data_call_id = data_call_id)
@app.route('/about')
def about():
    #return get_data()
    return render_template('about.html', title = dashboard_title, logo = logo, contact_name = contact_name, contact_call = contact_call, contact_email = contact_email, contact_website = contact_website)_name__ == '__main__':
    app.run(debug = True, port=dash_port, host=dash_host)
