#!/usr/bin/env python
#
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

from flask import Flask
import ast, os

app = Flask(__name__)
dash_entries = ast.literal_eval(os.popen('cat /tmp/gps_data_user_loc.txt').read())
#dash_bb = ast.literal_eval(os.popen('cat /tmp/gps_data_user_bb.txt').read())

def get_data():
    dash_loc = ast.literal_eval(os.popen('cat /tmp/gps_data_user_loc.txt').read())
    dash_bb = ast.literal_eval(os.popen('cat /tmp/gps_data_user_bb.txt').read())
    tmp_bb = ''
    tmp_loc = ''
    tbl_hdr = '''
<table style="border-color: black; margin-left: auto; margin-right: auto;" border="2" cellspacing="6" cellpadding="2"><tbody>
'''
    tbl_ftr = '''
</tbody>
</table>
'''
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
    
    for e in dash_bb:
        tmp_bb = tmp_bb + '''<tr>
<td style="text-align: center;"><strong>&nbsp;''' + e['call'] + '''&nbsp;</strong></td>
<td style="text-align: center;">''' + str(e['dmr_id']) + '''</td>
<td style="text-align: center;"><strong>&nbsp;''' + e['bulliten'] + '''&nbsp;</strong></td>
<td style="text-align: center;">&nbsp;''' + e['time'] + '''&nbsp;</td>
</tr>'''
    for e in dash_loc:
        tmp_loc = tmp_loc + '''<tr>
<td style="text-align: center;"><strong>&nbsp;''' + e['call'] + '''&nbsp;</strong></td>
<td style="text-align: center;">&nbsp;''' + str(e['lat']) + '''&nbsp;</td>
<td style="text-align: center;">&nbsp;''' + str(e['lon']) + '''&nbsp;</td>
<td style="text-align: center;">&nbsp;''' + e['time'] + '''&nbsp;</td>
</tr>'''
    return str('<h1 style="text-align: center;">Bulletin Board</h1>' + tbl_hdr + bb_hdr + tmp_bb + tbl_ftr + str('<h1 style="text-align: center;">Positions Received</h1>') + tbl_hdr + loc_hdr + tmp_loc + tbl_ftr)

@app.route('/')
def dash():
    #return 'Hello, World!'
    return get_data()
