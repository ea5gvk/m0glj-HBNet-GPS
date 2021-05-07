from flask import Flask, render_template, request, Response, Markup, jsonify, make_response
from config import *
import base64, hashlib
from dmr_utils3.utils import int_id, bytes_4

auth_dict = {}



app = Flask(__name__)

def gen_passphrase(dmr_id):
    _new_peer_id = bytes_4(int(str(dmr_id)[:7]))
    calc_passphrase = base64.b64encode((_new_peer_id) + append_int.to_bytes(2, 'big'))
    return str(calc_passphrase)[2:-1]


@app.route('/gen', methods = ['POST', 'GET'])
def gen():
    #content = Markup('<strong>The HTML String</strong>')
    user_id = request.args.get('user_id')
    print(user_id)
    print(request.args.get('mode'))
    if request.args.get('mode') == 'generated':
        auth_dict.update({int(user_id):''})
        content = '''
    <p style="text-align: center;">Your passphrase for <strong>''' + str(user_id) + '''</strong>:</p>
    <p style="text-align: center;"><strong>''' + str(gen_passphrase(int(user_id))) + '''</strong></p>
'''
    if request.args.get('mode') == 'legacy':
        auth_dict.update({int(user_id):0})
        content = '''<p style="text-align: center;">Using legacy auth</p>'''
    if request.args.get('mode') == 'custom':
        auth_dict.update({int(user_id):str(request.args.get('custom'))})
        content = '''<p style="text-align: center;">Using custom auth passphrase: ''' + request.args.get('custom') + '''</p>'''
    
    print(auth_dict)
            
    
    return render_template('generic.html', title = title, url = url, logo = logo, content = Markup(content))



@app.route('/')
def index():
    #content = Markup('<strong>The HTML String</strong>')
    content = '''
<table style="width: 600px; margin-left: auto; margin-right: auto;" border="3">
<tbody>
<tr>
<td><form action="gen" method="get">
<table style="margin-left: auto; margin-right: auto;">
<tbody>
<tr style="height: 62px;">
<td style="text-align: center; height: 62px;">
<h2><strong><label for="user_id">DMR ID</label></strong></h2>
</td>
</tr>
<tr style="height: 51.1667px;">
<td style="height: 51.1667px; text-align: center;"><input id="user_id" name="user_id" type="text" /></td>
</tr>
<tr style="height: 51.1667px;">
<td style="height: 51.1667px; text-align: center;"><select name="mode">
<option selected="selected" value="generated">Generated Passphrase</option>
<option value="legacy">Legacy</option>
<option value="custom">Custom</option>
</select></td>
</tr>
<tr style="height: 51.1667px;">
<td style="height: 51.1667px;">Custom Password (only use if custom is selected): <input id="custom" name="custom" type="text" /></td>
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
        
    
    return render_template('generic.html', title = title, url = url, logo = logo, content = Markup(content))

@app.route('/auth', methods=['POST'])
def auth():
    hblink_req = request.json
    print((hblink_req))
    print(auth_dict)
    if hblink_req['secret'] in shared_secrets:
        if hblink_req['id'] in auth_dict:
            if auth_dict[hblink_req['id']] == 0:
                response = jsonify(
                        allow=True,
                        mode='legacy',
                        )
            elif auth_dict[hblink_req['id']] == '':
            # normal
                response = jsonify(
                        allow=True,
                        mode='normal',
                        )
            elif auth_dict[hblink_req['id']] != '' or auth_dict[hblink_req['id']] != 0:
                response = jsonify(
                        allow=True,
                        mode='override',
                        value=auth_dict[hblink_req['id']]
                            )
        if hblink_req['id'] not in auth_dict:
            response = jsonify(
                        allow=False)
    else:
        message = jsonify(message='Authentication error')
        response = make_response(message, 401)
        
    return response


if __name__ == '__main__':

    app.run(debug = True, port=ums_port, host=ums_host)
