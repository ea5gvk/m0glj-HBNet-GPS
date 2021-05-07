from flask import Flask, render_template, request, Response, Markup, jsonify, make_response

auth_dict = {
    3153591:0,
    3153597:''
    }



app = Flask(__name__)

@app.route('/')
def index():
    value = Markup('<strong>The HTML String</strong>')
    return value
    #return render_template('index.html', title = dashboard_title, dashboard_url = dashboard_url, logo = logo, emergency = check_emergency(), api = use_api)


@app.route('/auth', methods=['POST'])
def auth():
    hblink_req = request.json
    #print((auth_dict[hblink_req['id']]))
    #try:
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
##    except:
        response = jsonify(
                    allow=False)
    return response


if __name__ == '__main__':

    app.run(debug = True, port=8080, host='127.0.0.1')
