from flask import Flask, render_template, request, Response, Markup, jsonify, make_response

auth_dict = {
    3153591:'hello'
    }



app = Flask(__name__)

@app.route('/auth', methods=['POST'])
def auth():
    hblink_req = request.json
    print(type(auth_dict[hblink_req['id']]))
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
    return response


if __name__ == '__main__':

    app.run(debug = True, port=8080, host='127.0.0.1')
