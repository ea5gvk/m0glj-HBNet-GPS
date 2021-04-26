## [Home](https://kf7eel.github.io/hblink3/) | [Configuration](/hblink3/config_doc.html) | [API Documentation](https://kf7eel.github.io/hblink3/api_doc.html) | [HBlink Website](https://hblink-org.github.io/)

The API is a new feature that allows users to interact with external applications via SMS and send messages users on other HBLink servers. The API is built into the D-APRS dashboard. All interaction takes place over HTTP POST requests in JSON format. This allows a single application to be used by multiple servers. Applications can be delevopen in multiple langauges.

There are presently 3 modes for data  exchange, "**msg_xfer**", "**app**", and "**raw**". 

**msg_xfer** is used to send a message. When the D-APRS dashboard receives a msg_xfer request, it generates an SMS message and places it in HBLink's SMS sending que.

With msg_xfer, there are 2 authentication types, "public" and "private". With private authentication, the requesting server (or application) must provide a username and password, specified in _authorized_users_ of the receiving server's rules.py. Public authentication is still a work in progress.

Here is an example of a msg_xfer JSON POST using private authentication:

`{
    "mode": "msg_xfer",
    "system_shortcut": "ABC",
    "server_name": "Test HBlink Network",
    "response_url": "http://localhost:8093/api/",
    "auth_type": "private",
    "credentials": {
        "user": "test_name",
        "password": "passw0rd"
    },
    "data": {
        "1": {
            "source_id": 1234,
            "destination_id": 3153591,
            "slot": 0,
            "msg_type": "unit",
            "msg_format": "motorola",
            "message": "text of the message"
        },
        "2": {
            "source_id": 1234,
            "destination_id": 3153591,
            "slot": 0,
            "msg_type": "unit",
            "msg_format": "motorola",
            "message": "text of the 2nd message"
        }
    }
}`