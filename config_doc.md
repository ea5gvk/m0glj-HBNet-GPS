# Configuration

## full_bridge.cfg

DATA_DMR_ID and CALL_TYPE, the DMR ID of the gateway. Call type specifies if you want to receive private data or group data. can be set to both to receive private and group data. Options: unit, group, both.

UNIT_SMS_TS. This is the default timeslot that an SMS is sent on. Every time a user keys the radio, whether a private call or talkgroup, the server saves the timeslot that the user is on. By default, an SMS is routed to the last known timeslot of a user. When the last timeslot is not know, UNIT_SMS_TS is used. For example, if the user has not transmitted in a long time, and APRS message is received, the generated SMS will be sent on UNIT_SMS_TS.

### APRS Configuration

USER_APRS_SSID and USER_APRS_COMMENT, the default SSID and coment for users. Users can change this in the dashboard or via SMS command.

APRS_LOGIN_CALL, APRS_LOGIN_PASSCODE, APRS_SERVER, and APRS_PORT, configuration used to login to an APRS server.

APRS_FILTER, sent to server for receiving specific packets. See [http://www.aprs-is.net/javAPRSFilter.aspx](http://www.aprs-is.net/javAPRSFilter.aspx) for filter options.

IGATE_, configuration for uploading the position of the gateway to APRS-IS. When the gateway uploads a position, APRS software such as aprs.fi will see it as an Igate. This is useful if you want aprs.fi or other APRS software to keep statistics. Time is set in minutes. Set IGATE_BEACON_TIME to 0 to disable Igate beaconing.

### Static Positions

In September of 2020, Daniele Marra (**IU7IGU**) created a function in HBLink that creates an APRS postiion for connected PEERS (repeaters, hotpots, etc) and send it to APRS-IS. His has been modified and included with this project to give it this functionality. APRS_STATIC_REPORT_INTERVAL is how often a position for a repeater of hotspot is uploaded to APRS-IS (must be greater than 15). APRS_STATIC_MESSAGE is the comment of the APRS position.

In each MASTER stanza, you will find the option STATIC_APRS_POSITION_ENABLED. Setting this to True will cause HBLink to sent the position of connected repeaters or hotspots to APRS-IS. Setting this to False will disable sending positions of connected peers. **This option does not affect the operation of GPS positions or SMS to individual radios**, it is used only if you want a position for hotspots/repeaters on APRS.

### LOCATION_FILE, BULLETIN_BOARD_FILE, MAILBOX_FILE, EMERGENCY_SOS_FILE, USER_SETTINGS_FILE

These options specify where to save and retrieve data used by HBLink and the D-APRS dashboard. It is OK to leave these at the default value. When saved in /tmp, the files will be lost when the server reboots. Change to a different directory to prevent the loss of the files after a reboot
**USER_SETTINGS_FILE must be set. An absolute path is required.**

### API Configuration

The API allows users to interact with external applications via SMS. The API also allows users to send messages to other users on a different network/server.

Set USE_APT to True to enable it.
AUTHORIZED_TOKENS_FILE, OK to leave as default. This is the file where one time tokens are saved.

MY_SERVER_SHORTCUT, should be something short, ideally 3 or 4 letters. This is used in the authentication and sending process. Should be unique from other servers, especially if you plan on allowing public access.

SERVER_NAME, the name of your server or network. This is used to identify your server with some external applications.

USE_PUBLIC_APPS, allow your users to use publicly accessible external applications. If set to True, every time HBLink is started, it downloads the latest list of publicly accessible external applications from the URL in PUBLIC_APPS_LIST. Leave PUBLIC_APPS_LIST as the default value to use the ["official" list](https://github.com/kf7eel/hblink_sms_external_apps/blob/main/public_systems.txt).

RULES_PATH, the absolute path to your rules.py. The D-APRS dashboard uses this to authenticate incoming API data. **You MUST set this with the absolute path to rules.py**

### D-APRS Dashboard Configuration

DASHBOARD_TITLE, title displayed on dashboard page. Can be different than SERVER_NAME.

DASHBOARD_URL is used for the API, RSS feed link, etc. This MUST be accessible from the internet. Do not add a trailing /. Can be a URL to an IP address.

LOGO, link to an image file.

DASH_PORT and DASH_HOST, port and IP address to run the dashboard. If IP set to 127.0.0.1, dashboard will only be accessible on localhost.

DESCRIPTION, description of dashboard.

TIME_FORMAT, format to display time in. Can be changed from default. Default format in month, day, year.

MAP_CENTER_LAT, MAP_CENTER_LON, ZOOM_LEVEL. The Latitude and Longitude to center the map at. ZOOM_LEVEL, default zoom level to display.

MAP_THEME, theme of the map. The following are options for map themes and just work, you should use one of these: “OpenStreetMap”, “Stamen” (Terrain, Toner, and Watercolor). List and preview of some map themes at [http://leaflet-extras.github.io/leaflet-providers/preview/](List and preview of some map themes at http://leaflet-extras.github.io/leaflet-providers/preview/).


----

## rules.py

UNIT, list the names of each system that should bridge unit to unit (individual) calls..

UNIT_TIME, this is also known as unit call flood timeout. This is the amount of time to keep sending private calls to a single system before
flooding all systems in UNIT with the call. A higher value means that the subscriber is mapped to a specific system for a longer period on time (in minutes). This can be set high for systems where subscribers are not moving between systems often (such as a group of hotspots). A lower value can be set for systems that have subscribers moving between systems often (switching repeaters often).

STATIC_UNIT. There are some instances where mapping a private call to a particular system should happen every time. An example use of this would be gps_data.py, where GPS data will always go. There is no need to flood every system with this data. Adding an entry here will route private calls and data to the specified system and not the other systems. For this to work, a system in STATIC_UNIT should not also be in UNIT.

STATIC_UNIT is optional and not required.

authorized_users, stored authentication credentials for other networks/servers that can your server SMS messages (using msg_xfer mode in the API). This list is manually specified and is optional.

local_systems, information about other networks/servers or publicly accessible external applications. This list is added to the public list when HBLink starts. Use this to manually specify non public external applications or non public servers/networks. See the API documentation for more information.
