# Installation
----

## [Home](https://kf7eel.github.io/hblink3/) | [Installation/Configuration](/hblink3/install.html) | [HBlink Website](https://hblink-org.github.io/)


----
## WORK IN PROGRESS


### Note about different branches:

There are three different branches to the project. All three branches contain hblink and the D-APRS application. The **gps** branch contains the D-APRS application. The **aprs_features** branch contains the D-APRS application _and_ a modification to allow the beaconing of the location of connected peers, authored by **IU7IGU**. The **termux** branch is optimized to run on Android.


# Installation

Clone the git repository.

`git clone https://github.com/kf7eel/hblink3`

Change directory to hblink3.

`cd hblink3`

Install the required modules.

`python3 -m pip install -r requirements.txt`

_**Note: Ignore any errors regarding smtplib or traceback as those modules come by default on most Linux distributions.**_


# Configuration

There are 2 diferent ways to run the application. 
First, it can be run as a client, think of it as a receive only DMR hotspot. This is useful for operators who just want
 to add APRS functionality to a network. This is the simplest approach and allows for the greatest flexibility for implementing the gateway.
 The second method is designed for small networks and is highly experimental. Rather than adding the application as a client, the gateway is included in bridge.py. This allows for much simpler configuration, and theoretically would
 handle multiple position transmissions at the same time. However, it is not know how well it will scale up and what processor resources are required, use at your own risk.
 
 **It is reccommended to run the gateway as a client.**
 
 A stanza is a section of the configuration file that begins with brackets (example: **[GLOBAL]**). A MASTER stanza is a section of the configuration that will accept incomming connections from clients (peers). A PEER stanza is a section of configuration that will connect to another MMDVM server. Below is a summary of each stanza found in the configuration. **For more detailed definitions, see the example configurations.**
 
 **[GLOBAL]**
 
 Contains settings for ACLs (access control) for the whole server. You also configure the path to configuration files and subscriber_ids here (leave as default).
 
 **[REPORTS]**
 
 Contains settings for network reporting. HBmonitor uses this. Leave as default.
 
 **[LOGGER]**
 
 Contains settings for logging to file, console, etc. Set log level here. Leave as default.
 
 **[GPS_DATA]**

**Note: The GPS_DATA stanza is only required in the configuration file that gps_data.py will be using.**

 DATA_DMR_ID - This is the DMR ID that users send DMR GPS data.
 
 CALL_TYPE - group, unit, or both. Group if you want users to send data to a talkgroup, unit if you want users to send data as a private call, or both if you     want both options.
 
 USER_APRS_SSID - Default APRS SSID assigned to user APRS positions.
 
 USER_APRS_COMMENT - Default Comment attached to user APRS positions.
 
 APRS_LOGIN_CALL, PASSCODE, SERVER, and PORT - Login settings for APRS-IS. Setting APRS_LOGIN_CALL to N0CALL will cause the gateway to not upload packets to  APRS server.
 
 The IGATE settings are only applicable if you are using the gps_data_beacon_igate script. The gps_data_beacon_igate script uploads the position of the gateway as configured. This will cause APRS clients (such as aprs.fi) to see the gateway as an igate and keep statistics about it. The igate script does not effect the operation gps_data itself. Time in minutes.
 
 The email gateway settings are OPTIONAL. They are NOT REQUIRED if you don't want to enable the email gateway. Leave as is to disable.
 
 
 **[ALIASES]**
 
 This is the configuration for downloading the latest DMR ID database from radioid.net. Default setting will fetch new DB every 7 days.
  
  
 _**See notes below to continue configuration**_
 
 
### D-APRS as a client
 
 Copy gps_data-SAMPLE.cfg to gps_data.cfg. Add a PEER stanza to connect to your network via MMDVM connection. Connecting the gateway to your network as a PEER is a fairly simple process. Add a MASTER stanza in you network configuration and call it something like "D-APRS". This is the MASTER that you will connect the gateway to as a client. You will need to modify rules.py on your network to allow the desired talkgroup/private calling to route to the gateway via MMDVM connection.
 
 You could also set a MASTER stanza and connect your network as a PEER. This is more suited for advanced users.
 
 Mention rules.py

#### gps branch

No more configuration reguired.

#### aprs_features branch

Modify the APRS stanza to your liking.

 **[APRS]**

**Note: This APRS stanza only applies to the _aprs_features_ beanch of the project. It is requires for beaconing the position of connected peers (repeaters or hotspots) and does not affect any GPS data from radios. This stanza only needs to be in hblink.cfg.**
 
 This stanza contains the settings for APRS-IS, this stanza only applies to the **_aprs_features_** branch. When beaconing the location of a connected hotspot or repeater (not GPS location of a radio), the settings here are used.
 
 You will also need to add **APRS: True** (or False) to each of your MASTER stanzas in hblink.cfg. Setting to false will disable the reporting of PEER locations (repeaters or hotspots) on the current MASTER stanza.
 
 See example hblink-SAMPLE.cfg in **aprs_features** branch.

### D-APRS built into bridge.py

Using this method, there is no need to have a gps_data.cfg file, or separate script running. The D-APRS gateway is "baked" into bridge.py. This is also much simpler to configure.

Simply modify hblink.cfg to your liking, ensuring that the GPS_DATA stanza is in hblink.cfg. If you are using the **aprs_features** branch, ensuse that the APRS stanza is in hblink.cfg and that **APRS: True** (or false) is in each MASTER stanza. Thats it. See hblink-SAMPLE.cfg in **aprs_features** branch.
  
 

 
