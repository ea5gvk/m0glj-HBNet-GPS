## WORK IN PROGRESS

# How to install HBLink3 with D-APRS

### Note about different branches:

There are three different branches to the project. All three branches contain hblink and the D-APRS application. The **gps** branch contains the D-APRS application. The **aprs_features** branch contains the D-APRS application _and_ a modification to allow the beaconing of the location of connected peers, authored by **IU7IGU**. The **termux** branch is optimized to run on Android.


# Installation

Install the required modules.

`python3 -m pip install -r requirements.txt`

_**Note: Ignore any errors regarding smtplib as that module come by default on most Linux distributions.**_


# Configuration

There are 2 diferent ways to run the application. 
First, it can be run as a client, think of it as a receive only DMR hotspot. This is useful for operators who just want
 to add APRS functionality to a network. This is the simplest approach and allows for the greatest flexibility for implementing the gateway.
 The second method is designed for small networks and is highly experimental. Rather than adding the application as a client, the gateway is included in bridge.py. This allows for much simpler configuration, and theoretically would
 handle multiple position transmissions at the same time. However, it is not know how well it will scale up and what processor resources are required, use at your own risk.
 
 **It is reccommended to run the gateway as a client.**
 
 A stanza is a section of the configuration file that begins with brackets (example: **[GLOBAL]**). Below is a summary of each stanza found in the configuration. For more detailed definitions, see the example configurations.
 
 **[GLOBAL]**
 
 Contains settings for ACLs (access control) for the whole server. You also configure the path to configuration files and subscriber_ids here (leave as default).
 
 **[REPORTS]**
 
 Contains settings for network reporting. HBmonitor uses this. Leave as default.
 
 **[LOGGER]**
 
 Contains settings for logging to file, console, etc. Set log level here. Leave as default.
 
 **Note: The GPS_DATA stanza is only required in the configuration file that gps_data.py will be using.**
 
 **[GPS_DATA]**
 
  
 **See notes below to continue configuration**
 
 
 # D-APRS as a client
 
 **gps branch**
 
 Copy gps_data-SAMPLE.cfg to gps_data.cfg. Add a PEER stanza to connect to your network via MMDVM connection. You could also set a MASTER stanza and connect your network as a PEER. Connecting the gateway to your network as a PEER is much simpler though. 
 
 Add a MASTER stanza in you network configuration and call it something like "D-APRS". This is the MASTER that you will connect the gateway to as a client. You will need to modify rules.py on your network to allow the desired talkgroup/private calling to route to the gateway via MMDVM connection.
 
 **aprs_features branch**
 

 # D-APRS built into bridge.py
  
**gps branch**
 
**aprs_features branch**
 
