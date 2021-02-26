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
 
 # D-APRS as a client
 
 **gps branch**
 
 **aprs_features branch**
 

 # D-APRS built into bridge.py
  
**gps branch**
 
**aprs_features branch**
 
