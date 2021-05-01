##### This is the development version that supports the sending of SMS. This is a work in progress and is not meant to be used in production at this time. This will become the 2nd genreation of the project.

# HBLink3 with APRS/SMS Features

This is a **fork** of the [HBLink project](https://hblink-org.github.io/) that supports APRS and DMR SMS functions.

This repository contains everything needed to setup an HBLink server with APRS/SMS features.

The development server can be found at [https://hbl.ink](https://hbl.ink).

## Features

* Decode GPS locations and upload APRS position packets
* Each user/DMR ID can customize APRS options (SSID, icon, comment)
* Send and receive APRS messages as DMR SMS
* Ability to receive data as a private call or group call
* Trigger a command or script via DMR SMS
* Optional web dashboard to show APRS packets uploaded
* See location of radios on dashboard map
* Use built in API to send SMS to other HBLink servers
* Ability to disable APRS and just use dashboard map
* Use [external applications](https://github.com/kf7eel/hblink_sms_external_apps) (see [API Documentation](https://kf7eel.github.io/hblink3/api_doc.html)) for weather reports, email, and other information.

#### Required modules

* pynmea2
* aprslib
* maidenhead
* libscrc

#### Optional Modules
* Flask - Required for dashboard
* folium - Required for mapping on dashboard.

# Radio Compatibility

## Confirmed working:
Actually tested

 | Radio | GPS | SMS Decode | SMS Encode |
 |-------|:---:|:---:|:---:|
 | Anytone D878| YES | YES | YES |
 | Anytone D578| YES | YES | Most Likely |
 | BTech DMR-6x2 | YES | Most likely | Not Tested |
 | MD-380 (MD380tools, no GPS) | - | YES | WIP |
 | MD-380 (stock firmware, GPS) | YES | Most likely | Not Tested |
 | MD-390 (stock firmware) | YES | YES |  Not Tested |
 | Retevis RT73* | YES | YES |  Not Tested |
 | Ailunce HD1 | YES | YES |  Not Tested |
 
 *RT73 must have unconfirmed data setting enabled.

## Highly suspected to work:
Not tested yet, but will most likely work.

 | Radio | GPS | SMS Decode | SMS Encode |
 |-------|:---:|:---:|:---:|
 | Anytone D868 | Most likely | Most Likely | Most Likely |
 | TYT MD-2017 | Most likely | Likely | Unknown |
 | TYT MD-9600 | Most likely | Likely | Unknown |
 | Retevis RT8 | Most likely | Likely | Unknown |
 
 
## Tested, but with issues.
  Tested, but with bugs present.
  
 | Radio | GPS | SMS Decode | SMS Encode 
 |-------|:---:|:---:|:---:|
 | Alinco DJ-MD5TGP | WIP | Most likely | Not Tested |
 | Motorola DP3601| WIP | WIP | Not Tested |


## Would like to test:

Connect Systems GPS enabled radios

## How it works

A user should configure their radio for the DMR ID of the application and private or group call. When a position is received by the application, it will extract the coordinates and create an APRS position packet. The application will find the callsign of the user based on the sending radio's DMR ID. It is essential to have an up to date subscriber_ids file for this to work. A predefined APRS SSID is appended to the callsign. The APRS location packet is then uploaded to APRS-IS. No setup is required beforehand on the part of the user. This is pretty much "plug and play."

For example, N0CALL has a DMR ID of 1234567. N0CALL's radio sends a position to the application. The application will query the subscriber_ids file for DMR ID 1234567. The result will be N0CALL. An APRS location pack is created and uploaded to APRS-IS.

## Individual user/DMR ID APRS settings

By default, all APRS positions will have an SSID of 15, a default comment, and the callsign of the DMR user. These default settings can be changed. 

The comment, SSID, and icon can be set for each individual user/DMR ID the application sees. The application stores all the setting in a file. You may have different SSIDs, icons, and comments for different DMR IDs. This is done via DMR SMS using the following commands:

 | Command | Description | Example |
 |-------|:---:|:---:|
|**SSID**|Change SSID of user callsign.|`SSID 7`|
|**ICON**|Change the icon of the APRS position. *See [http://aprs.net/vm/DOS/SYMBOLS.HTM](http://aprs.net/vm/DOS/SYMBOLS.HTM) for icon list.|`icon /p`|
|**COM**|Change the comment of the APRS.|`COM This is a test comment.`|
|**MH**|Set you location by maidenhead grid square. Designed for radios with no GPS or that are not compatable yet.|`MH DN97uk`| 
|**BB**|Post a bulliten to the web dashboard.|`BB This is a test bulletin.`|
|**@[CALLSIGN W/ SSID] [MESSAGE]**|Send a message to another station via APRS.|`@N0CALL-15 This is a test.`|
|**[EMAIL ADDRESS] [MESSAGE]**|Send an email to an email address.|`test@example.org This is a test.`| 
|**REM MAIL**|Remove all mail (APRS messages, SMS, etc) addressed to you.|`REM MAIL`|
**@NOTICE**|Used to prominantly display a notice, similar to EMERGENCY activation.|`@NOTICE Server going down at 1800`|
|**@SOS**|EMERGENCY activation displays a banner on the main dashboard page.|`THIS IS AN EMERGENCY. @SOS`|
|**REM SOS**|Removes an EMERGENCY or notice.|`REM SOS`|
|**ID**|Responds by send an SMS containing your DMR ID.|`ID`|
|**TEST**| Responds with "This is a test." as an SMS.|`TEST`|
|**?[Network Shortcut] [DMR ID] [Message]**| Send an SMS to a user on another network.|`?XYZ 123456789 This is a test`|
|**?[App Shortcut] [Input]**|Send SMS to an external application.|`?BBD This is a test post.`|
|**APRS ON**|Enable sending and receiving of APRS messages.|`@APRS ON`|
|**APRS OFF**|Disable sending and receiving of APRS messages.|`@APRS OFF`|



Send a DMR SMS to the configured dmr_data_id in the application with the desired command followed by the value. For example, to change your icon to a dog, the command would be `@ICON /p` (see the icon table for values). Changing your SSID is as simple as `@SSID 7`, and `@COM Testing 123` will change the comment. 

Sending `@BB Test` will result in a post to the bulletin board with the message of "Test".


**To remove any of the stored values, just send the appropriate command without any input.** `@COM` will remove the stored comment, `@ICON` will remove the stored icon, and `@COM` will remove the stored comment. Any position now reports sent will have the default settings.

## API
The API built in to the dashboard can be used to exchange SMS with other HBLink servers/networks or be used to access external applications that provide functionality via SMS. Multiple servers/networks can share a single external application.

See [hbl.ink](https://hbl.ink) for publicly accessible external applications that you can use.

See [API documentation](https://kf7eel.github.io/hblink3/).

Repository for [external applications](https://github.com/kf7eel/hblink_sms_external_apps), if you want to host your own.


## Web Dashboard

The web dashboard is completely optional. Python module flask is required for this to work. The web dashboard will display the last 15 positions of radios sent to APRS-IS. The dashboard will also sh user bulletin. A bulletin is a message sent via SMS that will display on the web dashboard. There are several uses for this, including: testing SMS functionality of radio, announcements, and moire. It is a novel feature. The page will automatically reload every 2 minutes. Setup is rather simple. Just modify the example config in the dashboard directory and rename it to dashboard_settings.py. Then start dashboard.py. 

## APRS messaging

You can send and receive APRS messages via DMR SMS. APRS messages received by the gateway are automatically sent to your DMR ID as a private SMS.

## APRS TOCALL

The project was granted a [tocall](http://www.aprs.org/aprs11/tocalls.txt) of **APHBLx** by Bob Bruniga, WB4APR. This will identify that your APRS position came from HBLink. The x on the end can be any letter/number. Here are the current designations of APHBLx:

* **APHBL3** - HBlink3 D-APRS gateway
* **APHBLD** - DMRlink D-APRS gateway (the IPSC version of the project)


## Configuration

See hblink_SAMPLE.cfg, rules_SAMPLE.py, and gps_data_SAMPLE.cfg for examples.

## Special thanks to:

**N0MJS** - For creating HBLink and dmr_utils. This project not possible without him.

**IU7IGU** - For creating APRS position beaconing for PEER connections.

**IV3JDV** - For helping debug SMS in Anytone radios.

**KD7LMN** - For pointing out a critical bug.

**KB5PBM** - For helping implement support for MD-380 type radios.

**EI7IG** - For writing the page explaining MD-380 type GPS packets.

**M0GLJ** - For assisting with Motorola testing.

**W4DBG** - For early testing.

**IW7EDX** - For contributing code.

**Xavier FRS2013** - For contributing and cleaning up code.

## Resources for DMR data

I spent many hours looking at the following for this project. You may find these links useful.

https://github.com/travisgoodspeed/md380tools/issues/160

https://jpronans.github.io/ei7ig/dmr.html

http://cloud.dstar.su/files/G4KLX/MMDVM/MMDVM%20Specification%2020150922.pdf

https://wiki.brandmeister.network/index.php/NMEA_Location_Reporting

https://forums.radioreference.com/threads/motorola-lrrp-protocol.370081/

https://forums.radioreference.com/threads/lrrp-decoding.359575/

https://github.com/polkabana/go-dmr

https://github.com/nonoo/dmrshark

https://wiki.brandmeister.network/index.php/Compressed_Location_Reporting

All of the ETSI DMR documents (ETSI 102 361-1 through 361-4).

The Shark RF forums.

---
### FOR SUPPORT, DISCUSSION, GETTING INVOLVED ###

Please join the DVSwitch group at groups.io for online forum support, discussion, and to become part of the development team.

DVSwitch@groups.io 

A voluntary registrty for HBlink systems with public access has been created at http://hblink-register.com.es Please consider listing your system if you allow open access.

---

## PROJECT: Open Source HomeBrew Repeater Proctol Client/Master. ##

**UPDATES:**

**PURPOSE:** Thanks to the work of Jonathan Naylor, G4KLX; Hans Barthen, DL5DI; Torsten Shultze, DG1HT we have an open protocol for internetworking DMR repeaters. Unfortunately, there's no generic client and/or master stacks. This project is to build an open-source, python-based implementation. You are free to use this software however you want, however we ask that you provide attribution in some public venue (such as project, club, organization web site). This helps us see where the software is in use and track how it is used.

For those who will ask: This is a piece of software that implements an open-source, amateur radio networking protocol. It is not a network. It is not intended to be a network. It is not intended to replace or circumvent a network. People do those things, code doesn't.
  
**PROPERTY:**  
This work represents the author's interpretation of the HomeBrew Repeater Protocol, based on the 2015-07-26 documents from DMRplus, "IPSC Protocol Specs for homebrew DMR repeater" as written by Jonathan Naylor, G4KLX; Hans Barthen, DL5DI; Torsten Shultze, DG1HT, also licenced under Creative Commons BY-NC-SA license.

**WARRANTY**
None. The owners of this work make absolutely no warranty, express or implied. Use this software at your own risk.

**PRE-REQUISITE KNOWLEDGE:**  
This document assumes the reader is familiar with Linux/UNIX, the Python programming language and DMR.  

**Using docker version**

To work with provided docker setup you will need:
* A private repository with your configuration files (all .cfg files in repo will be copyed to the application root directory on start up)
* A service user able to read your private repository (or be brave and publish your configuration, or be really brave and give your username and password to the docker)
* A server with docker installed
* Follow this simple steps:

Build your own image from source

```bash

docker build . -t millaguie/hblink:3.0.0

```

Or user a prebuilt one in docker hub: millaguie/hblink:3.0.0

Wake up your container

```bash
touch /var/log/hblink.log
chown 65000  /var/log/hblink.log
 run -v /var/log/hblink.log:/var/log/hblink.log -e GIT_USER=$USER -e GIT_PASSWORD=$PASSWORD -e GIT_REPO=$URL_TO_REPO_WITHOUT_HTTPS://  -p 54000:54000  millaguie/hblink:3.0.0
 ```

**MORE DOCUMENTATION TO COME**

***0x49 DE N0MJS***

Copyright (C) 2016-2020 Cortney T. Buffington, N0MJS n0mjs@me.com

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
