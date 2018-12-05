![TALR_logo](./Images/TALRlogo.png)

# Threat Alert Logic Repository (TALR)

A public repository for the collection and sharing of detection rules in platform agnostic formats. Collected rules are appended with STIX required fields for simplified sharing over TAXII servers.

Contains tools useful for translating from STIX to Sigma, and automating their ingestion/translation.

# Currently Supports:
* SIEM [as modified Sigma]

# Requirements:
Only required if using tools.
 
1. Python3 - required for pip
	```sudo apt-get install python3```
2. Pip - required to install the things
	```sudo apt-get install python3-pip```
4. JSON to YAML - required for stix2sigmac
	```pip3 install json2yaml```
5. sigmatools - required for stix2sigmac
	```pip3 install sigmatools```
6. OPTIONAL: figlet - For the intro banner
	```sudo apt-get install figlet```

# Goals:
* [X] Select SIEM rule sharing method (Tranlate to STIX, transport with TAXII)
* [X] Automate ingestion of SIEM rules from a STIX bundle (stix2sigmac)
* [ ] Publish public TAXII server for community testing

# Projects in use / Thanks:
* Sigma (https://github.com/Neo23x0/sigma/)
* STIX & TAXII (https://oasis-open.github.io/cti-documentation/)

# Contributors:
Nick Ascoli, Zachary Santoro, Brandon Martin, Tyler Fredrick, Kevin Foster
