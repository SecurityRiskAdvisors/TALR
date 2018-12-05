# TOOLS

# stix2sigmac:
Takes a STIX bundle, finds the sigma rules, runs them against sigmac with your desired parameters, and exports the STIX objects to a local directory.
Enter the following in the scripts location in the command line:

Open a terminal and navigate to the scripts location, and give it execute permissions:
```cd /LOCATION/OF/SCRIPT/```
```chmod +x stix2sigmac.sh```

Enter the following in the command line, using your parameters:
```./stix2sigmac import [PRODUCT_TYPE or CATEGORY or SERVICE or ATTACK_TACTIC] [/DIRECTORY/WITH/STIX_BUNDLE/] [BUNDNLE_NAME.json] [DIRECTORY/TO/PLACE_RULES/] [SIEM] [BACKEND_OPTIONS]```

Example:

* ```./stix2sigmac import windows /etc/taxii/bundles/ dailybundle.json /etc/siemrules/ splunk none```
* ```./stix2sigmac import lateral_movement /etc/taxii/bundles/ bundleX.json /etc/siemrules/ splunk none```
* ```./stix2sigmac import application /etc/taxii/bundles/ objectUpdates.json /etc/taxii/ splunk none```
* ```./stix2sigmac import VPN /etc/taxii/imports/ siemrules.json /home/rulesrepo/myrules/ splunk -Orulecomment=True```
* ```./stix2sigmac import antivirus /misc/taxii/exportbundles/ aptupdates.json /etc/sigma/ es-dsl -Oes=http://localhost:9200,output=curl```

Product/Category/Service/ATT&CK Type Examples:

* ```all``` Will get all rules
* ```lateral_movement``` Will get rules for lateral movement detection
* ```windows``` Will get windows rules
* ```application``` Will get windows application rules
* ```linux``` Will get all linux rules
* ```VPN``` Will get any rules for VPN products
* etc...

#Next Steps:

* Combine seperated detections that were seperated by a STIX bundle (currently in dev)