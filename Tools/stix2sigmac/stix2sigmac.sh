#! /bin/sh
# stix2sigmac
# Author: Nick Ascoli
#--------------------------------------------
# This script is designed to pull sigma rules from a STIX bundle and run them through sigmac
# Exported rules will be stored in the directory of your choice
# To use: navigate to the directory w/ the script: ./stix2sigmac import [PRODUCT_TYPE or CATEGORY or SERVICE or ATTACK_TECHNIQUE] [/DIRECTORY/WITH/STIX_BUNDLE/] [BUNDNLE_NAME.json] [/DIRECTORY/TO/PLACE_RULES/] [-OBACKENDOPTIONS]
#--------------------------------------------

# ---------- IMPORT SIGMA RULES ----------------------------------------------
importRules()
{
    local requiredArgs=7
    # Make a log file if it doesnt exist
    if [ ! -e $rulesLocation"log.csv" ]; then
            echo "DATE, OBJECT, ACTION" >> $rulesLocation"log.csv"
    fi
    echo "$(date), stix2sigmac.sh version $ver, script started" >> $rulesLocation"log.csv"
    echo "$(date), arguments, import param called on arguments" >> $rulesLocation"log.csv"

    # If the amount of arguments is not correct, error. Otherwise - move on to rule translation and importing
    if [ $num_args != $requiredArgs ]; then
        echo "- Arguments error. You passed in $num_args parameters, $requiredArgs are required."
        echo "- For 'import' Please enter import(SPACE)product_type, category, or service(SPACE)Bundle_directory(SPACE)bundle_name(SPACE)export_directory(SPACE)SIEM(SPACE)BACKENDOPTIONS"
        echo "- Directories and file names cannot include spaces."
        echo "- EXAMPLE: ./stix2sigmac import windows /etc/taxii/bundles/ dailybundle.json /etc/stix/sigmarules/ splunk -Orulecomment=True"
        echo "$(date), parameters, bad parameter count exiting script" >> $rulesLocation"log.csv"
        exit 0
    else
        echo ${cyan}
        echo "Importing ${green}$importFilter${cyan} rules from ${blue}$bundleLocation${yellow}$bundleName${cyan} to ${blue}$rulesLocation ${cyan}in ${green}$SIEM ${green}${cyan}syntax with the following backend options:${teal}$backendOptions!"
        echo ""
        cd $bundleLocation
        
        # Translate STIX objects to YAML and puts them in the identified directory
        json2yaml $bundleName SigmacMe.yml
        mv SigmacMe.yml $rulesLocation
        echo "$(date), $bundleName, Bundle translated to yaml in SigmacMe.yml" >> $rulesLocation"log.csv"
        cd $rulesLocation

        # Remove the STIX bundle lines, and backspace line twice, so the rule will work with SigmaC
        sed '1,4d' -i SigmacMe.yml
        sed -i 's/^..//' SigmacMe.yml
        sed -i 's/_type/_t1pe/g' SigmacMe.yml # Replace any other occurences of the word type that may appear in the STIX bundle
        echo "$(date), $bundleName, SigmacMe.yml moved to $rulesLocation" >> $rulesLocation"log.csv"

        # Break the bundle down into individual YAML files, remove the original bundle, and get a rule count
        awk '/type/{x="rule"++i".yml";}{print > x;}' SigmacMe.yml
        echo "$(date), $bundleName, SigmacMe.yml broken up into individual object files" >> $rulesLocation"log.csv"
        rm SigmacMe.yml
        echo "$(date), SigmacMe.yml, SigmacMe.yml removed" >> $rulesLocation"log.csv"
        num_rules=$(ls -1q rule* | wc -l)
        echo ""
        echo "Found "$num_rules" objects."
        echo ""
        echo "$(date), $bundleName, Now sorting the $num_rules objects found in $bundleName" >> $rulesLocation"log.csv"

        # Make the imported/notImported directories
        if [ ! -d $rulesLocation"imported/" ]; then
            mkdir $rulesLocation"imported/"
            mkdir $rulesLocation"imported/initial_access/"
            mkdir $rulesLocation"imported/execution/"
            mkdir $rulesLocation"imported/persistence/"
            mkdir $rulesLocation"imported/privilege_escalation/"
            mkdir $rulesLocation"imported/defense_evasion/"
            mkdir $rulesLocation"imported/credential_access/"
            mkdir $rulesLocation"imported/discovery/"
            mkdir $rulesLocation"imported/lateral_movement/"
            mkdir $rulesLocation"imported/collection/"
            mkdir $rulesLocation"imported/exfiltration/"
            mkdir $rulesLocation"imported/command_and_control/"
            mkdir $rulesLocation"imported/unsorted/"
        fi
        if [ ! -d $rulesLocation"notImported/" ]; then
            mkdir $rulesLocation"notImported/"
        fi
        if [ ! -d $rulesLocation"STIX/" ]; then
            mkdir $rulesLocation"STIX/"
        fi

        # Loop counters
        local counter=1
        local importCounter=0
        
        # Make sure the rule is the correct product type, run through sigmac, change name to object title, append with import statement if sigma
        while [ $counter -le $num_rules ]
        do
            # Find the title, product type, category type, service type, STIX ID, and att&ck mapping  for the rule
            local type="$(grep -m 1 "type:" rule$counter.yml | cut -d: -f2- | sed -e 's/^[[:space:]]*//')"
            local title="$(grep -w "title:"  rule$counter.yml|sed -e 's/ /_/g'|cut -d: -f2-| cut -c2-)"
            local id="$(grep -m 1 "id:" rule$counter.yml | cut -d: -f2- | sed -e 's/^[[:space:]]*//')"
            local product="$(grep -w "product:" rule$counter.yml | cut -d: -f2- | sed -e 's/^[[:space:]]*//')"
            local category="$(grep -w "category:" rule$counter.yml | cut -d: -f2- | sed -e 's/^[[:space:]]*//')"
            local service="$(grep -w "service:" rule$counter.yml | cut -d: -f2- | sed -e 's/^[[:space:]]*//')"
            local attack="$(grep -m 1 "attack." rule$counter.yml |sed -e 's/ //g'| cut -d: -f2-| cut -c9-)"
           
            if [ "$attack" != "initial_access" ] && [ "$attack" != "execution" ] && [ "$attack" != "persistence" ] && [ "$attack" != "privilege_escalation" ] && [ "$attack" != "defense_evasion" ] && [ "$attack" != "credential_access" ] && [ "$attack" != "discovery" ] && [ "$attack" != "lateral_movement" ] && [ "$attack" != "collection" ] && [ "$attack" != "exfiltration" ] && [ "$attack" != "command_and_control" ]; then
                attack='unsorted'
            fi

            sed -i 's/_t1pe/_type/g' rule$counter.yml #Return any occurences of type that may have been removed before processing

            echo "${yellow}----------------------------------------------------------------"
            echo ${cyan}"Checking rule $counter: $title"
            # Add the date and filter for import
            echo "imported: $(date) for filter '$importFilter rules'" >> rule$counter.yml

            # Import filter match, backend options required
            if [ "$product" = "$importFilter" ] || [ "$attack" = "$importFilter" ] || [ "$category" = "$importFilter" ] || [ "$service" = "$importFilter" ] && [ $backendOptions != "none" ]; then
                echo "This rule matches search parameters. Importing." ${yellow}
                sigmac -t $SIEM $backendOptions $rulesLocation"rule$counter.yml"
                importCounter=$((importCounter+1))
                echo "Moving to /imported/$attack/"
                mv "rule$counter.yml" $rulesLocation"imported/$attack/$title.yml"
                echo "$(date), $id, rule $title.yml imported and moved to /imported/$attack/ on search filter $importFilter" >> $rulesLocation"log.csv"
            # Import filter match, backend options not required
            elif [ "$product" = "$importFilter" ] || [ "$attack" = "$importFilter" ] || [ "$category" = "$importFilter" ] || [ "$service" = "$importFilter" ] && [ $backendOptions = "none" ]; then
                echo "This rule matches search parameters. Importing." ${yellow}
                sigmac -t $SIEM $rulesLocation"rule$counter.yml"
                importCounter=$((importCounter+1))
                echo "Moving to /imported/$attack/"
                mv "rule$counter.yml" $rulesLocation"imported/$attack/$title.yml"
                echo "$(date), $id, rule $title.yml imported and moved to /imported/$attack/ on search filter $importFilter" >> $rulesLocation"log.csv"
            # Importing all sigma rules, with NO backend params
            elif [ "$importFilter" = "all" ] && [ "$type" = "x-sigma-rules" ] && [ $backendOptions = "none" ]; then
                echo "This rule matches search parameters. Importing." ${yellow}
                sigmac -t $SIEM $rulesLocation"rule$counter.yml"
                importCounter=$((importCounter+1))
                echo "Moving to /imported/$attack/"
                mv "rule$counter.yml" $rulesLocation"imported/$attack/$title.yml"
                echo "$(date), $id, rule $title.yml imported and moved to /imported/$attack/ on search filter $importFilter" >> $rulesLocation"log.csv"
            # Importing all sigma rules, with backend params
            elif [ "$importFilter" = "all" ] && [ "$type" = "x-sigma-rules" ] && [ $backendOptions != "none" ]; then
                echo "This rule matches search parameters. Importing." ${yellow}
                sigmac -t $SIEM $backendOptions $rulesLocation"rule$counter.yml"
                importCounter=$((importCounter+1))
                echo "Moving to /imported/$attack/"
                mv "rule$counter.yml" $rulesLocation"imported/$attack/$title.yml"
                echo "$(date), $id, rule $title.yml imported and moved to /imported/$attack/ on search filter $importFilter" >> $rulesLocation"log.csv"
            # No match on the import filter
            elif [ "$type" != "x-sigma-rules" ]; then
                echo "This is not a sigma rule, it is a(n) STIX $type object${yellow}"
                echo "Moving to /STIX/"
                mv "rule$counter.yml" $rulesLocation"STIX/$id.yml"
                echo "$(date), $id, object $id.yml is a STIX object and moved to /STIX/ search filter $importFilter" >> $rulesLocation"log.csv"
            # No match on the import filter
            else
                echo ${cyan}"***This rule is for $product $category not importing.***"
                echo "${yellow}Moving to /notImported/"${cyan}
                mv "rule$counter.yml" $rulesLocation"notImported/$title.yml"
                echo "$(date), $id, rule $title.yml not imported and moved to /notImported/ on search filter $importFilter" >> $rulesLocation"log.csv"
            fi
            echo "${cyan}Rule $counter complete"
            echo "$(date), $id, done processing $id.yml and moving on to next object $importFilter" >> $rulesLocation"log.csv"
            counter=$((counter+1))
        done
        echo "${yellow}----------------------------------------------------------------"
        echo ""
        echo ${cyan}"Done! Imported $importCounter rules matching $importFilter out of $num_rules total objects."
        echo "$(date), $bundleLocation, done processing $bundleName" >> $rulesLocation"log.csv"
        echo ""
    fi
}

# ---------- DEFINE COLORS -------------------------------------------------
red=`tput setaf 1`
green=`tput setaf 2`
yellow=`tput setaf 3`
cyan=`tput setaf 6`
blue=`tput setaf 4`
teal=`tput setaf 51`
reset=`tput sgr0`

# ---------- WELCOME --------------------------------------------------------
echo $0 $1 $2 $3 $4 $5 $6 $7
num_args=$#
ver="1.07"
echo "${cyan}---"
figlet -f big "stix2sigmac"
echo ""
echo "Security Risk Advisors"
echo "---"
sleep 1


if [ "$1" = "import" ]; then
    importFilter=$2
    bundleLocation=$3
    bundleName=$4
    rulesLocation=$5
    SIEM=$6
    backendOptions=$7
    importRules
    exit 0
else
    # Make a log file if it doesnt exist
    if [ ! -e $rulesLocation"log.csv/" ]; then
            echo "DATE, OBJECT, ACTION" >> $rulesLocation"log.csv"
    fi
    echo "$(date), stix2sigmac.sh version $ver, script started" >> $rulesLocation"log.csv"
    echo "$1 is not a supported parameter."
    echo "No rules imported!"
    echo "$(date), parameters, parameter does not match import exiting script" >> $rulesLocation"log.csv"
    exit 0
fi
exit 0