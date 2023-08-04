#!/usr/bin/env python

import datetime
import xml.etree.ElementTree as ET
import sys
import re

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} vuln.xml")
    sys.exit(1)

re_date = re.compile(r'^(19|20)[0-9]{2}-[0-9]{2}-[0-9]{2}$')
re_invalid_package_name = re.compile('[@!#$%^&*()<>?/\|}{~:]')

# warn if description has more than X characters
DESCRIPTION_LENGTH = 5000

tree = ET.parse(sys.argv[1])
root = tree.getroot()

namespace = "{http://www.vuxml.org/apps/vuxml-1}"

ret = 0


def dateof(string):
    return datetime.datetime.strptime(string, "%Y-%m-%d")

all_vids = set()


for vuln in root:
    vid = vuln.get("vid")

    cancelled = vuln.find(f"{namespace}cancelled") is not None
    if cancelled:
        continue

    # Validate Vids
    if vid in all_vids:
        print("Error: duplicate vid : {0}".format(vid))
    all_vids.add(vid)

    # Validate References
    references = vuln.find(f"{namespace}references")
    if references is None:
        print("Error: references is None : {0}".format(vid))
        ret = 1
    else:
        prev = references[0]
        for reference in references:
            prev = reference

    # Validate Dates
    dates = vuln.find(f"{namespace}dates")
    if dates is None:
        print("Error: no date : {0}".format(vid))
        ret = 1
    else:
        discovery = dates.find(f"{namespace}discovery")
        entry = dates.find(f"{namespace}entry")
        modified = dates.find(f"{namespace}modified")
        if discovery is None:
            print("Error: discovery is None : {0}".format(vid))
            ret = 1
        elif entry is None:
            print("Error: entry is None : {0}".format(vid))
            ret = 1
        else:
            if modified is None:
                modified = entry
            if not (dateof(discovery.text) <= dateof(entry.text) <= dateof(modified.text)):
                print("Error: dates are insane : {0}".format(vid))
                ret = 1

        # Make sure the dates are in YYYY-MM-DD format
        datelist = [discovery.text, entry.text] + ([modified.text] if modified is not None else [])
        for d in datelist:
            if not re_date.match(d):
                print("Warning: dates must be in YYYY-MM-DD format: {0}".format(d))

        # Check description lengths
        description = vuln.find(f"{namespace}description")
        description_len = len(ET.tostring(description))
        if description_len > DESCRIPTION_LENGTH:
            print("Warning: description too long ({0} chars, {1} is warning threshold): {2})" \
                  .format(description_len, DESCRIPTION_LENGTH, vid))

        # Walk and validate package names
        affects = vuln.find(f"{namespace}affects")
        packages = affects.findall(f"{namespace}package")
        for package in packages:
            names = package.findall(f"{namespace}name")

            for name in names:
                if (re_invalid_package_name.search(name.text) is not None):
                    print(f"Error: invalid package name: {name.text} for VID {format(vid)}")
                    ret = 1

sys.exit(ret)
