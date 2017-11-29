#!/bin/python3
# Copyright (c) 2017 Pavel Sedlák; Red Hat, Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

###
# Tool for converting passwords from Google Chrome to Firefox.
#
# Reads from chrome's plain sqlite "Login Data" file
# and generates xml files suitable for use with FFX `Password Exporter addon`_.
#
# (addon is atm NOT compatible with current firefox 57+,
#  so get older one (e.g. from `Mozilla FTP`_, e.g. 56, install addon,
#  import passwords, and then run again your new/current firefox
#  [nightly||aurora in my case])
#
# Copy your "Login Data" ($HOME/.config/google-chrome/Default/Login\ Data)
# next to this file, and run this.
# It will generate two xml files passlist.xml and blacklist.xml,
# to be used for importing via Password Exporter addon for Firefox.
#
# If this script fails with exception, likely You will have to tweak the code,
# as there may be unexpected cases (like url schemes/protocols not used by me
# etc, and atm i'm not trying to figure out those).
#
# If Password Exporter reports issues (most likely collisions etc),
# you may want to remove all passwords from firefox,
# tweak passlist.xml by hand and re-import again.
# (E.g. i had multiple passwords with same account stored in chrome,
#  while some/most of them actually outdated so clear those, keep just valid
#  ones)
#
# This worked for me to great deal (>300 passwords copied and working, bunch of
# blacklisted ones etc) with having to tweak ~10 in xml by hand,
# but no promise it will work for you.


import sqlite3

sql_fields = (
    'origin_url',
    'action_url',
    'username_element',
    'username_value',
    'password_element',
    'password_value',
    'submit_element',
    'signon_realm',
    'preferred',
    'date_created',
    'blacklisted_by_user',
    'scheme',
    'password_type',
    'times_used',
    'form_data',
    'date_synced',
    'display_name',
    'icon_url',
    'federation_url',
    'skip_zero_click',
    'generation_upload_status',
    'possible_username_pairs',
)
passlist_tpl = ("<xml>"
                "<entries ext=\"Password Exporter\" extxmlversion=\"1.1\""
                " type=\"saved\" encrypt=\"false\">\n"
                "{}"
                "</entries>"
                "</xml>\n")
blacklist_tpl = ("<xml>"
                 "<entries ext=\"Password Exporter\" extxmlversion=\"1.0.2\""
                 " type=\"rejected\">\n"
                 "{}"
                 "</entries>"
                 "</xml>\n")
row_tpl = ("<entry"
           " host=\"{origin_url}\""
           " user=\"{username_value}\""
           " password=\"{password_value}\""
           " formSubmitURL=\"{action_url}\""
           " userFieldName=\"{username_element}\""
           " passFieldName=\"{password_element}\""
           " />\n")
row_realm_tpl = ("<entry"
                 " host=\"{origin_url}\""
                 " user=\"{username_value}\""
                 " password=\"{password_value}\""
                 " httpRealm=\"{signon_realm}\""
                 " userFieldName=\"{username_element}\""
                 " passFieldName=\"{password_element}\""
                 " />\n")
blackrow_tpl = ("<entry host=\"{origin_url}\"/>\n")


def strip_path(url):
    if not url:
        return url
    if (url.startswith('http')):
        return '/'.join(url.split('/')[0:3])
    raise Exception('Unexpected url: %s' % url)

passlist_filepath = "passlist.xml"
blacklist_filepath = "blacklist.xml"

passlist = []
blacklist = []

with sqlite3.connect('./Login Data') as c:
    for dbrow in c.execute('SELECT * from logins'):
        # convert db row to dict
        row = {}
        for idx, field in enumerate(sql_fields):
            row[field] = dbrow[idx]

        if dbrow[0].startswith('chrome:'):
            # exclude internal chrome's passwords
            continue

        try:
            # FFX `nsILoginInfo docs`_ say just url WITHOUT path
            row['origin_url'] = strip_path(row['origin_url'])
            row['action_url'] = strip_path(row['action_url'])
        except Exception as exc:
            print(dbrow)
            raise
        # convert password from blob (bytes) to string
        row['password_value'] = row['password_value'].decode('utf-8')

        if row['blacklisted_by_user']:
            # Blacklist is ex/imported from it's own file, keep separated
            row_rendered = blackrow_tpl.format(**row)
            blacklist.append(row_rendered)
        else:
            if not row['action_url']:
                # FFX `nsILoginInfo docs`_ say only form url OR realm
                # (seems when I kept both as in chrome db,
                #  ffx did not used them in forms at all,
                #  so export with realm only when there is no form/action url)
                row_rendered = row_realm_tpl.format(**row)
            else:
                row_rendered = row_tpl.format(**row)

            passlist.append(row_rendered)

# remove duplicates, as chrome stores with full url's to form (including path)
# seems that when converted to just hostname, it can result in multiple
# same entries at the end, de-duplicating here avoids confusion at import time
# (where it correctly detects and reports duplicates too)
# (does not handle duplicate entries for same username with different pass or
#  formfields, those have to be handled by You in final xml before importing)
#
# also sort, so output files are friendly to human inspection
passlist = sorted(list(set(passlist)))
blacklist = sorted(list(set(blacklist)))

with open(passlist_filepath, 'w') as passlist_file:
    passlist_file.write(passlist_tpl.format(''.join(passlist)))
    print("Written {} entries to {}".format(
        len(passlist), passlist_filepath))

with open(blacklist_filepath, 'w') as blacklist_file:
    blacklist_file.write(blacklist_tpl.format(''.join(blacklist)))
    print("Written {} entries to {}".format(
        len(blacklist), blacklist_filepath))


# .. _Mozilla FTP: https://ftp.mozilla.org/pub/firefox/releases/56.0.2/
# .. _Password Exporter addon:
#    https://addons.mozilla.org/en-US/firefox/addon/password-exporter/
# .. _nsILoginInfo docs:
#    https://developer.mozilla.org/en-US/docs/Mozilla/Tech/XPCOM/Reference/Interface/nsILoginInfo
