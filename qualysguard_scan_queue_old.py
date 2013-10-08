#!/usr/bin/env python

'''Run multiple WAS v2 scans as a workaround to the concurrency limit.

Author: Parag Baxi <parag.baxi@gmail.com>
License: GPL
'''

'''To do:
Add ability to import CSV.
'''

import argparse
import base64, urllib2
import datetime, time
import logging
import os
import unicodedata

from collections import defaultdict
from lxml import objectify
from texttable import Texttable

def qg_was_api(uri, data = None):
    """Returns XML for API call requested.
       GET call if data is None. POST call otherwise.
    """
    global base64string
    logging.debug('qg_was_api(%s, %s)' % (uri, data))
    # Set request. Force add creds. Let API know type of content in POST.
    req = urllib2.Request(uri, data)
    req.add_header("Authorization", "Basic %s" % base64string)
    req.add_header("Content-Type", "text/xml")
    # Make request.
    result = urllib2.urlopen(req)
    response = result.read()
    logging.debug('qg_was_api.response = %s' % (response))
    return response

def list_apps(apps):
    """Print applications into a pretty table.
    """
    table = Texttable()
    table.set_cols_align(["r", "l", "l"])
    table.set_cols_valign(["m", "m", "m"])
    table.add_rows([ ['App #', 'App name', 'App ID #'], ], header = True) 
    c=0
    for webapp in apps:
        c+=1
        table.add_row([c, webapp['name'], webapp['id']])
    # Print table.
    print (table.draw() + '\n')
    return True

# Start of script.
# Declare the command line flags/options we want to allow.
parser = argparse.ArgumentParser(description = 'Automate sequential scanning of multiple QualysGuard webapps.')
parser.add_argument('-a', '--all_apps', action = 'store_true',
                    help = 'Select all web applications. Overwrites any tag filters.')
parser.add_argument('-c', '--concurrency_limit', default = 10,
                    help = 'Limit scans to CONCURRENCY_LIMIT simultaneous scans. (Default = 10)')
parser.add_argument('-d', '--delay', default = 5,
                    help = 'Wait DELAY Minutes between scan attempts if concurrency limit is reached. (Default = 5)')
parser.add_argument('--debug', action = 'store_true',
                    help = 'Outputs additional information to log.')
parser.add_argument('-f', '--file', default = 'apps.txt',
                    help = 'Output file to store XML results from initiating scans. (Default = apps.txt)')
parser.add_argument('-l', '--list', action = 'store_true', default = True,
                    help = 'List all selected web applications. (Default = True)')
parser.add_argument('-o', '--option_profile',
                    help = 'Scan selected web applications with OPTION_PROFILE ID.')
parser.add_argument('-p', '--password', required = True,
                    help = 'Corresponding QualysGuard WAS API password.')
parser.add_argument('-s', '--scan', action = 'store_true',
                    help = 'Scan all selected web applications.')
parser.add_argument('-t', '--tag',
                    help = 'Filter selection of web applications to those with TAG.')
#parser.add_argument('-T', '--Tags_file',
#                    help = 'Filter selection of web applications to those with all tags from TAGS_FILE (tags combined using a logical AND). Tags from file should be separated by line break.')
parser.add_argument('-u', '--username', required = True,
                    help = 'QualysGuard WAS v2 API username.')
parser.add_argument('-y', '--scan_type', default = 'discovery',
                    help = 'Scan type: discovery, vulnerability. (Default = discovery)')
# Parse arguements.
c_args = parser.parse_args()
# Check arguments.
if c_args.option_profile and c_args.scan:
    parser.print_help()
    exit(1)
# Create log directory.
PATH_LOG = 'log'
if not os.path.exists(PATH_LOG):
    os.makedirs(PATH_LOG)
# Set log options.
now = datetime.datetime.now()
LOG_FILENAME = '%s/%s-%s.log' % (PATH_LOG,
                                 __file__,
                                 datetime.datetime.now().strftime('%Y-%m-%d.%H-%M-%S'))
# Set logging level.
if c_args.debug:
    # Enable debug level of logging.
    print "Logging level set to debug."
    logging.basicConfig(filename = LOG_FILENAME, format = '%(asctime)s %(message)s',
                        level = logging.DEBUG)
else:
    logging.basicConfig(filename = LOG_FILENAME, format = '%(asctime)s %(message)s',
                        level = logging.INFO)
# Validate arguements.
if not ((c_args.all_apps or c_args.tag or c_args.Tags_file)):
    parser.print_help()
    logging.error('Invalid run parameters.')
    exit(1)
c_args.concurrency_limit = int(c_args.concurrency_limit)
# Credentials for basic authorization.
logging.info('username = %s' % (c_args.username))
logging.debug('password = %s' % (c_args.password))
base64string = base64.encodestring('%s:%s' % (c_args.username, c_args.password))[:-1]
# There may be more than 1000 apps so start with first possible record, # 0.
last_record = '0'
apps_to_scan = []
print 'Downloading list of applications.'
while True:
    # Get list of web apps.
    query_uri = 'https://qualysapi.qualys.com/qps/rest/3.0/search/was/webapp'
    if c_args.all_apps:
        data = '''
        <ServiceRequest>
            <filters>
                <Criteria field="createdDate" operator="GREATER">2000-02-21T00:00:00Z</Criteria>
                <Criteria field="id" operator="GREATER">%s</Criteria>
            </filters>
            <preferences>
                <limitResults>1000</limitResults>
            </preferences>
        </ServiceRequest>''' % (last_record)
    elif c_args.tag:
        data = '''
        <ServiceRequest>
            <filters>
                <Criteria field="tags.name" operator="EQUALS">%s</Criteria>
                <Criteria field="id" operator="GREATER">%s</Criteria>
            </filters>
            <preferences>
                <limitResults>1000</limitResults>
            </preferences>
        </ServiceRequest>''' % (c_args.tag, last_record)
    search_apps = qg_was_api(query_uri, data)
    # Parse list of web apps to associate each web app id with web app name.
    tree = objectify.fromstring(search_apps)
    for webapp in tree.data.WebApp:
        app = defaultdict(str)
        app_name = webapp.name.text
        # App name may be in unicode.
        if isinstance(app_name, unicode):
            # Decode to string.
            app_name = unicodedata.normalize('NFKD', app_name).encode('ascii','ignore')
        app['name'] = app_name
        app['id']=webapp.id.text
        apps_to_scan.append(app)
    if tree.hasMoreRecords.text == 'true':
        last_record = tree.lastId.text
    else:
        break
print '\n'
logging.info('apps_to_scan = %s' % (apps_to_scan))
if c_args.list:
    list_apps(apps_to_scan)
if not c_args.scan:
    print ''
    exit()
# Start scanning.
apps_scanned=[]
logging.debug('Writing results of initiating app scans to %s' %(c_args.file))
f = file(c_args.file, 'w')
for app in apps_to_scan:
    logging.debug('Attempting to scan %s, %s' % (app['name'], app['id']))
    # Limit scans to concurrency limit.
    # See if we have hit the concurrency limit (loop).
    while True:
        print 'Checking number of web application scans in use...'
        # How many are currently submitted?
        current_scans = 0
        query_uri = 'https://qualysapi.qualys.com/qps/rest/3.0/count/was/wasscan'
        data = '''
            <ServiceRequest>
                <filters>
                    <Criteria field="status" operator="EQUALS">SUBMITTED</Criteria>
                </filters>
            </ServiceRequest>'''
        # Make request
        scans_submitted = qg_was_api(query_uri, data)
        tree = objectify.fromstring(scans_submitted)
        # Add to total of current scans slots used.
        number_scans_submitted = tree.count.text
        logging.debug('Number of scans submitted = %s' % (str(number_scans_submitted)))
        current_scans += number_scans_submitted
        # How many are currently running?
        query_uri = 'https://qualysapi.qualys.com/qps/rest/3.0/count/was/wasscan'
        data = '''
            <ServiceRequest>
                <filters>
                    <Criteria field="status" operator="EQUALS">RUNNING</Criteria>
                </filters>
            </ServiceRequest>'''
        # Make request
        scans_running = qg_was_api(query_uri, data)
        tree = objectify.fromstring(scans_running)
        number_scans_running = tree.count.text
        # Add to total of current scans slots used.
        logging.debug('Number of scans running = %s' % (tree.count))
        current_scans += number_scans_running
        logging.debug('current_scans = %s' % (str(current_scans)))
        # Have we hit the limit?
        if current_scans >= c_args.concurrency_limit:
            # Hit concurrency limit. Wait.
            logging.debug('Concurrency limit met. Delaying scan. Trying again in %s seconds.' % (str(60*c_args.delay)))
            print 'Too many web application scans running. Trying again in %s seconds.' % (str(60*c_args.delay))
            time.sleep(60*c_args.delay)
        else:
            # Under concurrency limit, do not delay.
            logging.debug('Running scan.')
            break
    # Scan web app.
    query_uri = 'https://qualysapi.qualys.com/qps/rest/3.0/launch/was/wasscan'
    # Setup request to scan web app.
    option_profile = c_args.option_profile
    scan_type = c_args.scan_type.upper()
    data = '''
        <ServiceRequest>
            <data>
                <WasScan>
                    <name>Auto %s</name>
                    <type>%s</type>
                    <target>
                        <webApp>
                            <id>%s</id>
                        </webApp>
                    </target>
                    <profile>
                        <id>%s</id>
                    </profile>
                </WasScan>
            </data>
        </ServiceRequest>''' % (app['name'], scan_type, app['id'], option_profile)
    # Make request
    logging.info('Scanning %s (web app ID %s)...' % (app['name'], app['id']))
    print 'Scanning %s (web app ID %s)...' % (app['name'], app['id'])
    response = qg_was_api(query_uri, data)
    print 'Done:'
    logging.info(response)
    print response + '\n'
    app['response'] = response
    apps_scanned.append(app)
    f.write(str(app['name']))
    f.write(str(app['id']))
    f.write(str(app['response']))
f.close()
