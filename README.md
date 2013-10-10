qualysguard_was_scan_queue
==========================

Automate sequential scanning of multiple QualysGuard webapps.

Workflow
========

Here's what the script does:

1. Selects the applications you want to scan based on filters.
2. Lists selected applications.
3. Runs scans against applications.

Examples
========
List web applications with tag "Product Management"

    python qualysguard_scan_queue.py --tag "Product Management" --list

Run 2 simultaneous discovery scans against all web applications

    python qualysguard_scan_queue.py --all_apps --scan_type discovery --concurrency_limit 2 --scan

Run vulnerability scans against web applications with tag "QA"

    python qualysguard_scan_queue.py --tag "QA" --scan_type vulnerability --scan

Troubleshoot why script will not work (put in debug mode)

    python qualysguard_scan_queue.py --all_apps --scan_type discovery --scan --debug

Usage
=====

    usage: qualysguard_scan_queue.py [-h] [-a] [-c CONCURRENCY_LIMIT]
                                 [--config CONFIG] [-d DELAY] [--debug]
                                 [-f FILE] [-l] [-o OPTION_PROFILE] [-s]
                                 [-t TAG] [-y SCAN_TYPE]

    Automate sequential scanning of multiple QualysGuard webapps.
    
    optional arguments:
      -h, --help            show this help message and exit
      -a, --all_apps        Select all web applications. Overwrites any tag
                            filters.
      -c CONCURRENCY_LIMIT, --concurrency_limit CONCURRENCY_LIMIT
                            Limit scans to CONCURRENCY_LIMIT simultaneous scans.
                            (Default = 10)
      --config CONFIG       Configuration for Qualys connector.
      -d DELAY, --delay DELAY
                            Wait DELAY seconds between scan attempts if
                            concurrency limit is reached. (Default = 60)
      --debug               Outputs additional information to log.
      -f FILE, --file FILE  Output file to store XML results from initiating
                            scans. (Default = apps.txt)
      -l, --no_list         Do not list all selected web applications. (Default =
                            False)
      -o OPTION_PROFILE, --option_profile OPTION_PROFILE
                            Scan selected web applications with OPTION_PROFILE ID.
      -s, --scan            Scan all selected web applications.
      -t TAG, --tag TAG     Filter selection of web applications to those with
                            TAG.
      -y SCAN_TYPE, --scan_type SCAN_TYPE
                            Scan type: discovery, vulnerability. (Default =
                            discovery)



Screenshot

    $ python qualysguard_scan_queue.py --option_profile 56358 --scan --concurrency_limit 2 --tag 'Hostname contains QA'
    
    +-------------------------+-------------------------+-------------------------+
    |          App #          |        App name         |        App ID #         |
    +=========================+=========================+=========================+
    |                       1 | My Co. - QA Lab - Demo  | 41325                   |
    |                         | 6                       |                         |
    +-------------------------+-------------------------+-------------------------+
    |                       2 | My Co. - QA Lab - Demo  | 51326                   |
    |                         | 11                      |                         |
    +-------------------------+-------------------------+-------------------------+
    |                         | Catalog Web             |                         |
    |                       3 | Application: hpux444444 | 562256                  |
    |                         | 0-7.vuln.qa.my-com.com, |                         |
    |                         | Port 2222               |                         |
    +-------------------------+-------------------------+-------------------------+
    |                         | Catalog Web             |                         |
    |                       4 | Application: sql2k-qnim | 6106459                 |
    |                         | sp2-3.patch.na.vuln.qa. |                         |
    |                         | my-com.com, Port 8080   |                         |
    +-------------------------+-------------------------+-------------------------+
    |                         | Catalog Web             |                         |
    |                       5 | Application: sol10-qnim | 1793795                 |
    |                         | bus212.prod.qa.my-com.c |                         |
    |                         | om, Port 67899          |                         |
    +-------------------------+-------------------------+-------------------------+
    
    Checking number of web application scans in use...
    Scanning My Co. - QA Lab - Demo 6 (web app ID 41325)...
    Done:
    <?xml version="1.0" encoding="UTF-8"?>
    <ServiceResponse xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="https://qualysapi.qualys.com/qps/xsd/3.0/was/wasscan.xsd">
      <responseCode>SUCCESS</responseCode>
      <count>1</count>
      <data>
        <WasScan>
          <id>2763740</id>
        </WasScan>
      </data>
    </ServiceResponse>
    
    Checking number of web application scans in use...
    Scanning My Co. - QA Lab - Demo 11 (web app ID 51326)...
    Done:
    <?xml version="1.0" encoding="UTF-8"?>
    <ServiceResponse xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="https://qualysapi.qualys.com/qps/xsd/3.0/was/wasscan.xsd">
      <responseCode>SUCCESS</responseCode>
      <count>1</count>
      <data>
        <WasScan>
          <id>2763741</id>
        </WasScan>
      </data>
    </ServiceResponse>
    
    Checking number of web application scans in use...
    Too many web application scans running. Trying again in 300 seconds.
    Checking number of web application scans in use...
    Scanning Catalog Web Application: hpux4444440-7.vuln.qa.my-com.com, Port 2222 (web app ID 562256)...
    Done:
    <?xml version="1.0" encoding="UTF-8"?>
    <ServiceResponse xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="https://qualysapi.qualys.com/qps/xsd/3.0/was/wasscan.xsd">
      <responseCode>SUCCESS</responseCode>
      <count>1</count>
      <data>
        <WasScan>
          <id>2763742</id>
        </WasScan>
      </data>
    </ServiceResponse>
    
    Checking number of web application scans in use...
    Scanning Catalog Web Application: sql2k-qnimsp2-3.patch.na.vuln.qa.my-com.com, Port 8080 (web app ID 2106459)...
    Done:
    <?xml version="1.0" encoding="UTF-8"?>
    <ServiceResponse xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="https://qualysapi.qualys.com/qps/xsd/3.0/was/wasscan.xsd">
      <responseCode>SUCCESS</responseCode>
      <count>1</count>
      <data>
        <WasScan>
          <id>2763743</id>
        </WasScan>
      </data>
    </ServiceResponse>
    
    Checking number of web application scans in use...
    Too many web application scans running. Trying again in 300 seconds.
    Checking number of web application scans in use...
    Scanning Catalog Web Application: sol10-qnimbus212.prod.qa.my-com.com, Port 67899 (web app ID 1793795)...
    Done:
    <?xml version="1.0" encoding="UTF-8"?>
    <ServiceResponse xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="https://qualysapi.qualys.com/qps/xsd/3.0/was/wasscan.xsd">
      <responseCode>SUCCESS</responseCode>
      <count>1</count>
      <data>
        <WasScan>
          <id>2763745</id>
        </WasScan>
      </data>
    </ServiceResponse>


Requirements
============

1. Python 2.6+
2. lxml
3. qualysapi
4. texttable

How to install libraries
------------------------

Install pip:

    curl https://raw.github.com/pypa/pip/master/contrib/get-pip.py | sudo python

Install libraries:

    pip install lxml qualysapi texttable
