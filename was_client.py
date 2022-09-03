#!/usr/bin/env python
# Need to install requests package for python
# easy_install requests
import argparse
import csv
import datetime
import gzip
import itertools
import sys
import re
from pprint import pprint as pp
import json

try:
    from ConfigParser import ConfigParser
except:
    from configparser import ConfigParser

from tenable.io import TenableIO

# <refactor import="refactor/code_inspect_start.py">
# improved debugging
import inspect
import code

def lineno():
    """Returns the current line number in our program."""
    return inspect.currentframe().f_back.f_lineno


# global error level
global_error = 0
# </refactor>

description = """Simple client to the WAS API v2 from tenable build on top of the library.
"""

epilog = """
"""

'''
Sample usage:
python was_client.py --config ~/.sectool.config  --debug --listwasconfigs --outfile listwasconfigs.json
export WASCONFIG=xxx-xxx-xxx
python was_client.py --config ~/.sectool.config  --debug --listwasscans --wasconfigid $WASCONFIGID --outfile listwasscans.json
export WASSCANID=yyy-yyy-yyy
python was_client.py --config ~/.sectool.config  --debug --wasscanstatus --wasconfigid $WASCONFIGID --wasscanid $WASSCANID --outfile wasscanstatus.txt
python was_client.py --config ~/.sectool.config  --debug --outfile export.pdf --wasscanexport --wasconfigid $WASCONFIGID --wasscanid $WASSCANID --pprint
python was_client.py --config ~/.sectool.config --debug --outfile export.json --wasscanexport --wasconfigid $WASCONFIGID --wasscanid $WASSCANID --pprint
python was_client.py --config ~/.sectool.config --debug --outfile export.xml --wasscanexport --wasconfigid $WASCONFIGID --wasscanid $WASSCANID --pprint
python was_client.py --config ~/.sectool.config --debug --outfile export.html --wasscanexport --wasconfigid $WASCONFIGID --wasscanid $WASSCANID --pprint
python was_client.py --config ~/.sectool.config --debug --outfile export.csv --wasscanexport --wasconfigid $WASCONFIGID --wasscanid $WASSCANID --pprint

python was_client.py --config ~/.sectool.config  --debug --wastemplates --outfile templates.json
python was_client.py --config ~/.sectool.config  --debug --wasusertemplates --outfile usertemplates.json
python was_client.py --config ~/.sectool.config  --debug --wasusertemplatedetails --wasusertemplateid ttt-ttt-ttt --outfile usertemplatedetails.json

python was_client.py --config ~/.sectool.config  --debug --wasscanconfigdetails --wasconfigid $WASCONFIGID --outfile wasscandetails.json
python was_client.py --config ~/.sectool.config  --debug --wasscanconfigcreate wasscandetails-configinput.json
# Created abc-abc
python was_client.py --config ~/.sectool.config  --debug --wasscanconfigupdate '{"description":"bla bla bla"}' --wasconfigid abc-abc
python was_client.py --config ~/.sectool.config  --debug --wasscanconfigdelete  abc-abc --wasconfigid abc-abc

python was_client.py --config ~/.sectool.config  --debug --wasscanhistory --wasconfigid $WASCONFIGID --outfile wasscanhistory.json

'''

def handle_result(args, results_table):
    if args.outfile:
        f=open(args.outfile,'w')
        json.dump(results_table, f)
        f.close()
    if args.pprint:
        pp(results_table)
    try:
        if args.debug:
            print("[DEBUG] Number of records retrieved: %s" % len(results_table))
    except:
        pass

def required_kw(config_kw):
    '''Check if required keywords are present
    '''
    required=['name', 'targets','owner_id','template_id', 'settings']
    for r in required:
        if not r in config_kw:
            print("[ERROR] Missing %s in keywords" % r)
            return False
    return True
            

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=description, epilog=epilog)
    parser.add_argument("--config", type=str, help="Configuration file to use")
    parser.add_argument(
        "--noproxy", action="store_true", default=False, help="Do not use proxy"
    )
    
    parser.add_argument(
        "--pprint", action="store_true", default=False, help="pprint the result"
    )
    parser.add_argument(
        "--outfile", type=str, default=None, help="Save result to file"
    )
    
    parser.add_argument(
        "--listwasconfigs", action="store_true", default=False, help="List all was configs"
    )
    parser.add_argument(
        "--wasscanconfigdetails", action="store_true", default=False, help="Retrive scan details"
    )
    parser.add_argument(
        "--wasscanconfigcreate", type=str, help="Create a scan based on json or file"
    )
    parser.add_argument(
        "--wasscanconfigupdate", type=str, help="Update a scan based on json or file"
    )
    parser.add_argument(
        "--wasscanconfigdelete", type=str, help="Delete a scan configuration based on json or file"
    )
    
    parser.add_argument(
        "--wasscanhistory", action="store_true", default=False, help="Retrive scan history for wasconfigid"
    )
    parser.add_argument(
        "--wastemplates", action="store_true", default=False, help="List all was templates"
    )
    parser.add_argument(
        "--wasusertemplates", action="store_true", default=False, help="List all was templates"
    )
    parser.add_argument(
        "--wasusertemplatedetails", action="store_true", default=False, help="Retrieves usertemplate details"
    )
    
    parser.add_argument(
        "--listwasscans", action="store_true", default=False, help="List all was scans"
    )
    parser.add_argument(
        "--wasscanresults", action="store_true", default=False, help="Retrieve results for a given wasscanid"
    )
    
    parser.add_argument(
        "--wasscanstatus", action="store_true", default=False, help="Retrive scan status"
    )
    parser.add_argument(
        "--wasscanlaunch", action="store_true", default=False, help="Launch a scan"
    )
    parser.add_argument(
        "--wasscanstop", action="store_true", default=False, help="Stop a running scan"
    )
    parser.add_argument(
        "--wasscandelete", type=str, help="Delete a scan based on json or file"
    )
    
    
    parser.add_argument(
        "--wasscanexport", action="store_true", default=False, help="Export a scan, requires outfile"
    )


    parser.add_argument(
        "--wasconfigid", type=str, default=False, help="WAS scan config_id"
    )
    parser.add_argument(
        "--wasscanid", type=str, default=False, help="WAS scan scan_id"
    )
    parser.add_argument(
        "--wasusertemplateid", type=str, default=False, help="WAS user template id"
    )
    
    # <refactor import="refactor/code_inspect_arguments.py">
    try:
        parser.add_argument(
            "--interactive",
            default=False,
            action="store_true",
            help="Launch a interactive shell at the end",
        )
    except:
        pass
    try:
        parser.add_argument(
            "--debug", action="store_true", default=False, help="debug level"
        )
    except:
        pass
    try:
        parser.add_argument(
            "--details", action="store_true", default=False, help="details of findings"
        )
    except:
        pass
    # </refactor>

    args = parser.parse_args()

    try:
        config = ConfigParser()
        config.read(args.config)
    except:
        print("ConfigParser: Missing or error in configuration file")
        if args.debug:
            print("ConfigParser: Raise")
            raise
        sys.exit(1)

    try:
        if args.noproxy:
            proxies = None
        else:
            proxies = {
                "http": config.get("PROXY", "http_proxy"),
                "https": config.get("PROXY", "https_proxy"),
            }
    except:
        proxies = None
        if args.debug:
            print("ConfigGet: Could not get proxy parameters")
    # Retrieve TENABLE from config file
    if config.has_section("TENABLE"):
        if config.has_section("PROXY") and not (args.noproxy):
            tio = TenableIO(
                config.get("TENABLE", "TIO_ACCESS_KEY"),
                config.get("TENABLE", "TIO_SECRET_KEY"),
                retries=1,
                proxies=proxies,
            )
        else:
            tio = TenableIO(
                config.get("TENABLE", "TIO_ACCESS_KEY"),
                config.get("TENABLE", "TIO_SECRET_KEY"),
                retries=1,
            )
    else:
        if args.debug:
            print("[DEBUG] No TENABLE section in configuration file")
        sys.exit(-1)

    if args.listwasconfigs:
        results = tio.wasscans.list()
        results_table = []
        for i in results:
            results_table.append(i)
        handle_result(args, results_table)
    elif args.wastemplates:
        results = tio.wasscans.templateslist()
        results_table = []
        for i in results:
            results_table.append(i)
        handle_result(args, results_table)
    elif args.wasusertemplates:
        results = tio.wasscans.usertemplateslist()
        results_table = []
        for i in results:
            results_table.append(i)
        handle_result(args, results_table)
    elif args.wasusertemplatedetails and args.wasusertemplateid:
        result = tio.wasscans.usertemplatesdetails(user_template_id=args.wasusertemplateid)
        handle_result(args, result)
    elif args.listwasscans and args.wasconfigid:
        results = tio.wasscans.history(wasscan_id=args.wasconfigid)
        results_table = []
        for i in results:
            results_table.append(i)
        handle_result(args, results_table)
    elif args.wasscanstatus and args.wasscanid:
        result = tio.wasscans.status(wasscan_id=args.wasscanid)
        handle_result(args, result)        
    elif args.wasscanlaunch:
        if args.wasconfigid:
            result = tio.wasscans.launch(wasconfig_id=args.wasconfigid)
            handle_result(args, result)        
        else:
            print("Missing WAS scan config id, use --wasconfigid xxx-xxx-xxx")
            global_error = 1
    elif args.wasscanstop:
        if args.wasscanid:
            result = tio.wasscans.stop(wasscan_id=args.wasscanid)
            handle_result(args, result)        
        else:
            print("Missing WAS scan id, use --wasscanid xxx-xxx-xxx")
            global_error = 1
    elif args.wasscanconfigdetails:
        if args.wasconfigid:
            result = tio.wasscans.details(wasscan_id=args.wasconfigid)
            handle_result(args, result)
        else:
            print("Missing WAS scan config id, use --wasconfigid xxx-xxx-xxx")
            global_error = 1
    elif args.wasscanexport and args.wasscanid and args.outfile:
        if args.outfile.endswith('.json'): 
            f=open(args.outfile,'wb')
            fo=tio.wasscans.export(wasscan_id=args.wasscanid, fobj=f, format='application/json')
            f.close()
        elif args.outfile.endswith('.pdf'): 
            f=open(args.outfile,'wb')
            fo=tio.wasscans.export(wasscan_id=args.wasscanid, fobj=f, format='application/pdf')
            f.close()
        elif args.outfile.endswith('.html') or args.outfile.endswith('.htm'): 
            f=open(args.outfile,'wb')
            fo=tio.wasscans.export(wasscan_id=args.wasscanid, fobj=f, format='text/html')
            f.close()
        elif args.outfile.endswith('.csv'): 
            f=open(args.outfile,'wb')
            fo=tio.wasscans.export(wasscan_id=args.wasscanid, fobj=f, format='text/csv')
            f.close()
        elif args.outfile.endswith('.xml'): 
            f=open(args.outfile,'wb')
            fo=tio.wasscans.export(wasscan_id=args.wasscanid, fobj=f, format='text/xml')
            f.close()
        else:
            if args.debug:
                print("[DEBUG] Outformat for file not recognised")
    elif args.wasscanconfigcreate:
        config_kw = None
        try:
            config_kw=json.loads(args.wasscanconfigcreate)
        except:
            if args.debug:
                print("[DEBUG] Trying to load json from string failed.")
        if not config_kw:
            # check if this is a file
            try:
                f=open(args.wasscanconfigcreate)
                config_kw=json.load(f)
                f.close()
            except:
                if args.debug:
                    print("[DEBUG] Trying to load json from file failed.")
                print("Missing wasscanconfigcreate: it should be either a valid json object or file.")
                global_error=2
        if config_kw:
                # check for some key fields
                if required_kw(config_kw):
                    result = tio.wasscans.create(config_dict=config_kw)
                    print("[OK] Scan created with ID %s" % result)
                    pass
        else:
            print("Missing wasscanconfigcreate: it should be either a valid json object or file.")
            global_error=2
    elif args.wasscanconfigupdate:
        if args.wasconfigid:
            config_kw = None
            try:
                config_kw=json.loads(args.wasscanconfigupdate)
            except:
                if args.debug:
                    print("[DEBUG] Trying to load json from string failed.")
            if not config_kw:
                # check if this is a file
                try:
                    f=open(args.wasscanconfigupdate)
                    config_kw=json.load(f)
                    f.close()
                except:
                    if args.debug:
                        print("[DEBUG] Trying to load json from file failed.")
                    print("Missing wasscanconfigupdate: it should be either a valid json object or file.")
                    global_error=2
            if config_kw:
                    result = tio.wasscans.configure(wasconfig_id=args.wasconfigid, config_dict=config_kw)
                    print("[OK] Scan updated with ID %s" % args.wasconfigid) 
                    if args.debug:
                        pp(result)
            else:
                print("Missing wasscanconfigupdate: it should be either a valid json object or file.")
                global_error=2
        else:
            print("Missing WAS scan config id, for update action please provide --wasconfigid xxx-xxx-xxx")
            global_error = 1
    elif args.wasscanconfigdelete:
        if args.wasconfigid and args.wasscanconfigdelete==args.wasconfigid:
            result = tio.wasscans.delete(wasconfig_id=args.wasconfigid)
            handle_result(args, result)
        else:
            print("Missing WAS scan config id, for delete action please have both --wasconfigid xxx-xxx-xxx and --wasscanconfigdelete xxxx-xxx set to the same")
            global_error = 1
    elif args.wasscandelete:
        if args.wasscanid and args.wasscandelete==args.wasscanid:
            result = tio.wasscans.delete(wasscan_id=args.wasscanid)
            handle_result(args, result)
        else:
            print("Missing WAS scan id, for delete action please have both --wasscanid xxx-xxx-xxx and --wasscandelete xxxx-xxx set to the same")
            global_error = 1
    # tio.wasscans.results
    elif args.wasscanresults:
        if args.wasscanid :
            result = tio.wasscans.results(wasscan_id=args.wasscanid)
            handle_result(args, result)
        else:
            print("Missing WAS scan id, for results action please have --wasscanid xxx-xxx-xxx")
            global_error = 1
        
    # tio.wasscans.history
    elif args.wasscanhistory:
        if args.wasconfigid:
            results = tio.wasscans.history(wasconfig_id=args.wasconfigid)
            results_table = []
            for i in results:
                results_table.append(i)
            handle_result(args, results_table)
        else:
            print("Missing WAS scan config id, for history action please provide --wasconfigid xxx-xxx-xxx")
            global_error = 1

# <refactor import="refactor/code_inspect_end.py">
    if args.interactive:
        print("[INTERACTIVE] At ", lineno())
        code.interact(local=locals())
    if args.debug:
        print("Exit code: ", global_error)
    sys.exit(global_error)
# </refactor>
