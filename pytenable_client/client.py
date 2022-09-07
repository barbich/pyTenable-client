#!/usr/bin/env python
# Need to install requests package for python
# easy_install requests
import fire
import logging

import sys
from fire import parser
import re
from pprint import pprint as pp
from pprint import pformat
import json

try:
    from ConfigParser import ConfigParser
except:
    from configparser import ConfigParser

from tenable.io import TenableIO
from tenable.errors import UnexpectedValueError, FileDownloadError

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

"""
Sample usage:

# List all users of the tio
pytenable_client tio --config ../../.sectool.config --noproxy - users list -- --prettyprint --outfile users.json

# List all configured wasscans
pytenable_client tio --config ../../.sectool.config --noproxy - wasscans list -- --prettyprint --outfile wasscans.json

# List WAS scan scans
export WASCONFIG=xxx-xxx-xxx
pytenable_client tio --config ../../.sectool.config --noproxy - wasscans history $WASCONFIGID -- --prettyprint

# Get the status of a scan. 
export WASSCANID=yyy-yyy-yyy
pytenable_client tio --config ../../.sectool.config --noproxy - wasscans status $WASSCANID -- --prettyprint

# Export a scan to a file
pytenable_client tio --config ../../.sectool.config --noproxy - wasscans export --filename export.json --wasscanid $WASSCANID
pytenable_client tio --config ../../.sectool.config --noproxy --debug - wasscans export --filename export.pdf --wasscanid $WASSCANID
pytenable_client tio --config ../../.sectool.config --noproxy --debug  - wasscans export --filename export.html --wasscanid $WASSCANID
pytenable_client tio --config ../../.sectool.config --noproxy --debug  - wasscans export --filename export.csv --wasscanid $WASSCANID
pytenable_client tio --config ../../.sectool.config --noproxy --debug  - wasscans export --filename export.xml --wasscanid $WASSCANID

# Get the list of templates
pytenable_client tio --config ../../.sectool.config --noproxy --debug  - wasscans templateslist -- --outfile templates.json
pytenable_client tio --config ../../.sectool.config --noproxy --debug  - wasscans usertemplateslist -- --outfile usertemplates.json

# Get the details of a template
pytenable_client tio --config ../../.sectool.config --noproxy --debug  - wasscans templatesdetails --template_id $TEMPLATEID -- --outfile templates-details.json
pytenable_client tio --config ../../.sectool.config --noproxy --debug  - wasscans usertemplatesdetails --user_template_id $USERTEMPLATEID -- --outfile usertemplates-details.json

# Get the details of a config
pytenable_client tio --config ../../.sectool.config --noproxy --debug  - wasscans details --wasconfig_id $WASCONFIGID -- --outfile wasscan-details.json

# Create a new tenable wasscan from json file
pytenable_client tio --config ../../.sectool.config --noproxy --debug  - wasscans create --wasconfiguration=wasscan-details-input.json -- --prettyprint

# Update configuration
pytenable_client tio --config ../../.sectool.config --noproxy --debug  - wasscans configure --wasconfig_id $WASCONFIGID --wasconfiguration='{"description":"bla bla bla"}' -- --prettyprint

# Delete a configuration
pytenable_client tio --config ../../.sectool.config --noproxy --debug  - wasscans delete --wasconfig_id $WASCONFIGID

# Get scan history
pytenable_client tio --config ../../.sectool.config --noproxy --debug  - wasscans history --wasconfig_id $WASCONFIGID -- --outfile wasscan-history.json

#  Get scan history details
pytenable_client tio --config ../../.sectool.config --noproxy --debug  - wasscans results --wasscan_id $WASCONFIGID --  --outfile wasscan-result.json

"""


def required_kw(config_kw):
    """Check if required keywords are present"""
    required = ["name", "targets", "owner_id", "template_id", "settings"]
    for r in required:
        if not r in config_kw:
            print("[ERROR] Missing %s in keywords" % r)
            return False
    return True


# clas ioscan(ScansAPI):


class tio(object):
    def __init__(self, config, noproxy=False, debug=False):
        self.__config = None
        self.proxies = None
        self.__tio = None

        self.debug = debug
        self.noproxy = noproxy
        # set debugging context
        if self.debug:
            logging.basicConfig(level=logging.DEBUG)

        try:
            self.__config = ConfigParser()
            self.__config.read(config)
        except:
            logging.WARNING(
                "ConfigParser: Missing or error in configuration file", exc_info=True
            )

            if self.debug:
                logging.debug("ConfigParser: Raise")
                raise
            sys.exit(1)
        try:
            if noproxy:
                self.proxies = None
            else:
                self.proxies = {
                    "http": self.__config.get("PROXY", "http_proxy"),
                    "https": self.__config.get("PROXY", "https_proxy"),
                }
        except:
            self.proxies = None
            logging.debug("ConfigGet: Could not get proxy parameters", exc_info=True)
        if self.__config.has_section("TENABLE"):
            if self.__config.has_section("PROXY") and not (noproxy):
                self.__tio = TenableIO(
                    self.__config.get("TENABLE", "TIO_ACCESS_KEY"),
                    self.__config.get("TENABLE", "TIO_SECRET_KEY"),
                    retries=1,
                    proxies=self.proxies,
                )
            else:
                self.__tio = TenableIO(
                    self.__config.get("TENABLE", "TIO_ACCESS_KEY"),
                    self.__config.get("TENABLE", "TIO_SECRET_KEY"),
                    retries=1,
                )
            logging.debug("TIO initialized")
        else:
            logging.debug("No TENABLE section in configuration file")
            sys.exit(-1)
        # self.wss = self.__tio.wasscans # WasScan interface
        # self.wss.list = self.__wss_list
        # self.vm = self.__tio.scans # Vulnerability Management interface
        # self.users = self.__tio.users # Scan interface
        # print("[INTERACTIVE] At ", lineno())
        # Publish ALL subclasses
        # t=self.__tio
        for cls in dir(self.__tio):
            logging.debug("Adding capability %s" % cls)
            if not cls.startswith("_") and "tenable.io" in str(
                eval("type(self._tio__tio.%s)" % cls)
            ):
                # code.interact(local=locals())
                setattr(self, cls, eval("self._tio__tio.%s" % cls))

        # Overwrite some calls
        if hasattr(self, "wasscans"):
            if hasattr(self.wasscans, "list"):
                self.wasscans.list = self.__wasscans_list
            if hasattr(self.wasscans, "history"):
                self.wasscans.history = self.__wasscans_history
            if hasattr(self.wasscans, "export"):
                self.wasscans.export = self.__wasscans_export
            if hasattr(self.wasscans, "templateslist"):
                self.wasscans.templateslist = self.__wasscans_templateslist
            if hasattr(self.wasscans, "usertemplateslist"):
                self.wasscans.usertemplateslist = self.__wasscans_usertemplateslist
            if hasattr(self.wasscans, "create"):
                self.wasscans.create = self.__wasscans_create
            if hasattr(self.wasscans, "configure"):
                self.wasscans.configure = self.__wasscans_configure

        # code.interact(local=locals())

    def __wasscans_configure(self, wasconfig_id, wasconfiguration):
        config_kw = None

        try:
            config_kw = json.loads(wasconfiguration)
        except:
            logging.debug("[DEBUG] Trying to load json from string failed.")
        if not config_kw:
            # check if this is a file
            try:
                f = open(wasconfiguration)
                config_kw = json.load(f)
                f.close()
            except:
                logging.debug("[DEBUG] Trying to load json from file failed.")
                # logging.warning("Missing wasscanconfigcreate: it should be either a valid json object or file.")
                config_kw = wasconfiguration
        if config_kw:
            # check for some key fields
            result = self.__tio.wasscans.configure(
                wasconfig_id=wasconfig_id, config_dict=config_kw
            )
            logging.info("[OK] Scan created with ID %s" % result)
            return result
        else:
            logging.debug(
                "Missing wasscanconfigcreate: it should be either a valid json object or file."
            )
        raise ValueError(
            "configuration parameter should be a valid json string or path to a file containing a valid json."
        )

    def __wasscans_create(self, wasconfiguration):
        """
        Create a new wasscan.
        """
        config_kw = None
        try:
            config_kw = json.loads(wasconfiguration)
        except:
            logging.debug("[DEBUG] Trying to load json from string failed.")
        if not config_kw:
            # check if this is a file
            try:
                f = open(wasconfiguration)
                config_kw = json.load(f)
                f.close()
            except:
                logging.debug("[DEBUG] Trying to load json from file failed.")
                # logging.warning("Missing wasscanconfigcreate: it should be either a valid json object or file.")

        if config_kw:
            # check for some key fields
            if required_kw(config_kw):
                result = self.__tio.wasscans.create(config_dict=config_kw)
                logging.info("[OK] Scan created with ID %s" % result)
                return result
        else:
            logging.debug(
                "Missing wasscanconfigcreate: it should be either a valid json object or file."
            )
        raise ValueError(
            "configuration parameter should be a valid json string or path to a file containing a valid json."
        )

    def __wasscans_list(self, limit=None, offset=None, pages=None, sort=None):
        """
        Retrieve the list of configured wasscans.

        :devportal:`wasscans: list <wasscans-list>`

        Args:
            limit (int, optional):
                The number of records to retrieve.  Default is 50
            offset (int, optional):
                The starting record to retrieve.  Default is 0.
            sort (tuple, optional):
                A tuple of tuples identifying the the field and sort order of
                the field.

        Returns:
            :obj:`WasScanConfigIterator`:
                An iterator that handles the page management of the requested
                records.

        Examples:
            >>> for scan in tio.wasscans.list():
            ...     pprint(scan)
        """
        results = self.__tio.wasscans.list(
            limit=limit, offset=offset, pages=pages, sort=sort
        )
        results_table = []
        for i in results:
            results_table.append(i)
        # self.__handle_result(results_table)
        return results_table

    def __wasscans_history(
        self, wasconfig_id, limit=None, offset=None, pages=None, sort=None
    ):
        """
        Get the scan history of a given wasscan from Tenable.io.

        :devportal:`scans: history <scans-history>`

        Args:
            wasconfig_id (int or uuid):
                The unique identifier for the scan.
            limit (int, optional):
                The number of records to retrieve.  Default is 50
            offset (int, optional):
                The starting record to retrieve.  Default is 0.
            sort (tuple, optional):
                A tuple of tuples identifying the the field and sort order of
                the field.

        Returns:
            :obj:`ScanHistoryIterator`:
                An iterator that handles the page management of the requested
                records.

        Examples:
            >>> for history in tio.wasscans.history(1):
            ...     pprint(history)
        """
        results = self.__tio.wasscans.history(
            wasconfig_id=wasconfig_id,
            limit=limit,
            offset=offset,
            pages=pages,
            sort=sort,
        )
        results_table = []
        for i in results:
            results_table.append(i)
        # self.__handle_result(results_table)
        return results_table

    def __wasscans_templateslist(self, limit=None, offset=None, pages=None, sort=None):
        results = self.__tio.wasscans.templateslist(
            limit=limit, offset=offset, pages=pages, sort=sort
        )
        results_table = []
        for i in results:
            results_table.append(i)
        return results_table

    def __wasscans_usertemplateslist(
        self, limit=None, offset=None, pages=None, sort=None
    ):
        """
        Returns a paginated list of user-defined templates that are available to be used for scan configurations.
        """
        results = self.__tio.wasscans.usertemplateslist(
            limit=limit, offset=offset, pages=pages, sort=sort
        )
        results_table = []
        for i in results:
            results_table.append(i)
        return results_table

    def __wasscans_export(self, wasscanid, filename, format="application/json"):
        """
        Export the scan report.
        """
        if filename.endswith(".json"):
            f = open(filename, "wb")
            fo = self.__tio.wasscans.export(
                wasscan_id=wasscanid, fobj=f, format="application/json"
            )
            f.close()
        elif filename.endswith(".pdf"):
            f = open(filename, "wb")
            fo = self.__tio.wasscans.export(
                wasscan_id=wasscanid, fobj=f, format="application/pdf"
            )
            f.close()
        elif filename.endswith(".html") or filename.endswith(".htm"):
            f = open(filename, "wb")
            fo = self.__tio.wasscans.export(
                wasscan_id=wasscanid, fobj=f, format="text/html"
            )
            f.close()
        elif filename.endswith(".csv"):
            f = open(filename, "wb")
            fo = self.__tio.wasscans.export(
                wasscan_id=wasscanid, fobj=f, format="text/csv"
            )
            f.close()
        elif filename.endswith(".xml"):
            f = open(filename, "wb")
            fo = self.__tio.wasscans.export(
                wasscan_id=wasscanid, fobj=f, format="text/xml"
            )
            f.close()
        else:
            logging.debug("[DEBUG] Outformat for file not recognised")
            raise FileDownloadError(
                msg="Output format not recognized",
                filename=filename,
                resource="__wasscan_export",
                resource_id=wasscanid,
            )
        return "File saved: %s" % filename


def dontprint(result):
    args = sys.argv[1:]
    args, flag_args = parser.SeparateFlagArgs(args)
    argparser = parser.CreateParser()
    argparser.add_argument(
        "--outfile",
        "-o",
    )
    argparser.add_argument("--prettyprint", "-P", action="store_true")
    argparser.add_argument("--console", action="store_true")
    parsed_flag_args, unused_args = argparser.parse_known_args(flag_args)
    debug = "--debug" in args
    console = "--console" in flag_args

    response = result
    if parsed_flag_args.console:
        print("[INTERACTIVE] At ", lineno())
        code.interact(local=locals())
    try:
        response = json.dumps(result)
        if parsed_flag_args.prettyprint:
            response = pformat(result)
        if hasattr(parsed_flag_args, "outfile"):
            if parsed_flag_args.outfile.endswith(".json"):
                f = open(parsed_flag_args.outfile, "w")
                f.write(json.dumps(result))
                f.close()
            else:
                f = open(parsed_flag_args.outfile, "w")
                f.writelines(response)
                f.close()
            logging.debug("Saving to file %s" % parsed_flag_args.outfile)
            response = ""
    except:
        if console:
            print("[INTERACTIVE] At (except) ", lineno())
            code.interact(local=locals())
    return response


def cli():
    if "--debug" in sys.argv[1:]:
        logging.basicConfig(level=logging.DEBUG)

    fire.Fire(
        {
            "tio": tio,
        },
        serialize=dontprint,
    )


if __name__ == "__main__":
    cli()
