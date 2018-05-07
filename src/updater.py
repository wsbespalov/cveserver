import sys
import pika
import peewee
import json
import time
from dateutil.parser import parse as parse_datetime
from datetime import datetime
import cpe as cpe_module
from utils import *

##############################################################################

SETTINGS = {
    "sources": {
        "cve_modified": "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.gz",
        "cve_recent": "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-recent.json.gz",
        "cve_base": "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-",
        "cve_base_postfix": ".json.gz",
        "cpe22": "https://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.2.xml.zip",
        "cpe23": "https://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip",
        "cwe": "http://cwe.mitre.org/data/xml/cwec_v2.8.xml.zip",
        "capec": "http://capec.mitre.org/data/xml/capec_v2.6.xml",
        "ms": "http://download.microsoft.com/download/6/7/3/673E4349-1CA5-40B9-8879-095C72D5B49D/BulletinSearch.xlsx",
        "d2sec": "http://www.d2sec.com/exploits/elliot.xml",
        "npm": "https://api.nodesecurity.io/advisories",
    },
    "start_year": 2018,
    "postgres": {
        "user": 'admin',
        "password": '123',
        "database": "updater_db",
        "host": "localhost",
        "port": "5432"
    }
}

##############################################################################

POSTGRES = SETTINGS.get("postgres", {})
database = peewee.PostgresqlDatabase(
    database=POSTGRES.get("database", "updater_db"),
    user=POSTGRES.get("user", "postgres"),
    password=POSTGRES.get("password", "password"),
    host=POSTGRES.get("host", "localhost"),
    port=int(POSTGRES.get("port", 5432))
)

##############################################################################

class CVEItem(object):
    def __init__(self, data):
        cve = data.get("cve", {})
        # Get Data Type -> str
        self.data_type = cve.get("data_type", None)
        # Get Data Format -> str
        self.data_format = cve.get("data_format", None)
        # Get Data Version -> str
        self.data_version = cve.get("data_version", None)  # Data version like 4.0
        # Get CVE ID like CVE-2002-2446 -> str
        CVE_data_meta = cve.get("CVE_data_meta", {})
        self.cve_id = CVE_data_meta.get("ID", None)
        # GET CWEs -> JSON with list -> {"data": cwe}
        cwe = []
        problemtype = cve.get("problemtype", {})
        problemtype_data = problemtype.get("problemtype_data", [])
        for pd in problemtype_data:
            description = pd.get("description", [])
            for d in description:
                value = d.get("value", None)
                if value is not None:
                    cwe.append(value)
        self.cwe = {"data": cwe}
        # GET RREFERENCES -> JSON with list -> {"data": references}
        references = []
        ref = cve.get("references", {})
        reference_data = ref.get("reference_data", [])
        for rd in reference_data:
            url = rd.get("url", None)
            if url is not None:
                references.append(url)
        self.references = {"data": references}
        # GET DESCRIPTION -> str
        self.description = ""
        descr = cve.get("description", {})
        description_data = descr.get("description_data", [])
        for dd in description_data:
            value = dd.get("value", "")
            self.description = self.description + value
        # GET cpe -> JSON with list -> {"data": cpe22}
        cpe22 = []
        conf = data.get("configurations", {})
        nodes = conf.get("nodes", [])
        for n in nodes:
            cpe = n.get("cpe", [])
            for c in cpe:
                c22 = c.get("cpe22Uri", None)
                cpe22.append(c22)
        self.vulnerable_configuration = {"data": cpe22}
        self.cpe = ""
        self.published = data.get("publishedDate", datetime.utcnow())
        self.modified = data.get("lastModifiedDate", datetime.utcnow())

        # Additional fields
        self.component = ""
        self.version = ""

    def to_json(self):
        return json.dumps(self,
                          default=lambda o: o.__dict__,
                          sort_keys=True)

##############################################################################

def download_cve_file(source):
    file_stream, response_info = get_file(source)
    try:
        result = json.load(file_stream)
        if "CVE_Items" in result:
            return result["CVE_Items"], response_info
        return None
    except json.JSONDecodeError as json_error:
        print('Get an JSON decode error: {}'.format(json_error))
        return None


def parse_cve_file__list_json(items=None):
    if items is None:
        items = []
    parsed_items = []
    for item in items:
        parsed_items.append(json.loads(CVEItem(item).to_json()))
    return parsed_items


def unify_time(dt):
    if isinstance(dt, str):
        if 'Z' in dt:
            dt = dt.replace('Z', '')
        return parse_datetime(dt)

    if isinstance(dt, datetime):
        return parse_datetime(str(dt))

def unify_bool(param):
    if isinstance(param, bool):
        if param is False:
            return 'false'
        elif param is True:
            return 'true'
    elif isinstance(param, str):
        if param == 'False':
            return 'false'
        elif param == 'True':
            return 'true'
        elif param == '':
            return 'false'
    elif isinstance(param, type(None)):
        return 'false'

def print_list(items_to_print):
    for item in items_to_print:
        print("-> {}".format(item))

def print_short(items_to_print):
    for item in items_to_print:
        print("Component: {}, version: {}, CVE: {}, CP: {}, VCONF: {}".format(
            item["component"],
            item["version"],
            item["cve_id"],
            item["cpe"],
            item["vulnerable_configuration"]["data"]))

def progressbar(it, prefix="Processing ", size=50):
    count = len(it)

    def _show(_i):
        if count != 0 and sys.stdout.isatty():
            x = int(size * _i / count)
            sys.stdout.write("%s[%s%s] %i/%i\r" % (prefix, "#" * x, " " * (size - x), _i, count))
            sys.stdout.flush()

    _show(0)
    for i, item in enumerate(it):
        yield item
        _show(i + 1)
    sys.stdout.write("\n")
    sys.stdout.flush()

##############################################################################

def filter_cpe_string__json(element):
    result = {
        "component": None,
        "version": None
    }
    try:
        c22 = cpe_module.CPE(element, cpe_module.CPE.VERSION_2_2)
    except ValueError as value_error:
        try:
            c22 = cpe_module.CPE(element, cpe_module.CPE.VERSION_2_3)
        except ValueError as another_value_error:
            try:
                c22 = cpe_module.CPE(element, cpe_module.CPE.VERSION_UNDEFINED)
            except NotImplementedError as not_implemented_error:
                c22 = None

    c22_product = c22.get_product() if c22 is not None else []
    c22_version = c22.get_version() if c22 is not None else []
    result["component"] = c22_product[0] if isinstance(c22_product, list) and len(c22_product) > 0 else None
    result["version"] = c22_version[0] if isinstance(c22_version, list) and len(c22_version) > 0 else None

    return result

def filter_items_to_update(items_fo_filter):
    filtered_items = []
    for item in items_fo_filter:
        # For every item in downloaded update
        # Get cpe strings
        list_of_cpe_ctrings_field = item.get("vulnerable_configuration", {})
        list_of_cpe_ctrings = list_of_cpe_ctrings_field.get("data", [])
        # If list not empty
        if len(list_of_cpe_ctrings) > 0:
            # For every cpe string
            for one_cpe_string in list_of_cpe_ctrings:
                # Get one string and check it
                filtered_cpe_string = filter_cpe_string__json(one_cpe_string)
                version = filtered_cpe_string.get("version", "")
                component = filtered_cpe_string.get("component", "")
                if version is not None and not str(version).__eq__(""):
                    if component is not None and not str(component).__eq__(""):
                        # Copy item into filtered items
                        new_item = {}
                        new_item = item.copy()
                        new_item["component"] = filtered_cpe_string["component"]
                        new_item["version"] = filtered_cpe_string["version"]
                        new_item["vulnerable_configuration"] = {"data": list_of_cpe_ctrings}
                        new_item["cpe"] = one_cpe_string
                        filtered_items.append(new_item)
                        del new_item
    return filtered_items

##############################################################################

def update_vulners_table(items_to_update):
    # print_list(items_to_update)
    print_short(items_to_update)
    pass

##############################################################################

def populate_cve_from_source():
    start_year = SETTINGS.get("start_year", 2018)
    current_year = datetime.now().year
    for year in range(start_year, current_year + 1):
        print("Populate CVE-{}".format(year))
        source = SETTINGS["sources"]["cve_base"] + str(year) + SETTINGS["sources"]["cve_base_postfix"]
        cve_item, response = download_cve_file(source)
        parsed_cve_items = parse_cve_file__list_json(cve_item)
        items_to_populate = filter_items_to_update(parsed_cve_items)
        update_vulners_table(items_to_populate)
        print("Get {} populated elements from source".format(len(parsed_cve_items)))
        print("Append {} populated elements from souce in database".format(len(items_to_populate)))


def update_modified_cves_from_source():
    modified_items, response = download_cve_file(SETTINGS["sources"]["cve_modified"])
    modified_parsed = parse_cve_file__list_json(modified_items)

    items_to_update = filter_items_to_update(modified_parsed)

    update_vulners_table(items_to_update)

    print("Get {} modified elements from source".format(len(modified_parsed)))
    print("Append {} modified elements from souce in database".format(len(items_to_update)))

def update_recent_cves_from_source():
    recent_items, response = download_cve_file(SETTINGS["sources"]["cve_recent"])
    recent_parsed = parse_cve_file__list_json(recent_items)

    items_to_update = filter_items_to_update(recent_parsed)

    update_vulners_table(items_to_update)

    print("Get {} reccent elements from source".format(len(recent_parsed)))
    print("Append {} recent elements from souce in database".format(len(items_to_update)))

##############################################################################

def main():
    populate_cve_from_source()
    # update_modified_cves_from_source()
    # update_recent_cves_from_source()
    print("Complete updater work.")

##############################################################################


if __name__ == '__main__':
    sys.exit(main())