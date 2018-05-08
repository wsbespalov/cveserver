import sys
import pika
import ast
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
        "port": "5432",
        "drop_before": True,
        "cache_size_mb": 64
    },
    "debug": True
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

def connect_database():
    # database.pragma('cache_size', -1024 * int(SETTINGS["postgres"]["cache_size"]))
    try:
        if database.is_closed():
            database.connect()
    except peewee.OperationalError as peewee_operational_error:
        pass

def disconnect_database():
    try:
        if not database.is_closed():
            database.close()
    except peewee.OperationalError as peewee_operational_error:
        pass

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

class vulnerabilities(peewee.Model):
    class Meta:
        database = database
        table_name = "vulnerabilities"

    id = peewee.PrimaryKeyField(null=False,)
    component = peewee.TextField(default="",)
    version = peewee.TextField(default="",)
    data_type = peewee.TextField(default="",)
    data_format = peewee.TextField(default="",)
    data_version = peewee.TextField(default="",)
    cve_id = peewee.TextField(default="",)
    cwe = peewee.TextField(default='{"data":[]},')
    references = peewee.TextField(default='{"data":[]}',)
    description = peewee.TextField(default="",)
    cpe = peewee.TextField(default="",)
    vulnerable_configuration = peewee.TextField(default='{"data":[]}',)
    published = peewee.DateTimeField(default=datetime.now,)
    modified = peewee.DateTimeField(default=datetime.now,)

    def __unicode__(self):
        return "vulnerabilities"

    def __str__(self):
        return self.cve_id

    @property
    def to_json(self):
        return dict(
            id=self.id,
            component=self.component,
            version=self.version,
            data_type=self.data_type,
            data_format=self.data_format,
            data_version=self.data_version,
            cve_id=self.cve_id,
            cwe=self.cwe,
            references=self.references,
            description=self.description,
            cpe=self.cpe,
            vulnerable_configuration=self.vulnerable_configuration,
            published=self.published,
            modified=self.modified
        )


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

def serialize_json(source):
    return json.dumps(ast.literal_eval(source))

def deserialize_json(source):
    a = ast.literal_eval(source)
    if isinstance(a, dict):
        return a
    return json.loads(a)

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

def normalize_ts(first_ts, second_ts):

    pass

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

def filter_items_to_update__list_of_items(items_fo_filter):
    filtered_items = []
    # for item in items_fo_filter:
    for item in progressbar(items_fo_filter, prefix='Filtering  '):
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

def if_item_already_exists__ids(component, version, cve_id):
    # Get IDs of records
    list_of_elements = list(
        vulnerabilities.select().where(
            (vulnerabilities.component==component) &
            (vulnerabilities.version==version) &
            (vulnerabilities.cve_id==cve_id)
        )
    )
    list_of_ids = []
    for element in list_of_elements:
        list_of_ids.append(element.id)
    return list_of_ids

def create_record_in_database__vulner_id(item_to_create):
    vulner = vulnerabilities(
        component=item_to_create.get("component", ""),
        version=item_to_create.get("version", ""),
        data_type=item_to_create.get("data_type", ""),
        data_format=item_to_create.get("data_format", ""),
        data_version=item_to_create.get("data_version", ""),
        cve_id=item_to_create.get("cve_id", ""),
        cwe=item_to_create.get("cwe", '{"data": []}'),
        references=item_to_create.get("references", '{"data": []}'),
        description=item_to_create.get("description", ""),
        cpe=item_to_create.get("cpe", ""),
        vulnerable_configuration=item_to_create.get("vulnerable_configuration", '{"data": []}'),
        published=item_to_create.get("published", str(datetime.utcnow())),
        modified=item_to_create.get("modified", str(datetime.utcnow()))
    )
    vulner.save()
    return vulner.id

def update_vulner_in_database__vulner_id(item_to_update, item_id_in_database):
    was_modified = False
    vulner_from_database = vulnerabilities.get(vulnerabilities.id==item_id_in_database)
    vulner = vulner_from_database.to_json
    if vulner["data_type"] != item_to_update["data_type"]:
        was_modified = True
        vulner_from_database.data_type = item_to_update["data_type"]
    if vulner["data_format"] != item_to_update["data_format"]:
        was_modified = True
        vulner_from_database.data_format = item_to_update["data_format"]
    if vulner["data_version"] != item_to_update["data_version"]:
        was_modified = True
        vulner_from_database.data_version = item_to_update["data_version"]
    if deserialize_json(vulner["cwe"]) != item_to_update["cwe"]:
        was_modified = True
        vulner_from_database.cwe = serialize_json(item_to_update["cwe"])
    if deserialize_json(vulner["references"]) != item_to_update["references"]:
        was_modified = True
        vulner_from_database.references = serialize_json(item_to_update["references"])
    if vulner["description"] != item_to_update["description"]:
        was_modified = True
        vulner_from_database.description = item_to_update["description"]
    if vulner["cpe"] != item_to_update["cpe"]:
        was_modified = True
        vulner_from_database.cpe = item_to_update["cpe"]
    if deserialize_json(vulner["vulnerable_configuration"]) != item_to_update["vulnerable_configuration"]:
        was_modified = True
        vulner_from_database.vulnerable_configuration = serialize_json(item_to_update["vulnerable_configuration"])
    if unify_time(vulner["published"]) != unify_time(item_to_update["published"]):
        was_modified = True
        vulner_from_database.published = unify_time(item_to_update["published"])
    if unify_time(vulner["modified"]) != unify_time(item_to_update["modified"]):
        was_modified = True
        vulner_from_database.modified = unify_time(item_to_update["modified"])
    if was_modified:
        vulner_from_database.save()
    return vulner_from_database.id

def update_vulners_table__counts(items_to_update):
    start_time = time.time()
    count_of_new_records = 0
    count_of_updated_records = 0

    connect_database()

    vulnerabilities.create_table()

    # For every item in items to update
    # for one_item in items_to_update:
    for one_item in progressbar(items_to_update):
        # Check if exists
        component = one_item.get("component", None)
        version = one_item.get("version", None)
        cve_id = one_item.get("cve_id", None)
        if component is not None and \
            version is not None and \
            cve_id is not None:
            if_records_exists_in_database__ids = if_item_already_exists__ids(component, version, cve_id)
            if len(if_records_exists_in_database__ids) > 0:
                for item_id_in_database in if_records_exists_in_database__ids:
                    update_vulner_in_database__vulner_id(one_item, item_id_in_database)
                    count_of_updated_records += 1
            else:
                create_record_in_database__vulner_id(one_item)
                count_of_new_records += 1
        pass

    disconnect_database()

    return count_of_new_records, count_of_updated_records, time.time() - start_time

##############################################################################

def populate_cve_from_source__counts():
    start_time = time.time()
    start_year = SETTINGS.get("start_year", 2018)
    current_year = datetime.now().year
    count_of_parsed_cve_items = 0
    count_of_populated_items = 0
    for year in range(start_year, current_year + 1):
        print("Populate CVE-{}".format(year))
        source = SETTINGS["sources"]["cve_base"] + str(year) + SETTINGS["sources"]["cve_base_postfix"]

        cve_item, response = download_cve_file(source)

        parsed_cve_items = parse_cve_file__list_json(cve_item)

        items_to_populate = filter_items_to_update__list_of_items(parsed_cve_items)

        update_vulners_table__counts(items_to_populate)

        count_of_parsed_cve_items += len(parsed_cve_items)
        count_of_populated_items += len(items_to_populate)
    return count_of_parsed_cve_items, count_of_populated_items, time.time() - start_time

def update_modified_cves_from_source__counts():
    start_time = time.time()
    count_of_parsed_cve_items = 0
    count_of_updated_items = 0

    modified_items, response = download_cve_file(SETTINGS["sources"]["cve_modified"])
    modified_parsed = parse_cve_file__list_json(modified_items)

    items_to_update = filter_items_to_update__list_of_items(modified_parsed)

    update_vulners_table__counts(items_to_update)

    count_of_parsed_cve_items = len(modified_parsed)
    count_of_updated_items = len(items_to_update)
    return count_of_parsed_cve_items, count_of_updated_items, time.time() - start_time

def update_recent_cves_from_source__counts():
    start_time = time.time()
    count_of_parsed_cve_items = 0
    count_of_updated_items = 0

    recent_items, response = download_cve_file(SETTINGS["sources"]["cve_recent"])
    recent_parsed = parse_cve_file__list_json(recent_items)

    items_to_update = filter_items_to_update__list_of_items(recent_parsed)

    update_vulners_table__counts(items_to_update)

    count_of_parsed_cve_items = len(recent_parsed)
    count_of_updated_items = len(items_to_update)
    return count_of_parsed_cve_items, count_of_updated_items, time.time() - start_time

##############################################################################

def find_vulner_in_postgres_by_cve_id__list_of_items(cve_id):
    connect_database()
    database_items = list(vulnerabilities.select().where(vulnerabilities.cve_id==cve_id))
    items = []
    for database_item in database_items:
        items.append(
            database_item.to_json
        )
    disconnect_database()
    return items

def find_list_of_vulners_in_postgres_by_cve_id__list_of_items(list_of_cve_ids):
    items = []
    if isinstance(list_of_cve_ids, list):
        connect_database()
        for cve_id in list_of_cve_ids:
            database_items = list(vulnerabilities.select().where(vulnerabilities.cve_id == cve_id))
            for database_item in database_items:
                items = items + [database_item.to_json]
        disconnect_database()
    return items

def find_vulner_in_postgres_by_component_and_version__list_of_items(component, version):
    connect_database()
    list_of_elements = []
    if "*" in version:
        version = version[:version.index("*")]
        list_of_elements = list(
            vulnerabilities.select().where(
                (vulnerabilities.component == component) &
                (vulnerabilities.version.startswith(version))
            )
        )
    else:
        list_of_elements = list(
            vulnerabilities.select().where(
                (vulnerabilities.component == component) &
                (vulnerabilities.version == version)
            )
        )
    items = []
    for element in list_of_elements:
        items.append(element.to_json)
    disconnect_database()
    return items

def find_list_of_vulners_in_postgres_by_component_and_versions_list__list_of_items(list_of_component_and_versions):
    """
    Get list if vulners with component and versions.
    If version contains "*" - slice version and use "startwith".
    example:
        version = "1.3.*" -> version = "1.3."
    :param list_of_component_and_versions:
    :return:
    """
    items = []
    if isinstance(list_of_component_and_versions, list):
        connect_database()
        for component_and_version in list_of_component_and_versions:
            if isinstance(component_and_version, dict):
                component = str(component_and_version["component"])
                version = str(component_and_version["version"])
                list_of_elements = []

                if "*" in version:
                    version = version[:version.index("*")]
                    list_of_elements = list(
                        vulnerabilities.select().where(
                            (vulnerabilities.component == component) &
                            (vulnerabilities.version.startswith(version))
                        )
                    )
                else:
                    list_of_elements = list(
                        vulnerabilities.select().where(
                            (vulnerabilities.component == component) &
                            (vulnerabilities.version == version)
                        )
                    )
                new_items = []
                for element in list_of_elements:
                    new_items.append(element.to_json)
                items = items + new_items
        disconnect_database()
    return items

def reformat_vulner_for_output__json(item_to_reformat):
    pass

##############################################################################

def main():
    # if SETTINGS["postgres"]["drop_before"]:
    #     print('Table ~vulnerabilities~ will be drop according SETTINGS ~drop_before~ parameter.')
    #     connect_database()
    #     vulnerabilities.delete()
    #     disconnect_database()

    # print("Start population of database")
    # count_of_parsed_cve_items, count_of_populated_items, time_delta = populate_cve_from_source__counts()
    # print("Get        {} populated elements from source".format(count_of_parsed_cve_items))
    # print("Append     {} populated elements from source in database".format(count_of_populated_items))
    # print("TimeDelta  %.2f sec." % (time_delta))

    # print("Start update modified of database")
    # count_of_parsed_cve_items, count_of_updated_items, time_delta = update_modified_cves_from_source__counts()
    # print("Get        {} modified elements from source".format(count_of_parsed_cve_items))
    # print("Append     {} modified elements from source in database".format(count_of_updated_items))
    # print("TimeDelta  %.2f sec." % (time_delta))

    # print("Start update recent of database")
    # count_of_parsed_cve_items, count_of_updated_items, time_delta = update_recent_cves_from_source__counts()
    # print("Get        {} recent elements from source".format(count_of_parsed_cve_items))
    # print("Append     {} recent elements from souce in database".format(count_of_updated_items))
    # print("TimeDelta  %.2f sec." % (time_delta))

    # connect_database()
    # count = vulnerabilities.select().count()
    # disconnect_database()
    # print('Table ~vulnerabilities~ count now is: {}'.format(count))



    # start_time = time.time()
    # print_list(find_vulner_in_postgres_by_cve_id__list_of_items("CVE-2018-0001"))
    # print("TimeDelta: {}".format(time.time() - start_time))



    # start_time = time.time()
    # print_list(find_list_of_vulners_in_postgres_by_cve_id__list_of_items([
    #     "CVE-2018-0001",
    #     "CVE-2018-0003",
    #     "CVE-2017-9998",
    #     "CVE-2017-9993",
    #     "CVE-2017-9992",
    #     "CVE-2018-0089"]))
    # print("TimeDelta: {}".format(time.time() - start_time))
    # print("Complete   updater work.")



    # start_time = time.time()
    # print_list(find_vulner_in_postgres_by_component_and_version__list_of_items("junos", "14.1"))
    # print("TimeDelta: {}".format(time.time() - start_time))


    # start_time = time.time()
    # print_list(find_list_of_vulners_in_postgres_by_component_and_versions_list__list_of_items([
    #     {"component": "junos", "version": "14.1"},
    #     {"component": "junos", "version": "14.2"},
    #     {"component": "ffmpeg", "version": "3.2"},
    # ]))
    # print("TimeDelta: {}".format(time.time() - start_time))

    start_time = time.time()
    print_list(find_list_of_vulners_in_postgres_by_component_and_versions_list__list_of_items([
        {"component": "ffmpeg", "version": "3.2*"},
    ]))
    print("TimeDelta: {}".format(time.time() - start_time))


##############################################################################


if __name__ == '__main__':
    sys.exit(main())