import re
import time
import json
import urllib
import string
import cpe as cpe_module
from datetime import datetime

from models import vulnerabilities

from utils import get_file
from utils import unify_time
from utils import progressbar
from utils import serialize_json__for_postgres
from utils import deserialize_json__for_postgres

from cveitem import CVEItem
from database import connect_database
from database import disconnect_database
from settings import SETTINGS

##############################################################################
# Download and parse CVE database
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

##############################################################################
# Filter CPE strings in CVE Items for valid component and version values
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

##############################################################################
# Filter Vulners items and create more items for database - one by one item
# for filtered element in cpe strings in CVE Item
##############################################################################

def filter_items_to_update__list_of_items(items_fo_filter, unquote=True, only_digits_and_dot_in_version=True):
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
                        if unquote:
                            try:
                                new_item["version"] = urllib.parse.unquote(new_item["version"])
                            except:
                                pass
                        if only_digits_and_dot_in_version:
                            allow = string.digits + '.' + '(' + ')'
                            new_item["version"] = re.sub('[^%s]' % allow, '', new_item["version"])
                        new_item["vulnerable_configuration"] = {"data": list_of_cpe_ctrings}
                        new_item["cpe"] = one_cpe_string
                        filtered_items.append(new_item)
                        del new_item
    return filtered_items

##############################################################################
# Check, if items already exists in Vulnerabilities table by component,
# version and cve ID. If exists - return list of its IDs.
##############################################################################

def if_item_already_exists_in_vulnerabilities_table__ids(component, version, cve_id):
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

##############################################################################
# Create record in vulnerabilities table and return its ID.
##############################################################################

def create_record_in_vulnerabilities_table__vulner_id(item_to_create):
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

##############################################################################
# Update record in vulnerabilities table and return its ID.
##############################################################################

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
    if deserialize_json__for_postgres(vulner["cwe"]) != item_to_update["cwe"]:
        was_modified = True
        vulner_from_database.cwe = serialize_json__for_postgres(item_to_update["cwe"])
    if deserialize_json__for_postgres(vulner["references"]) != item_to_update["references"]:
        was_modified = True
        vulner_from_database.references = serialize_json__for_postgres(item_to_update["references"])
    if vulner["description"] != item_to_update["description"]:
        was_modified = True
        vulner_from_database.description = item_to_update["description"]
    if vulner["cpe"] != item_to_update["cpe"]:
        was_modified = True
        vulner_from_database.cpe = item_to_update["cpe"]
    if deserialize_json__for_postgres(vulner["vulnerable_configuration"]) != item_to_update["vulnerable_configuration"]:
        was_modified = True
        vulner_from_database.vulnerable_configuration = serialize_json__for_postgres(item_to_update["vulnerable_configuration"])
    if unify_time(vulner["published"]) != unify_time(item_to_update["published"]):
        was_modified = True
        vulner_from_database.published = unify_time(item_to_update["published"])
    if unify_time(vulner["modified"]) != unify_time(item_to_update["modified"]):
        was_modified = True
        vulner_from_database.modified = unify_time(item_to_update["modified"])
    if was_modified:
        vulner_from_database.save()
    return vulner_from_database.id

##############################################################################
# Update vulnerabilities table with list of items and return counts of:
# - new records to update;
# - updated records;
# - time delta.
##############################################################################

def update_vulnerabilities_table__counts(items_to_update):
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
            if_records_exists_in_database__ids = if_item_already_exists_in_vulnerabilities_table__ids(component, version, cve_id)
            if len(if_records_exists_in_database__ids) > 0:
                for item_id_in_database in if_records_exists_in_database__ids:
                    update_vulner_in_database__vulner_id(one_item, item_id_in_database)
                    count_of_updated_records += 1
            else:
                create_record_in_vulnerabilities_table__vulner_id(one_item)
                count_of_new_records += 1
        pass

    disconnect_database()

    return count_of_new_records, count_of_updated_records, time.time() - start_time

##############################################################################
# Populate vulnerabilities table and return counts of:
# - new records to update;
# - updated records;
# - time delta.
##############################################################################

def populate_vulners_from_source__counts():
    start_time = time.time()
    start_year = SETTINGS.get("start_year", 2018)
    current_year = datetime.now().year
    count_of_parsed_cve_items = 0
    count_of_populated_items = 0
    if start_year < int(SETTINGS["minimum_year"]):
        print("Start year less 2002 (set eq. 2002 now) - please check it ini SETTINGS.")
        start_year = int(SETTINGS["minimum_year"])
    for year in range(start_year, current_year + 1):
        print("Populate CVE-{}".format(year))
        source = SETTINGS["sources"]["cve_base"] + str(year) + SETTINGS["sources"]["cve_base_postfix"]

        cve_item, response = download_cve_file(source)

        parsed_cve_items = parse_cve_file__list_json(cve_item)

        items_to_populate = filter_items_to_update__list_of_items(parsed_cve_items)

        update_vulnerabilities_table__counts(items_to_populate)

        count_of_parsed_cve_items += len(parsed_cve_items)
        count_of_populated_items += len(items_to_populate)
    return count_of_parsed_cve_items, count_of_populated_items, time.time() - start_time

##############################################################################
# Update modified elements in vulnerabilities table and return counts of:
# - new records to update;
# - updated records;
# - time delta.
##############################################################################

def update_modified_vulners_from_source__counts():
    start_time = time.time()
    count_of_parsed_cve_items = 0
    count_of_updated_items = 0

    modified_items, response = download_cve_file(SETTINGS["sources"]["cve_modified"])
    modified_parsed = parse_cve_file__list_json(modified_items)

    items_to_update = filter_items_to_update__list_of_items(modified_parsed)

    update_vulnerabilities_table__counts(items_to_update)

    count_of_parsed_cve_items = len(modified_parsed)
    count_of_updated_items = len(items_to_update)
    return count_of_parsed_cve_items, count_of_updated_items, time.time() - start_time

##############################################################################
# Update recent elements in vulnerabilities table and return counts of:
# - new records to update;
# - updated records;
# - time delta.
##############################################################################

def update_recent_vulners_from_source__counts():
    start_time = time.time()
    count_of_parsed_cve_items = 0
    count_of_updated_items = 0

    recent_items, response = download_cve_file(SETTINGS["sources"]["cve_recent"])
    recent_parsed = parse_cve_file__list_json(recent_items)

    items_to_update = filter_items_to_update__list_of_items(recent_parsed)

    update_vulnerabilities_table__counts(items_to_update)

    count_of_parsed_cve_items = len(recent_parsed)
    count_of_updated_items = len(items_to_update)
    return count_of_parsed_cve_items, count_of_updated_items, time.time() - start_time

##############################################################################
# Get vulnerabilities table count on Postgres
##############################################################################

def get_vulners_table_count():
    connect_database()
    count = vulnerabilities.select().count()
    disconnect_database()
    print('Table ~vulnerabilities~ count now is: {}'.format(count))

##############################################################################
# Drop vulnerabilities table.
##############################################################################

def drop_vulners_table():
    if SETTINGS["postgres"]["drop_before"]:
        print('Table ~vulnerabilities~ will be drop according SETTINGS ~drop_before~ parameter.')
        connect_database()
        vulnerabilities.delete()
        disconnect_database()
