import re
import sys

from settings import SETTINGS
from utils import *
from caches import cache
from database import *
from models import vulnerabilities

##############################################################################
# Find vulner in vulnerabilities table in Postgres by cve_id.
##############################################################################

def find_vulner_in_postgres_by_cve_id__list_of_items_in_json(cve_id):
    connect_database()
    database_items = list(vulnerabilities.select().where(vulnerabilities.cve_id==cve_id))
    items = []
    for database_item in database_items:
        items.append(
            database_item.to_json
        )
    disconnect_database()
    return items

##############################################################################
# Find list of vulners in vulnerabilities table in Postgres by list of cve_id.
##############################################################################

def find_list_of_vulners_in_postgres_by_cve_id__list_of_items_in_json(list_of_cve_ids):
    items = []
    if isinstance(list_of_cve_ids, list):
        connect_database()
        for cve_id in list_of_cve_ids:
            database_items = list(vulnerabilities.select().where(vulnerabilities.cve_id == cve_id))
            for database_item in database_items:
                items = items + [database_item.to_json]
        disconnect_database()
    return items

##############################################################################
# Find list of vulners in vulnerabilities table in Postgres
# by component and version.
# Return list of Items in JSON format.
##############################################################################

def find_vulners_in_postgres_by_component_and_version__list_of_items_in_json(component, version):
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

##############################################################################
# Find list of vulners in vulnerabilities table in Postgres
# by list of components and its versions.
# Return list of Items in JSON format.
##############################################################################

def find_list_of_vulners_in_postgres_by_component_and_versions_list__list_of_items_in_json(list_of_component_and_versions):
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

##############################################################################
# Create collectin name for cache search.
##############################################################################

def create_collection_name_by_component_and_version(component, version):
    if version is None:
        version = "*"
    if version == "":
        version = "*"
    collection_name = "".join([
        SETTINGS["cache"]["index"],
        SETTINGS["cache"]["separator"],
        component,
        SETTINGS["cache"]["separator"],
        str(version)
    ])
    return collection_name

##############################################################################
# Check if item already in cache by component and version.
# Return list of Items in JSON format.
##############################################################################

def check_if_item_is_already_cached_in_redis__list_of_items_in_json(component, version):
    collection_name = create_collection_name_by_component_and_version(
        component=component,
        version=version
    )
    elements_in_cache = []
    try:
        elements_in_cache = cache.lrange(
            collection_name, 0, -1
        )
    except:
        pass
    list_of_components = []
    for element in elements_in_cache:
        list_of_components.append(
            deserialize_as_json__for_cache(
                element
            )
        )
    return list_of_components

##############################################################################
# Put Items (in list) into cache.
##############################################################################

def put_items_into_redis_cache(items_to_cache):
    count = 0
    for element in items_to_cache:
        component = element.get("component", None)
        version = element.get("version", None)
        if component is not None and version is not None:
            collection_name = create_collection_name_by_component_and_version(
                component=component,
                version=version
            )
            try:
                cache.rpush(
                    collection_name,
                    serialize_as_json__for_cache(
                        element=element
                    )
                )
                cache.expire(
                    collection_name,
                    SETTINGS["cache"]["key_expire_time_in_sec"]
                )
                count += 1
            except Exception as ex:
                print("{}".format(ex))
    return count


##############################################################################
# Search items by list of components and its versions in Postgres and in Cache.
##############################################################################

def fast_search_for_list_of_vulners__list_of_items_as_json(list_of_component_and_versions):
    ready_items = []
    for item in list_of_component_and_versions:
        if isinstance(item, dict):
            component = item.get("component", None)
            version = item.get("version", None)
            if component is not None and version is not None:
                items_in_redis = check_if_item_is_already_cached_in_redis__list_of_items_in_json(component, version)
                if len(items_in_redis) > 0:
                    # If item in redis - get data from redis
                    ready_items = ready_items + items_in_redis
                else:
                    # If item not in redis - get data from postgres
                    items_in_postgres = find_vulners_in_postgres_by_component_and_version__list_of_items_in_json(
                        component=component,
                        version=version
                    )
                    # And put it into cache
                    put_items_into_redis_cache(items_in_postgres)
                    # Append result
                    ready_items = ready_items + items_in_postgres
    return ready_items

##############################################################################
# Reformat vulnet for Response.
##############################################################################

def only_digits(var):
    return re.sub("\D", "", var)

def reformat_vulner_for_output__json(item_to_reformat):
    published = unify_time(item_to_reformat.get("publushed", datetime.utcnow()))
    modified = unify_time(item_to_reformat.get("modified", datetime.utcnow()))
    access = item_to_reformat.get("access", dict(
            vector="",
            complexity="",
            authentication=""
        ))
    impact = item_to_reformat.get("impact", dict(
            confidentiality="",
            integrity="",
            availability=""
        ))
    cvss_time = unify_time(item_to_reformat.get("cvss_time", datetime.utcnow()))
    cvss = float(item_to_reformat.get("cvss", "0.0"))
    cwe_json = item_to_reformat.get("cwe", "")
    cwe_list = cwe_json.get("data", [])
    if len(cwe_list) > 0:
        cwe = cwe_list[0]
    else:
        cwe = ""
    cwe_id = only_digits(cwe)
    template = dict(
        Published=published,
        Modified=modified,
        access=access,
        impact=impact,
        cvss_time=cvss_time,
        cvss=cvss,
        cwe=cwe,
        cwe_id=cwe_id,
        title=item_to_reformat.get("cve_id", ""),
        description=item_to_reformat.get("description", ""),
        rank=item_to_reformat.get("rank", ""),
        __v=item_to_reformat.get("__v", ""),
        capec=item_to_reformat.get("capec", []),
        vulnerable_configurations=item_to_reformat.get("vulnerable_configurations", []),
        vulnerable_configuration=item_to_reformat.get("cpe", []),
        cve_references=item_to_reformat.get("references", [])
    )
    return template

##############################################################################
# Search one Item by component and it version from JSON request
# in Postgres and in Cache.
# Return reformatted item.
##############################################################################

def fast_search_for_one_vulner_in_json__list_of_items_in_json(item_to_search):
    # Source request for search:

    # {"project_id":"5aed6441ba733d37419d5565",
    #  "organization_id":"5ae05fde9531a003aacdacf8",
    #  "set_id":"5aed6441ba733d37419d5564",
    #  "component":{
    #       "name":"tomcat","version":"3.0"}}
    ready_items = []
    if isinstance(item_to_search, dict):
        component_and_version = item_to_search.get("component", {})
        if isinstance(component_and_version, dict):
            component = component_and_version.get("name", None)
            version = component_and_version.get("version", None)
            if component is not None and version is not None:
                items_in_redis = check_if_item_is_already_cached_in_redis__list_of_items_in_json(component, version)
                if len(items_in_redis) > 0:
                    # If item in redis - get data from redis
                    ready_items = ready_items + items_in_redis
                else:
                    # If item not in redis - get data from postgres
                    items_in_postgres = find_vulners_in_postgres_by_component_and_version__list_of_items_in_json(
                        component=component,
                        version=version
                    )
                    # And put it into cache
                    put_items_into_redis_cache(items_in_postgres)
                    # Append result
                    ready_items = ready_items + items_in_postgres
        pass
    # Reformat items
    reformatted_items = []
    for item in ready_items:
        reformatted_items.append(
            reformat_vulner_for_output__json(
                item
            )
        )
    return reformatted_items

def tests():
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

    # start_time = time.time()
    # print_list(find_list_of_vulners_in_postgres_by_component_and_versions_list__list_of_items([
    #     {"component": "ffmpeg", "version": "3.2*"},
    # ]))
    # print("TimeDelta: {}".format(time.time() - start_time))

    # search_request = {
    #     "project_id": "5aed6441ba733d37419d5565",
    #     "organization_id": "5ae05fde9531a003aacdacf8",
    #     "set_id": "5aed6441ba733d37419d5564",
    #     "component": {
    #         "name": "junos",
    #         "version": "14.1"}}
    #
    # start_time = time.time()
    # fast_search_for_one_vulner_in_json__list_of_items_in_json(search_request)
    # print("TimeDelta: {}".format(time.time() - start_time))
    pass

def main():
    pass


if __name__ == '__main__':
    sys.exit(main())