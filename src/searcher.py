import re
from math import floor
from utils import *
from caches import cache, queue
from database import *
from models import vulnerabilities


def find_vulner_in_postgres_by_cve_id(cve_id):
    """
    Find vulner in vulnerabilities table in PostgresQL by cve_id
    :param cve_id:
    :return: list of json items
    """
    connect_database()
    database_items = list(vulnerabilities.select().where(vulnerabilities.cve_id==cve_id))
    items = []
    for database_item in database_items:
        items.append(
            database_item.to_json
        )
    disconnect_database()
    return items


def find_list_of_vulners_in_postgres_by_cve_id(list_of_cve_ids):
    """
    Find list of vulners in vulnerabilities table in PostgresQL by list of cve_id
    :param list_of_cve_ids:
    :return: list of json items
    """
    items = []
    if isinstance(list_of_cve_ids, list):
        connect_database()
        for cve_id in list_of_cve_ids:
            database_items = list(vulnerabilities.select().where(vulnerabilities.cve_id == cve_id))
            for database_item in database_items:
                items = items + [database_item.to_json]
        disconnect_database()
    return items


def find_vulners_in_postgres_by_component_and_version(component, version):
    """
    Find list of vulners in vulnerabilities table in Postgres by component and version
    :param component:
    :param version:
    :return: list of json items
    """
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


def find_list_of_vulners_in_postgres_by_component_and_versions_list(list_of_component_and_versions):
    """
    Find list of vulners in vulnerabilities table in Postgres by list of components and its versions
    :param list_of_component_and_versions:
    :return: list of json items
    """

    # If version contains "*" - slice version and use "startswith".
    # example:
    #     version = "1.3.*" -> version = "1.3."

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


def create_collection_name_by_component_and_version(component, version):
    """
    Create collection name for cache search
    :param component:
    :param version:
    :return: collection name
    """
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


def check_if_item_is_already_cached_in_redis(component, version):
    """
    Check if item already exists in cache by component and version
    :param component:
    :param version:
    :return: list of json items
    """
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


def put_items_into_redis_cache(items_to_cache):
    """
    Put list Items into cache
    :param items_to_cache:
    :return: item put count
    """
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


def fast_search_for_list_of_vulners__list_of_items_as_json(list_of_component_and_versions):
    """
    Search items by list of components and its versions in PostgresQL and Cache
    :param list_of_component_and_versions:
    :return: list of json items
    """
    ready_items = []
    for item in list_of_component_and_versions:
        if isinstance(item, dict):
            component = item.get("component", None)
            version = item.get("version", None)
            if component is not None and version is not None:
                items_in_redis = check_if_item_is_already_cached_in_redis(component, version)
                if len(items_in_redis) > 0:
                    # If item in redis - get data from redis
                    ready_items = ready_items + items_in_redis
                else:
                    # If item not in redis - get data from postgres
                    items_in_postgres = find_vulners_in_postgres_by_component_and_version(
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
    id = item_to_reformat["id"]
    published = unify_time(item_to_reformat.get("publushed", datetime.utcnow()))
    modified = unify_time(item_to_reformat.get("modified", datetime.utcnow()))
    access_in_item = item_to_reformat.get("access", dict(
            vector="",
            complexity="",
            authentication=""
        ))
    if isinstance(access_in_item, str):
        access = deserialize_json__for_postgres(access_in_item)
    else:
        access = access_in_item

    impact_in_item = item_to_reformat.get("impact", dict(
            confidentiality="",
            integrity="",
            availability=""
        ))
    if isinstance(impact_in_item, str):
        impact = deserialize_json__for_postgres(impact_in_item)
    else:
        impact = impact_in_item

    vector_string = item_to_reformat.get("vector_string", "")
    cvss_time = unify_time(item_to_reformat.get("cvss_time", datetime.utcnow()))
    cvss = item_to_reformat.get("cvss", 0.0)
    cwe_in_item = item_to_reformat.get("cwe", {})
    cwe_json = deserialize_json__for_postgres(cwe_in_item)
    cwe_list = cwe_json.get("data", [])
    cwe_id_list = []
    for cwe_in_list in cwe_list:
        cwe_id_list.append(only_digits(cwe_in_list))
    title = item_to_reformat.get("cve_id", "")
    description = item_to_reformat.get("description", "")

    rank = floor(cvss)

    __v = 0

    capec_in_item = item_to_reformat.get("capec", {})
    capec_json = deserialize_json__for_postgres(capec_in_item)
    capec_list = capec_json.get("data", [])
    capec = [] # not yet
    for capec_in_list in capec_list:
        if isinstance(capec_in_list, str):
            capec.append(json.loads(capec_in_list))
        elif isinstance(capec_in_list, dict):
            capec.append(capec_in_list)
        else:
            pass

    for i in range(0, len(capec)):
        related_weakness = capec[i].get("related_weakness", "[]")
        capec[i]["related_weakness"] = ast.literal_eval(related_weakness)

    vulnerable_configurations = []

    vulnerable_configuration_in_item = item_to_reformat.get("vulnerable_configuration", {})
    vulnerable_configuration_in_json = deserialize_json__for_postgres(vulnerable_configuration_in_item)
    vulnerable_configuration = vulnerable_configuration_in_json.get("data", [])

    cve_references_in_item = item_to_reformat.get("references", {})
    cve_references_in_json = deserialize_json__for_postgres(cve_references_in_item)
    cve_references = cve_references_in_json.get("data", [])

    template = dict(
        _id=id,
        Published=published,
        Modified=modified,
        access=access,
        impact=impact,
        cvss_time=cvss_time,
        cvss=cvss,
        cwe=cwe_list,
        cwe_id=cwe_id_list,
        title=title,
        description=description,
        rank=rank,
        __v=__v,
        capec=capec,
        vulnerable_configurations=vulnerable_configurations,
        vulnerable_configuration=vulnerable_configuration,
        cve_references=cve_references,
        vector_string=vector_string
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
                items_in_redis = check_if_item_is_already_cached_in_redis(component, version)
                if len(items_in_redis) > 0:
                    # If item in redis - get data from redis
                    ready_items = ready_items + items_in_redis
                else:
                    # If item not in redis - get data from postgres
                    items_in_postgres = find_vulners_in_postgres_by_component_and_version(
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

##############################################################################
# Scan queue for keys
##############################################################################

def scan_queue_for_keys():
    mask = SETTINGS["queue"]["prefix_requests"] + "*"
    mykeys = []
    try:
        mykeys = queue.keys(mask)
    except Exception as ex:
        print("{}".format(ex))
    return mykeys

def run():
    channel_to_subscribe_and_publish = SETTINGS["queue"]["channel"]
    message_to_start_search = SETTINGS["queue"]["message_to_start_search"]
    message_to_kill_search = SETTINGS["queue"]["message_to_kill_search"]

    subscriber = queue.pubsub()
    subscriber.subscribe([channel_to_subscribe_and_publish])

    for message in subscriber.listen():
        # For every message in this channel
        data = message.get("data", {})
        if data == 1:
            pass
        else:
            if isinstance(data, bytes):
                data = data.decode("utf-8")
            elif isinstance(data, dict):
                pass
            if data == message_to_kill_search:
                # Message to kill search
                print("Close connection")
                subscriber.unsubscribe(channel_to_subscribe_and_publish)
                break
            elif data == message_to_start_search:
                # Message to search
                # start_time = time.time()
                mask = SETTINGS["queue"]["prefix_requests"]
                # Scan queue for keys
                mykeys = scan_queue_for_keys()
                # ID for request and complete message
                id_of_request = ""
                # For every key
                for one_key in mykeys:
                    if isinstance(one_key, bytes):
                        key = one_key.decode("utf-8")
                    # Get one id
                    id_of_request = key.replace(mask, "")
                    # Create new collection name for search results
                    new_collection_name = SETTINGS["queue"]["prefix_results"] + id_of_request
                    # Get content of collection
                    collection_content = []
                    try:
                        collection_content = queue.lrange(key, 0, -1)
                    except Exception as ex:
                        pass
                    # For every content element
                    for content in collection_content:
                        search_result = []
                        content_for_search = {}
                        if isinstance(content, str):
                            content_for_search = deserialize_as_json__for_cache(content)
                        elif isinstance(content, bytes):
                            content_decoded = content.decode("utf-8")
                            content_for_search = deserialize_json__for_postgres(content_decoded)
                        elif isinstance(content, dict):
                            pass
                        else:
                            continue
                        search_result = fast_search_for_one_vulner_in_json__list_of_items_in_json(
                            content_for_search
                        )
                        for one_search_result in search_result:
                            # Append results into structure
                            # {"project_id": "5aed6441ba733d37419d5565", "organization_id": "5ae05fde9531a003aacdacf8",
                            #  "set_id": "5aed6441ba733d37419d5564", "component": {"name": "tomcat", "version": "3.0"}}
                            # -> one_search_result - found item in JSON
                            try:
                                new_content = dict(
                                    project_id=content_for_search["project_id"],
                                    organization_id=content_for_search["organization_id"],
                                    set_id=content_for_search["set_id"],
                                    component=dict(
                                        name=content_for_search["component"]["name"],
                                        version=content_for_search["component"]["version"]
                                    ),
                                    vulnerability=one_search_result
                                )
                                # Push into collection
                                try:
                                    queue.rpush(
                                        new_collection_name,
                                        serialize_as_json__for_cache(
                                            new_content
                                        )
                                    )
                                except Exception as ex:
                                    pass
                            except Exception as ex:
                                pass
                    try:
                        # Delete search request
                        queue.delete(
                            one_key
                        )
                    except Exception as ex:
                        pass
                    pass
                # Publish message to channel for search complete
                complete_message = SETTINGS["queue"]["complete_message"] + id_of_request
                queue.publish(
                    channel=channel_to_subscribe_and_publish,
                    message=complete_message
                )
                # print('TimeDelta: {}'.format(time.time() - start_time))
                pass
            else:
                # Unprocessing message
                pass
            # print(data)
        pass
    pass


def main():
    # print('Searcher started...')
    # run()
    print_list(fast_search_for_one_vulner_in_json__list_of_items_in_json(
        {"project_id": "5aed6441ba733d37419d5565",
         "organization_id":"5ae05fde9531a003aacdacf8",
         "set_id":"5aed6441ba733d37419d5564",
         "component":{
              "name":"junos","version":"14.1"}}
    ))


if __name__ == '__main__':
    sys.exit(main())
