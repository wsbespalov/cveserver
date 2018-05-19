import re
from math import floor
from utils import *
from caches import cache, queue
from database import *
from models import vulnerabilities


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

def only_digits(var):
    """
    Get only digits from string
    :param var:
    :return:
    """
    if isinstance(var, str):
        return re.sub("\D", "", var)
    else:
        return ""

def reformat_vulner_for_output(item_to_reformat):
    """
    Reformat vulner for Response
    :param item_to_reformat:
    :return: reformatted item for response
    """
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
    cwe_in_item = item_to_reformat.get("cwe", [])
    cwe_list = deserialize_json__for_postgres(cwe_in_item)
    cwe_id_list = []
    for cwe_in_list in cwe_list:
        cwe_id_list.append(only_digits(cwe_in_list))
    title = item_to_reformat.get("cve_id", "")
    description = item_to_reformat.get("description", "")

    rank = floor(cvss)

    __v = 0

    capec_list = item_to_reformat.get("capec", [])
    capec = []  # not yet

    for capec_in_list in capec_list:
        if isinstance(capec_in_list, str):
            capec.append(json.loads(capec_in_list))
        elif isinstance(capec_in_list, dict):
            capec.append(capec_in_list)

    vulnerable_configurations = []

    vulnerable_configuration = item_to_reformat.get("vulnerable_configuration", [])

    cve_references = item_to_reformat.get("references", [])

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

def fast_search_for_one_vulner_in_json(item_to_search):
    """
    Search one Item by component and version from JSON request in Postgres and in Cache
    :param item_to_search:
    :return: reformatted item for response
    """
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
    # Filter results if needs to output only one
    # For ex.: junos:14.1:rc1, junos:14.1:rc2, junos:14.1:rc3, ... -> junos:14.1:rc1

    filtered_items = []

    if SETTINGS["search"]["output_only_one"]:
        if len(ready_items) > 1:
            filtered_items.append(ready_items[0])
            for i in range(1, len(ready_items)):
                for x in range(i + 1, len(ready_items)):
                    if ready_items[i]["component"] == ready_items[x]["component"] and \
                        ready_items[i]["version"] == ready_items[x]["version"] and \
                            ready_items[i]["cve_id"] == ready_items[x]["cve_id"]:
                        pass
                    else:
                        filtered_items.append(ready_items[i])
        elif len(ready_items) == 1:
            filtered_items = ready_items
        else:
            pass
        pass
    else:
        filtered_items = ready_items

    print('Foud items:')
    print_list(ready_items)
    print('Found without duplicates')
    print_list(filtered_items)

    # Reformat items
    reformatted_items = []
    for item in filtered_items:
        reformatted_items.append(
            reformat_vulner_for_output(
                item
            )
        )
    return reformatted_items

def scan_queue_for_keys() -> list:
    """
    Scan queue for keys by mask
    :return: list of keys
    """
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

        if data != 1:
            if isinstance(data, bytes):
                data = data.decode("utf-8")
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
                        else:
                            continue
                        search_result = fast_search_for_one_vulner_in_json(
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
                                    print('Exception while push: {}'.format(ex))
                            except Exception as ex:
                                print('Exception while handling one search result: {}'.format(ex))
                    try:
                        # Publish message to channel for search complete
                        complete_message = SETTINGS["queue"]["complete_message"] + id_of_request
                        queue.publish(
                            channel=channel_to_subscribe_and_publish,
                            message=complete_message
                        )

                        # Delete search request
                        queue.delete(
                            one_key
                        )
                    except Exception as ex:
                        pass

def main():
    print('Searcher started...')
    run()


if __name__ == '__main__':
    sys.exit(main())
