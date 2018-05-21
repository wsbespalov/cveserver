import re
from math import floor
from utils import *
from caches import cache, queue
from database import *
from models import vulnerabilities

from settings import SETTINGS


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
        cwe_id_list.append(re.sub("\D", "", cwe_in_list))
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


class Searcher(object):

    def __init__(self):
        self.key_expire_time_in_sec = SETTINGS["cache"]["key_expire_time_in_sec"]
        self.cache_index = SETTINGS["cache"]["index"]
        self.cache_separator = SETTINGS["cache"]["separator"]
        self.prefix_requests = SETTINGS["queue"]["prefix_requests"]

    @staticmethod
    def find_vulners_in_postgres_by_component_and_version(component, version):
        """
        Find list of vulners in vulnerabilities table in Postgres by component and version
        :param component:
        :param version:
        :return: list of json items
        """
        items = []
        connect_database()
        if "*" in version:
            version = version[:version.index("*")]
            list_of_elements = list(vulnerabilities.select().where(
                    (vulnerabilities.component == component) &
                    (vulnerabilities.version.startswith(version))))
        else:
            list_of_elements = list(
                vulnerabilities.select().where(
                    (vulnerabilities.component == component) &
                    (vulnerabilities.version == version)))
        for element in list_of_elements:
            items.append(element.to_json)
        disconnect_database()
        return items

    def create_collection_name_by_component_and_version(self, component, version):
        """
        Create collection name for cache search
        :param component:
        :param version:
        :return: collection name
        """
        if version is None or version == "":
            version = "*"
        return "".join([self.cache_index, self.cache_separator, component, self.cache_separator, str(version)])

    def check_if_item_is_already_cached_in_redis(self, component, version):
        """
        Check if item already exists in cache by component and version
        :param component:
        :param version:
        :return: list of json items
        """
        list_of_components = []
        collection_name = self.create_collection_name_by_component_and_version(
            component=component,
            version=version)
        try:
            elements_in_cache = cache.lrange(collection_name, 0, -1)
        except:
            elements_in_cache = []
        for element in elements_in_cache:
            list_of_components.append(deserialize_as_json__for_cache(element))
        return list_of_components

    def put_items_into_redis_cache(self, items_to_cache):
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
                collection_name = self.create_collection_name_by_component_and_version(
                    component=component,
                    version=version)
                try:
                    cache.rpush(collection_name, serialize_as_json__for_cache(element=element))
                    cache.expire(collection_name, self.key_expire_time_in_sec)
                    count += 1
                except Exception as ex:
                    print("{}".format(ex))
        return count

    @staticmethod
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

    def fast_search_for_one_vulner_in_json(self, item_to_search):
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
                    items_in_redis = self.check_if_item_is_already_cached_in_redis(component, version)
                    if len(items_in_redis) > 0:
                        # If item in redis - get data from redis
                        ready_items = ready_items + items_in_redis
                    else:
                        # If item not in redis - get data from postgres
                        items_in_postgres = self.find_vulners_in_postgres_by_component_and_version(
                            component=component,
                            version=version
                        )
                        # And put it into cache
                        self.put_items_into_redis_cache(items_in_postgres)
                        # Append result
                        ready_items = ready_items + items_in_postgres

        # Reformat items
        reformatted_items = []
        for item in ready_items:
            reformatted_items.append(reformat_vulner_for_output(item))
        return reformatted_items

    def scan_queue_for_keys__list(self):
        """
        Scan queue for keys by mask
        :return: list of keys
        """
        mykeys = []
        mask = self.prefix_requests + "*"
        try:
            mykeys = queue.keys(mask)
        except Exception as ex:
            print("{}".format(ex))
        return mykeys


    def run(self):
        self.queue_settings = SETTINGS.get("queue", {})
        channel_to_subscribe_and_publish = self.queue_settings.get("channel", "start_processing")
        message_to_start_search = self.queue_settings.get("message_to_start_search", "start_search")
        message_to_kill_search = self.queue_settings.get("message_to_kill_search", "message_to_kill_search")

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
                    mykeys = self.scan_queue_for_keys__list()

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
                        except Exception:
                            collection_content = []
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
                            search_result = self.fast_search_for_one_vulner_in_json(
                                content_for_search
                            )
                            for one_search_result in search_result:
                                # Append results into structure
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
                        except Exception:
                            pass


def main():
    print('Searcher started...')
    searcher = Searcher()
    searcher.run()


if __name__ == '__main__':
    sys.exit(main())
