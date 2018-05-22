import re
import time
from math import floor
from utils import *
from caches import cache, queue
from database import *
from models import VULNERABILITIES

from settings import SETTINGS
from utils import reformat_vulner_for_output

class Searcher(object):

    def __init__(self):
        self.queue_settings = SETTINGS.get("queue", {})
        self.cache_settings = SETTINGS.get("cache", {})

        self.key_expire_time_in_sec = self.cache_settings.get("key_expire_time_in_sec", 30)
        self.cache_index = self.cache_settings.get("index", "index")
        self.cache_separator = self.cache_settings.get("separator", "::")
        self.prefix_requests = self.queue_settings.get("prefix_requests", "search::")
        self.prefix_results = self.queue_settings.get("prefix_results", "create::")
        self.complete_message = self.queue_settings.get("complete_message", "create::")

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
            list_of_elements = list(VULNERABILITIES.select().where(
                (VULNERABILITIES.component == component) &
                (VULNERABILITIES.version.startswith(version))))
        else:
            list_of_elements = list(
                VULNERABILITIES.select().where(
                    (VULNERABILITIES.component == component) &
                    (VULNERABILITIES.version == version)))
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
                    start_time = time.time()
                    print('[+] Get message to start search')
                    # Message to search
                    # start_time = time.time()
                    mask = self.prefix_requests # SETTINGS["queue"]["prefix_requests"]
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
                        new_collection_name = self.prefix_results + id_of_request
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
                            print('[+] Process component: name = {}, version = {}'
                                  .format(content_for_search["component"]["name"],
                                          content_for_search["component"]["version"]))
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
                            complete_message = self.complete_message + id_of_request
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
                    print('[+] Complete search in {} sec.'.format(time.time() - start_time))

def main():
    print('Searcher started...')
    searcher = Searcher()
    searcher.run()


if __name__ == '__main__':
    sys.exit(main())
