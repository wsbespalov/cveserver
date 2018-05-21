import re
import sys
import json
from caches import queue
from utils import serialize_as_json__for_cache
from database import *
from models import VULNERABILITIES
from searcher import reformat_vulner_for_output

from settings import SETTINGS


class Populater(object):

    def __init__(self):
        self.queue_settings = SETTINGS.get("queue", {})
        self.channel_to_subscribe_and_publish = self.queue_settings.get("vulnerability_channel", "vulnerabilityServiceChannel")
        self.message_to_get_vulnerability = self.queue_settings.get("message_to_get_vulnerability", "getVulnerability")
        self.complete_get_vulnerability = self.queue_settings.get("complete_get_vulnerability", "result::")

    def run(self):
        subscriber = queue.pubsub()
        subscriber.subscribe([self.channel_to_subscribe_and_publish])

        for message in subscriber.listen():
            data = message.get("data", {})
            if data == 1:
                pass
            else:
                if isinstance(data, bytes):
                    data = data.decode("utf-8")
                if self.message_to_get_vulnerability in data:
                    id_of_request = data[len(self.message_to_get_vulnerability) + 10:]
                    uniq_id = data[len(self.message_to_get_vulnerability) + 1:len(self.message_to_get_vulnerability) + 9]
                    try:
                        int(id_of_request)
                    except ValueError:
                        search_options = json.loads(id_of_request)
                        new_collection_name = self.complete_get_vulnerability + uniq_id + ':' + search_options['name'] + ':' + search_options['version']

                        connect_database()

                        if search_options['version'] == '*':
                            count = VULNERABILITIES.select().where(
                                VULNERABILITIES.component == search_options['name']
                                ).count()
                            vulnerability = list(
                                VULNERABILITIES.select().where(
                                    (VULNERABILITIES.component == search_options['name']) &
                                    (VULNERABILITIES.cvss >= search_options['sort'])
                                ).offset(search_options['skip']).limit(search_options['limit']).order_by(VULNERABILITIES.cvss.desc())
                            )
                        else:
                            count = VULNERABILITIES.select().where(
                                (VULNERABILITIES.component == search_options['name']) &
                                (VULNERABILITIES.version == search_options['version'])
                                ).count()
                            vulnerability = list(
                                VULNERABILITIES.select().where(
                                    (VULNERABILITIES.component == search_options['name']) &
                                    (VULNERABILITIES.version == search_options['version']) &
                                    (VULNERABILITIES.cvss >= search_options['sort'])
                                ).offset(search_options['skip']).limit(search_options['limit']).order_by(VULNERABILITIES.cvss.desc())
                            )

                        queue.rpush(
                            new_collection_name,
                            count)

                        for i in vulnerability:
                            queue.rpush(
                                new_collection_name,
                                serialize_as_json__for_cache(reformat_vulner_for_output(i.to_json)))

                        disconnect_database()

                        queue.publish(
                            channel=self.channel_to_subscribe_and_publish,
                            message=new_collection_name)

                    except Exception as ex:
                        if SETTINGS.get("debug", False):
                            print(ex)
                    else:
                        new_collection_name = self.complete_get_vulnerability + uniq_id + ':' + id_of_request
                        connect_database()
                        vulnerability = list(
                            VULNERABILITIES.select().where(
                                VULNERABILITIES.id == id_of_request)
                        )

                        vlist = []

                        for i in vulnerability:
                            vlist.append(i.to_json)

                        if len(vlist) == 1:
                            queue.rpush(
                                new_collection_name,
                                serialize_as_json__for_cache(reformat_vulner_for_output(vlist[0])))

                        disconnect_database()

                        queue.publish(
                            channel=self.channel_to_subscribe_and_publish,
                            message=new_collection_name)


def main():
    print('Populater started...')
    populater = Populater()
    populater.run()


if __name__ == '__main__':
    sys.exit(main())
