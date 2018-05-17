import re
from math import floor
from utils import *
from caches import cache, queue
from database import *
from models import vulnerabilities
from searcher import reformat_vulner_for_output__json

def scan_queue_for_keys():
    mask = SETTINGS["queue"]["prefix_get"] + "*"
    mykeys = []
    try:
        mykeys = queue.keys(mask)
    except Exception as ex:
        print("{}".format(ex))
    return mykeys

def run():
    channel_to_subscribe_and_publish = SETTINGS["queue"]["vulnerability_channel"]
    message_to_get_vulnerability = SETTINGS["queue"]["message_to_get_vulnerability"]
    
    subscriber = queue.pubsub()
    subscriber.subscribe([channel_to_subscribe_and_publish])

    for message in subscriber.listen():
        data = message.get("data", {});
        if data == 1:
            pass
        else:
            if isinstance(data, bytes):
                data = data.decode("utf-8")
            elif isinstance(data, dict):
                pass
            if message_to_get_vulnerability in data:
                id_of_request = data[len(message_to_get_vulnerability) + 1:]
                new_collection_name = SETTINGS["queue"]["complete_get_vulnerability"] + id_of_request
                connect_database()
                vulnerability = list(
                    vulnerabilities.select().where(
                        vulnerabilities.id == id_of_request
                    )
                )
                vlist = []
                for i in vulnerability:
                    vlist.append(i.to_json)
                if len(vlist) == 1:
                    queue.rpush(
                        new_collection_name,
                        serialize_as_json__for_cache(reformat_vulner_for_output__json(vlist[0]))
                    )
                else:
                    pass
                disconnect_database()
                complete_message = SETTINGS["queue"]["complete_get_vulnerability"] + id_of_request
                queue.publish(
                    channel=channel_to_subscribe_and_publish,
                    message=complete_message
                )
            else:
                pass
    pass


def main():
    print('Searcher started...')
    # keys = queue.keys("result::*")
    # for key in keys:
    #     queue.delete(key)
    run()


if __name__ == '__main__':
    sys.exit(main())