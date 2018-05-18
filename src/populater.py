from utils import *
from caches import queue
from database import *
from models import vulnerabilities
from searcher import reformat_vulner_for_output


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
        data = message.get("data", {})
        if data == 1:
            pass
        else:
            if isinstance(data, bytes):
                data = data.decode("utf-8")
            elif isinstance(data, dict):
                pass
            if message_to_get_vulnerability in data:
                id_of_request = data[len(message_to_get_vulnerability) + 10:]
                uniq_id = data[len(message_to_get_vulnerability) + 1 :len(message_to_get_vulnerability) + 9]
                # print('uniq', uniq_id)
                # print('id_of_request', id_of_request)
                try:
                    int(id_of_request)
                except ValueError:
                    search_options = json.loads(id_of_request)
                    new_collection_name = SETTINGS["queue"]["complete_get_vulnerability"] + uniq_id + ':' + search_options['name'] + ':' + search_options['version']

                    search_options['name'] = 'junos'
                    search_options['version'] = '*'

                    connect_database()
                    if search_options['version'] == '*':
                        count = vulnerabilities.select().where(
                                vulnerabilities.component == search_options['name']
                            ).count()
                        vulnerability = list(
                            vulnerabilities.select().where(
                                    (vulnerabilities.component == search_options['name']) &
                                    (vulnerabilities.cvss >= search_options['sort'])
                            ).offset(search_options['skip']).limit(search_options['limit']).order_by(vulnerabilities.cvss.desc())
                        )
                    else:
                        count = vulnerabilities.select().where(
                                (vulnerabilities.component == search_options['name']) &
                                (vulnerabilities.version == search_options['version'])
                            ).count()
                        vulnerability = list(
                            vulnerabilities.select().where(
                                (vulnerabilities.component == search_options['name']) &
                                (vulnerabilities.version == search_options['version']) &
                                (vulnerabilities.cvss >= search_options['sort'])
                            ).offset(search_options['skip']).limit(search_options['limit']).order_by(vulnerabilities.cvss.desc())
                        )
                    queue.rpush(
                        new_collection_name,
                        count
                    )
                    for i in vulnerability:
                        queue.rpush(
                            new_collection_name,
                            serialize_as_json__for_cache(reformat_vulner_for_output(i.to_json))
                        )
                    disconnect_database()
                    queue.publish(
                        channel=channel_to_subscribe_and_publish,
                        message=new_collection_name
                    )
                except Exception as ex:
                    print(ex)
                else:
                    new_collection_name = SETTINGS["queue"]["complete_get_vulnerability"] + uniq_id + ':' + id_of_request
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
                            serialize_as_json__for_cache(reformat_vulner_for_output(vlist[0]))
                        )
                    else:
                        pass
                    disconnect_database()
                    # complete_message = SETTINGS["queue"]["complete_get_vulnerability"] + id_of_request
                    queue.publish(
                        channel=channel_to_subscribe_and_publish,
                        message=new_collection_name
                        # message=complete_message
                    )
            else:
                pass
    pass


def main():
    print('Populater started...')
    run()


if __name__ == '__main__':
    sys.exit(main())
