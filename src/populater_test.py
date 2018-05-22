import time

from caches import *
from settings import SETTINGS

channel_to_subscribe = SETTINGS["queue"]["vulnerability_channel"]


def publish_message_to_queue(message):
    queue.publish(channel=channel_to_subscribe, message=message)


publish_message_to_queue('getVulnerability:12345678:52')


time.sleep(5)

publish_message_to_queue("message_to_kill_search")
