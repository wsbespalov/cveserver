import redis
import json
import time

from caches import *
from settings import SETTINGS

channel_to_subscribe = SETTINGS["queue"]["channel"]

def publish_message_to_queue(message):
    queue.publish(channel=channel_to_subscribe, message=message)

message = {
    "project_id": "5aed6441ba733d37419d5565",
    "organization_id": "5ae05fde9531a003aacdacf8",
    "set_id": "5aed6441ba733d37419d5564",
    "component": {
        "name": "junos",
        "version": "14.1"}
}

publish_message_to_queue(message)

queue.rpush(
    "search::5aed6441ba733d37419d5565",
    message
)
time.sleep(5)

publish_message_to_queue(message)

queue.rpush(
    "search::5aed6441ba733d37419d5565",
    message
)
publish_message_to_queue(message)

queue.rpush(
    "search::5aed6441ba733d37419d5565",
    message
)
publish_message_to_queue("DIE")