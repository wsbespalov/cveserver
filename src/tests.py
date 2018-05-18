import redis
import json
import time

from caches import *
from settings import SETTINGS

channel_to_subscribe = SETTINGS["queue"]["channel"]

def publish_message_to_queue(message):
    queue.publish(channel=channel_to_subscribe, message=message)

message_1 = {
    "project_id": "5aed6441ba733d37419d5565",
    "organization_id": "5ae05fde9531a003aacdacf8",
    "set_id": "5aed6441ba733d37419d5564",
    "component": {
        "name": "junos",
        "version": "14.1"}
}

message_2 = {
    "project_id": "5a4494fc9ce7126433f002c0",
    "organization_id": "5ae05fde9531a003aacdacf8",
    "set_id": "5aed6441ba733d37419d5564",
    "component": {
        "name": "junos",
        "version": "14.*"}
}

message_3 = {
    "project_id": "5a4494fc9ce7126433f002d4",
    "organization_id": "5ae05fde9531a003aacdacf8",
    "set_id": "5aed6441ba733d37419d5564",
    "component": {
        "name": "junos_space",
        "version": "*"}
}

publish_message_to_queue('start_search')

queue.rpush(
    "search::5aed6441ba733d37419d5565",
    message_1
)
time.sleep(5)

# publish_message_to_queue('start_search')
#
# queue.rpush(
#     "search::5a4494fc9ce7126433f002c0",
#     message_2
# )
# publish_message_to_queue('start_search')
#
# queue.rpush(
#     "search::5a4494fc9ce7126433f002d4",
#     message_3
# )
publish_message_to_queue("message_to_kill_search")
