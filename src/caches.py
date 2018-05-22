import redis
from settings import SETTINGS

cache = redis.StrictRedis(
    host=SETTINGS["cache"]["host"],
    port=SETTINGS["cache"]["port"],
    db=SETTINGS["cache"]["db"]
)

queue = redis.StrictRedis(
    host=SETTINGS["queue"]["host"],
    port=SETTINGS["queue"]["port"],
    db=SETTINGS["queue"]["db"]
)


def drop_cache():
    try:
        cache.flushall()
    except Exception as ex:
        print('Get an exception while flushing cache in Redis: {}'.format(ex))
