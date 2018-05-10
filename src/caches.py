import redis
from settings import SETTINGS

cache = redis.StrictRedis(
    host=SETTINGS["cache"]["host"],
    port=SETTINGS["cache"]["port"],
    db=SETTINGS["cache"]["db"]
)
