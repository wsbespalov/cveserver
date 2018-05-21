import os
import re
import json
from datetime import datetime
from settings import SETTINGS

class InMemoryStorage(object):

    cache = {}

    @property
    def size(self) -> int:
        return len(self.cache)

    @property
    def stats(self):
        elements = 0
        keys = self.cache.keys()
        for key in keys:
            elements += len(self.cache[key])
        return elements

    def __contains__(self, item: str) -> bool:
        return item in self.cache

    def get(self, key: str) -> list:
        if self.__contains__(key):
            return self.cache[key]
        return []

    def set(self, key: str, item: list):
        self.cache[key] = item

    def append_by_key(self, key: str, item: dict) -> int:
        key_content = []
        if self.__contains__(key):
            key_content = self.get(key=key)
            key_content.append(item)
        self.set(key=key, item=key_content)
        return len(key_content)

    def append_item(self, item: dict) -> int:
        component = item["component"]
        version = item["version"]
        key = self.create_key(component=component, version=version)
        key_content = []
        duplicate = False
        if self.__contains__(key):
            key_content = self.get(key=key)
            # Filter for vulner duplicates
            for one_element in key_content:
                if item["component"] == one_element["component"] and \
                    item["version"] == one_element["version"] and \
                        item["cve_id"] == one_element["cve_id"]:
                    duplicate = True
                    break
        if not duplicate:
            key_content.append(item)
        self.set(key=key, item=key_content)
        return len(key_content)

    @staticmethod
    def create_key(component: str, version: str) -> str:
        return "".join([
            SETTINGS["memcached"]["key_prefix"],
            component,
            SETTINGS["memcached"]["separator"],
            version
        ])

    def dump_cache_into_json_file__with_ts(self):
        current_directory = os.path.dirname(os.path.abspath(__file__))
        ts = datetime.utcnow()
        full_directory_path = "".join([
            current_directory,
            SETTINGS["memcached"]["dump_directory"],
            "/"
        ])
        if os.path.isdir(full_directory_path):
            pass
        else:
            os.mkdir(full_directory_path)
        full_path = "".join([
            current_directory,
            SETTINGS["memcached"]["dump_directory"],
            "/",
            SETTINGS["memcached"]["dump_file_name_base"],
            "-",
            str(ts),
            ".",
            SETTINGS["memcached"]["dump_file_extension"]
        ])
        try:
            with open(full_path, "w") as objfile:
                json.dump(self.cache, objfile, ensure_ascii=False)
                return full_path
        except Exception as ex:
            print("Get an exception when make cache dump: {}".format(
                ex
            ))
        return None

    def restore_from_dump__with_full_path(self, full_path):
        if os.path.exists(full_path):
            try:
                with open(full_path, 'r') as objfile:
                    self.cache = json.load(objfile)
            except Exception as ex:
                print("Get an exception while restore dump: {}".format(
                    ex
                ))
        else:
            print("File does not exists")
        pass