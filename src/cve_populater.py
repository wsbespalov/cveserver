import re
import os
import string
import time
import urllib
import json
import cpe as cpe_module

from datetime import datetime

from models import CAPEC, vulnerabilities
from utils import progressbar
from upd_vulners import download_cve_file, parse_cve_file
from database import database

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
        if self.__contains__(key):
            key_content = self.get(key=key)
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


class CVEUpdaterDownloader(object):

    def __init__(self):
        self.cache = InMemoryStorage()

    @staticmethod
    def filter_cpe_string__json(element):
        result = {"component": None, "version": None}
        try:
            c22 = cpe_module.CPE(element, cpe_module.CPE.VERSION_2_2)
        except ValueError:
            try:
                c22 = cpe_module.CPE(element, cpe_module.CPE.VERSION_2_3)
            except ValueError:
                try:
                    c22 = cpe_module.CPE(element, cpe_module.CPE.VERSION_UNDEFINED)
                except NotImplementedError:
                    c22 = None
        c22_product = c22.get_product() if c22 is not None else []
        c22_version = c22.get_version() if c22 is not None else []
        result["component"] = c22_product[0] if isinstance(c22_product, list) and len(c22_product) > 0 else None
        result["version"] = c22_version[0] if isinstance(c22_version, list) and len(c22_version) > 0 else None
        return result

    def filter_items_to_update(self, items_fo_filter, unquote=True, only_digits_and_dot_in_version=True):
        filtered_items = []
        # for item in items_fo_filter:
        for item in progressbar(items_fo_filter, prefix='Filtering  '):
            # For every item in downloaded update
            # Get cpe strings
            list_of_cpe_strings = item.get("vulnerable_configuration", [])
            # If list not empty
            if len(list_of_cpe_strings) > 0:
                # For every cpe string
                for one_cpe_string in list_of_cpe_strings:
                    # Get one string and check it
                    filtered_cpe_string = self.filter_cpe_string__json(one_cpe_string)
                    version = filtered_cpe_string.get("version", "")
                    component = filtered_cpe_string.get("component", "")
                    if version is not None and not str(version).__eq__("") and component is not None and not str(
                            component).__eq__(""):
                    # Copy item into filtered items
                        new_item = item.copy()
                        new_item["component"] = filtered_cpe_string["component"]
                        new_item["version"] = filtered_cpe_string["version"]
                        if unquote:
                            try:
                                new_item["version"] = urllib.parse.unquote(new_item["version"])
                            except Exception:
                                pass
                        if only_digits_and_dot_in_version:
                            allow = string.digits + '.' + '(' + ')'
                            new_item["version"] = re.sub('[^%s]' % allow, '', new_item["version"])
                        new_item["vulnerable_configuration"] = list_of_cpe_strings
                        new_item["cpe"] = one_cpe_string
                        filtered_items.append(new_item)
                        del new_item
        return filtered_items

    def update_vulnerabilities_table_in_memory__counts(self, items_to_update):
        # Populate CVEs Items In Memory
        for item in progressbar(items_to_update):
            self.cache.append_item(item)
        print('Append {} keys.'.format(self.cache.size))

    def create_record_in_vulnerabilities_table(self, item_to_create):
        cwe_list = item_to_create.get("cwe", [])
        capec_list = []

        for cwe in cwe_list:
            capec = list(CAPEC.select().where(
                (CAPEC.related_weakness.contains(
                    cwe
                ))
            ))
            for capec_element in capec:
                capec_list.append(json.dumps(
                    dict(
                        id=re.sub("\D", "", str(capec_element.capec_id)),
                        name=capec_element.name,
                        summary=capec_element.summary,
                        prerequisites=capec_element.prerequisites,
                        solutions=capec_element.solutions,
                        related_weakness=capec_element.related_weakness
                    )
                ))

        vulner = vulnerabilities(
            component=item_to_create.get("component", ""),
            version=item_to_create.get("version", ""),
            data_type=item_to_create.get("data_type", ""),
            data_format=item_to_create.get("data_format", ""),
            data_version=item_to_create.get("data_version", ""),
            cve_id=item_to_create.get("cve_id", ""),
            cwe=item_to_create.get("cwe", []),
            references=item_to_create.get("references", []),
            description=item_to_create.get("description", ""),
            cpe=item_to_create.get("cpe", ""),
            vulnerable_configuration=item_to_create.get("vulnerable_configuration", '{"data": []}'),
            published=item_to_create.get("published", str(datetime.utcnow())),
            modified=item_to_create.get("modified", str(datetime.utcnow())),
            access=item_to_create.get("access", '{}'),
            impact=item_to_create.get("impact", '{}'),
            vector_string=item_to_create.get("vector_string", ""),
            cvss_time=item_to_create.get("cvss_time", str(datetime.utcnow())),
            cvss=item_to_create.get("cvss", 0.0),
            capec=capec_list
        )
        vulner.save()
        return vulner.id

    def update_vulnerabilities_table_in_postgres(self):
        database.connect()
        keys = self.cache.cache.keys()

        for key in progressbar(keys):
            items = self.cache.get(key)
            for item in items:
                self.create_record_in_vulnerabilities_table(item)

        database.close()
        pass

    def populate(self):
        start_time = time.time()
        start_year = SETTINGS.get("start_year", 2002)
        current_year = datetime.now().year
        count_of_parsed_cve_items = 0
        count_of_populated_items = 0
        for year in range(start_year, current_year + 1):
            print("Populate CVE-{}".format(year))
            source = SETTINGS["sources"]["cve_base"] + str(year) + SETTINGS["sources"]["cve_base_postfix"]
            cve_item, cve_data_timestamp, response = download_cve_file(source)
            parsed_cve_items = parse_cve_file(cve_item, cve_data_timestamp)
            items_to_populate = self.filter_items_to_update(parsed_cve_items)
            self.update_vulnerabilities_table_in_memory__counts(items_to_populate)
            count_of_parsed_cve_items += len(parsed_cve_items)
            count_of_populated_items += len(items_to_populate)
        self.update_vulnerabilities_table_in_postgres()
        return count_of_parsed_cve_items, count_of_populated_items, time.time() - start_time
    pass
