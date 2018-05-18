import re
import os
import string
import time
import peewee
import urllib
import urllib.request as req
import zipfile
from io import BytesIO
import gzip
import bz2
import sys
import json
import cpe as cpe_module
from functools import lru_cache
from dateutil.parser import parse as parse_datetime
from datetime import datetime

from models import CAPEC

from playhouse.postgres_ext import ArrayField

SETTINGS = {
    "sources": {
        "cve_modified": "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.gz",
        "cve_recent": "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-recent.json.gz",
        "cve_base": "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-",
        "cve_base_postfix": ".json.gz",
        "cpe22": "https://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.2.xml.zip",
        "cpe23": "https://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip",
        "cwe": "http://cwe.mitre.org/data/xml/cwec_v2.8.xml.zip",
        "capec": "http://capec.mitre.org/data/xml/capec_v2.6.xml",
        "ms": "http://download.microsoft.com/download/6/7/3/673E4349-1CA5-40B9-8879-095C72D5B49D/BulletinSearch.xlsx",
        "d2sec": "http://www.d2sec.com/exploits/elliot.xml",
        "npm": "https://api.nodesecurity.io/advisories",
    },
    "start_year": 2018,
    "memcached": {
        "key_prefix": "index",
        "separator": "::",
        "drop_cache_before": True,
        "dump_directory": "/tmp",
        "dump_file_name_base": "dump",
        "dump_file_extension": "json"
    },
    "postgres": {
        "user": 'admin',
        "password": '123',
        "database": "updater_db",
        "host": "localhost",
        "port": "5432",
        "drop_before": False,
        "cache_size_mb": 64
    },
}

POSTGRES = SETTINGS.get("postgres", {})
database = peewee.PostgresqlDatabase(
    database=POSTGRES.get("database", "updater_db"),
    user=POSTGRES.get("user", "postgres"),
    password=POSTGRES.get("password", "password"),
    host=POSTGRES.get("host", "localhost"),
    port=int(POSTGRES.get("port", 5432))
)

class vulnerabilities_inmemory(peewee.Model):
    class Meta:
        database = database
        ordering = ("component", )
        table_name = "vulnerabilities"

    id = peewee.PrimaryKeyField(null=False,)
    component = peewee.TextField(default="",)
    version = peewee.TextField(default="",)
    data_type = peewee.TextField(default="",)
    data_format = peewee.TextField(default="",)
    data_version = peewee.TextField(default="",)
    cwe = ArrayField(
        peewee.TextField,
        default=[],
        verbose_name='cwe'
    )
    cve_id = peewee.TextField(default="",)
    references = ArrayField(
        peewee.TextField,
        default=[],
        verbose_name='references'
    )
    description = peewee.TextField(default="",)
    cpe = peewee.TextField(default="",)
    vulnerable_configuration = ArrayField(
        peewee.TextField,
        default=[],
        verbose_name='vulnerable_configuration'
    )
    published = peewee.DateTimeField(default=datetime.now,)
    modified = peewee.DateTimeField(default=datetime.now,)

    access = peewee.TextField(default='{"vector": "", "complexity": "", "authentication": ""}',)
    impact = peewee.TextField(default='{"confidentiality": "", "integrity": "", "availability": ""}',)

    vector_string = peewee.TextField(default="",)

    cvss_time = peewee.DateTimeField(default=datetime.now,)

    cvss = peewee.FloatField(default=0.0,)

    capec = ArrayField(
        peewee.TextField,
        default=[],
        verbose_name='capec'
    )

    def __unicode__(self):
        return "vulnerabilities"

    def __str__(self):
        return self.cve_id

    @property
    def to_json(self):
        return dict(
            id=self.id,
            component=self.component,
            version=self.version,
            data_type=self.data_type,
            data_format=self.data_format,
            data_version=self.data_version,
            cve_id=self.cve_id,
            cwe=self.cwe,
            references=self.references,
            description=self.description,
            cpe=self.cpe,
            vulnerable_configuration=self.vulnerable_configuration,
            published=self.published,
            modified=self.modified,
            access=self.access,
            impact=self.impact,
            vector_string=self.vector_string,
            cvss_time=self.cvss_time,
            cvss=self.cvss,
            capec=self.capec
        )

def progressbar(it, prefix="Processing ", size=50):
    count = len(it)

    def _show(_i):
        if count != 0 and sys.stdout.isatty():
            x = int(size * _i / count)
            sys.stdout.write("%s[%s%s] %i/%i\r" % (prefix, "#" * x, " " * (size - x), _i, count))
            sys.stdout.flush()

    _show(0)
    for i, item in enumerate(it):
        yield item
        _show(i + 1)
    sys.stdout.write("\n")
    sys.stdout.flush()

class CVEItem(object):
    def __init__(self, data):
        cve = data.get("cve", {})
        # Get Data Type -> str
        self.data_type = cve.get("data_type", None)
        # Get Data Format -> str
        self.data_format = cve.get("data_format", None)
        # Get Data Version -> str
        self.data_version = cve.get("data_version", None)  # Data version like 4.0
        # Get CVE ID like CVE-2002-2446 -> str
        CVE_data_meta = cve.get("CVE_data_meta", {})
        self.cve_id = CVE_data_meta.get("ID", None)
        # GET CWEs -> JSON with list -> {"data": cwe}
        cwe = []
        problemtype = cve.get("problemtype", {})
        problemtype_data = problemtype.get("problemtype_data", [])
        for pd in problemtype_data:
            description = pd.get("description", [])
            for d in description:
                value = d.get("value", None)
                if value is not None:
                    cwe.append(value)
        self.cwe = {"data": cwe}
        # GET RREFERENCES -> JSON with list -> {"data": references}
        references = []
        ref = cve.get("references", {})
        reference_data = ref.get("reference_data", [])
        for rd in reference_data:
            url = rd.get("url", None)
            if url is not None:
                references.append(url)
        self.references = {"data": references}
        # GET DESCRIPTION -> str
        self.description = ""
        descr = cve.get("description", {})
        description_data = descr.get("description_data", [])
        for dd in description_data:
            value = dd.get("value", "")
            self.description = self.description + value
        # GET cpe -> JSON with list -> {"data": cpe22}
        cpe22 = []
        conf = data.get("configurations", {})
        nodes = conf.get("nodes", [])
        for n in nodes:
            cpe = n.get("cpe", [])
            for c in cpe:
                c22 = c.get("cpe22Uri", None)
                cpe22.append(c22)
        self.vulnerable_configuration = {"data": cpe22}
        self.cpe = ""
        self.published = data.get("publishedDate", datetime.utcnow())
        self.modified = data.get("lastModifiedDate", datetime.utcnow())

        # access
        impact = data.get("impact", {})

        self.access = {}
        baseMetricV2 = impact.get("baseMetricV2", {})
        cvssV2 = baseMetricV2.get("cvssV2", {})
        self.access["vector"] = cvssV2.get("accessVector", "")
        self.access["complexity"] = cvssV2.get("accessComplexity", "")
        self.access["authentication"] = cvssV2.get("authentication", "")

        # impact
        self.impact = {}
        self.impact["confidentiality"] = cvssV2.get("confidentialityImpact", "")
        self.impact["integrity"] = cvssV2.get("integrityImpact", "")
        self.impact["availability"] = cvssV2.get("availabilityImpact", "")

        # vector_string
        self.vector_string = cvssV2.get("vectorString", "")

        # baseScore - cvss
        self.cvss = cvssV2.get("baseScore", "")

        # Additional fields
        self.component = ""
        self.version = ""

    def to_json(self):
        return json.dumps(self,
                          default=lambda o: o.__dict__,
                          sort_keys=True)


class Utils(object):
    def unify_time(self, dt):
        if isinstance(dt, str):
            if 'Z' in dt:
                dt = dt.replace('Z', '')
            return parse_datetime(dt)
        if isinstance(dt, datetime):
            return parse_datetime(str(dt))
    def get_file(self, getfile, unpack=True, raw=False, HTTP_PROXY=None):
        try:
            if HTTP_PROXY:
                proxy = req.ProxyHandler({'http': HTTP_PROXY, 'https': HTTP_PROXY})
                auth = req.HTTPBasicAuthHandler()
                opener = req.build_opener(proxy, auth, req.HTTPHandler)
                req.install_opener(opener)
            data = response = req.urlopen(getfile)
            if raw:
                return data
            if unpack:
                if 'gzip' in response.info().get('Content-Type'):
                    buf = BytesIO(response.read())
                    data = gzip.GzipFile(fileobj=buf)
                elif 'bzip2' in response.info().get('Content-Type'):
                    data = BytesIO(bz2.decompress(response.read()))
                elif 'zip' in response.info().get('Content-Type'):
                    fzip = zipfile.ZipFile(BytesIO(response.read()), 'r')
                    length_of_namelist = len(fzip.namelist())
                    if length_of_namelist > 0:
                        data = BytesIO(fzip.read(fzip.namelist()[0]))
            return data, response
        except Exception as ex:
            return None, str(ex)
    def download_cve_file(self, source):
        file_stream, response_info = self.get_file(source)
        try:
            result = json.load(file_stream)
            if "CVE_Items" in result:
                CVE_data_timestamp = result.get("CVE_data_timestamp", self.unify_time(dt=datetime.utcnow()))
                return result["CVE_Items"], CVE_data_timestamp, response_info
            return None
        except json.JSONDecodeError as json_error:
            print('Get an JSON decode error: {}'.format(json_error))
            return None
    def parse_cve_file(self, items=None, CVE_data_timestamp=None):
        if CVE_data_timestamp is None:
            CVE_data_timestamp = self.unify_time(dt=datetime.utcnow())
        if items is None:
            items = []
        parsed_items = []
        for item in items:
            element = json.loads(CVEItem(item).to_json())
            element["cvss_time"] = CVE_data_timestamp
            parsed_items.append(element)
        return parsed_items


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

    # @lru_cache(maxsize=None, typed=False)
    def get(self, key: str) -> list:
        if self.__contains__(key):
            return self.cache[key]
        return []

    # @lru_cache(maxsize=None, typed=False)
    def set(self, key: str, item: list):
        self.cache[key] = item

    # @lru_cache(maxsize=None, typed=False)
    def append_by_key(self, key: str, item: dict) -> int:
        key_content = []
        if self.__contains__(key):
            key_content = self.get(key=key)
            key_content.append(item)
        self.set(key=key, item=key_content)
        return len(key_content)

    # @lru_cache(maxsize=None, typed=False)
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

    def create_key(self, component: str, version: str) -> str:
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
        self.utils = Utils()

    def filter_cpe_string__json(self, element):
        result = {"component": None, "version": None}
        try:
            c22 = cpe_module.CPE(element, cpe_module.CPE.VERSION_2_2)
        except ValueError as value_error:
            try:
                c22 = cpe_module.CPE(element, cpe_module.CPE.VERSION_2_3)
            except ValueError as another_value_error:
                try:
                    c22 = cpe_module.CPE(element, cpe_module.CPE.VERSION_UNDEFINED)
                except NotImplementedError as not_implemented_error:
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
            list_of_cpe_strings_field = item.get("vulnerable_configuration", {})
            list_of_cpe_strings = list_of_cpe_strings_field.get("data", [])
            # If list not empty
            if len(list_of_cpe_strings) > 0:
                # For every cpe string
                for one_cpe_string in list_of_cpe_strings:
                    # Get one string and check it
                    filtered_cpe_string = self.filter_cpe_string__json(one_cpe_string)
                    version = filtered_cpe_string.get("version", "")
                    component = filtered_cpe_string.get("component", "")
                    if version is not None and not str(version).__eq__(""):
                        if component is not None and not str(component).__eq__(""):
                            # Copy item into filtered items
                            new_item = {}
                            new_item = item.copy()
                            new_item["component"] = filtered_cpe_string["component"]
                            new_item["version"] = filtered_cpe_string["version"]
                            if unquote:
                                try:
                                    new_item["version"] = urllib.parse.unquote(new_item["version"])
                                except:
                                    pass
                            if only_digits_and_dot_in_version:
                                allow = string.digits + '.' + '(' + ')'
                                new_item["version"] = re.sub('[^%s]' % allow, '', new_item["version"])
                            new_item["vulnerable_configuration"] = {"data": list_of_cpe_strings}
                            new_item["cpe"] = one_cpe_string
                            filtered_items.append(new_item)
                            del new_item
        return filtered_items

    def update_vulnerabilities_table_in_memory__counts(self, items_to_update):
        #
        # Populate CVEs Items In Memory
        #
        for item in progressbar(items_to_update):
            self.cache.append_item(item)
        print('Append {} keys.'.format(self.cache.size))

    def create_record_in_vulnerabilities_table(self, item_to_create):
        capec_list = []

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

        vulner = vulnerabilities_inmemory(
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
                _id = self.create_record_in_vulnerabilities_table(item)

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
            cve_item, CVE_data_timestamp, response = self.utils.download_cve_file(source)
            parsed_cve_items = self.utils.parse_cve_file(cve_item, CVE_data_timestamp)
            items_to_populate = self.filter_items_to_update(parsed_cve_items)
            self.update_vulnerabilities_table_in_memory__counts(items_to_populate)
            count_of_parsed_cve_items += len(parsed_cve_items)
            count_of_populated_items += len(items_to_populate)
        self.update_vulnerabilities_table_in_postgres()
        return count_of_parsed_cve_items, count_of_populated_items, time.time() - start_time
    pass
