import re
from upd_cwe import action_update_cwe
from upd_capec import action_update_capec
from searcher import *
from database import drop_all_tables_in_postgres
from database import create_tables_in_postgres
import cpe as cpe_module
import urllib
import string
import time

from inmemorystorage import InMemoryStorage
from cveitem import CVEItem


class Updater(object):

    def __init__(self):
        self.cache = InMemoryStorage()
        self.start_year = SETTINGS.get("start_year", 2002)
        self.sources_settings = SETTINGS.get("sources", {})
        self.queue_settings = SETTINGS.get("queue", {})

        self.cve_base = self.sources_settings.get("cve_base", "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-")
        self.cve_base_postfix = self.sources_settings.get("cve_base_postfix", ".json.gz")
        self.channel_to_publish = self.queue_settings.get("channel", "start_processing")
        self.cve_modified = self.sources_settings.get("cve_modified", "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.gz")
        self.cve_recent = self.sources_settings.get("cve_recent", "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-recent.json.gz")
        self.new_queue = self.queue_settings.get("new_queue", "VulnerabilityManagement-CVE:new")
        self.modified_queue = self.queue_settings.get("modified_queue", "VulnerabilityManagement-CVE:modified")

    #
    # Files
    #

    def download_cve_file(self, source):
        """
        Download CVE file from internet database.
        :param source:
        :return: CVE data, CVE data timestamp and response or None if error
        """
        file_stream, response_info = get_file(source)
        try:
            if isinstance(file_stream, str):
                result = json.loads(file_stream)
            else:
                result = json.load(file_stream)
            if "CVE_Items" in result:
                CVE_data_timestamp = result.get("CVE_data_timestamp", unify_time(datetime.utcnow()))
                return result["CVE_Items"], CVE_data_timestamp, response_info
            return None
        except json.JSONDecodeError as json_error:
            print('Get an JSON decode error: {}'.format(json_error))
            return None

    def parse_cve_file(self, items=None, CVE_data_timestamp=unify_time(datetime.utcnow())):
        """
        Parse CVE file
        :param items:
        :param CVE_data_timestamp:
        :return: list of json
        """
        if items is None:
            items = []
        parsed_items = []
        for item in items:
            element = json.loads(CVEItem(item).to_json())
            element["cvss_time"] = CVE_data_timestamp
            parsed_items.append(element)
        return parsed_items

    #
    # Filters
    #

    @staticmethod
    def filter_cpe_string__json(element):
        """
        Filter CPE strings in CVE Items for valid component and version values
        :param element:
        :return: json
        """
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
        """
        Filter Vulners items and create more items for database - one by one item
        for filtered element in cpe strings in CVE Item
        :param items_fo_filter:
        :param unquote:
        :param only_digits_and_dot_in_version:
        :return: list of items
        """
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
                        if not str(new_item["version"]).__eq__(""):
                            filtered_items.append(new_item)
                        del new_item
        return filtered_items

    def if_item_already_exists_in_vulnerabilities_table(self, component, version, cve_id):
        """
        Check, if items already exist in Vulnerabilities table by component,
        version and CVE ID. If exists - return list of its IDs
        :param component:
        :param version:
        :param cve_id:
        :return: list of IDs
        """
        # Get IDs of records
        list_of_elements = list(
            VULNERABILITIES.select().where(
                (VULNERABILITIES.component == component) &
                (VULNERABILITIES.version == version) &
                (VULNERABILITIES.cve_id == cve_id)
            )
        )
        list_of_ids = []
        for element in list_of_elements:
            list_of_ids.append(element.id)
        return list_of_ids

    #
    # Creators
    #

    def create_record_in_vulnerabilities_table__id(self, item_to_create):
        """
        Create record in vulnerabilities table and return its ID
        :param item_to_create:
        :return: vulner id
        """
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

        vulner = VULNERABILITIES(
            component=item_to_create.get("component", ""),
            version=item_to_create.get("version", ""),
            data_type=item_to_create.get("data_type", ""),
            data_format=item_to_create.get("data_format", ""),
            data_version=item_to_create.get("data_version", ""),
            cve_id=item_to_create.get("cve_id", ""),
            cwe=item_to_create.get("cwe", []),
            references=item_to_create.get("references", []),
            description=item_to_create.get("description", ""),
            # cpe=item_to_create.get("cpe", ""),
            vulnerable_configuration=item_to_create.get("vulnerable_configuration", []),
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

    #
    # Updaters
    #

    def update_vulnerabilities_table_in_memory__counts(self, items_to_update):
        # Populate CVEs Items In Memory
        for item in progressbar(items_to_update):
            self.cache.append_item(item)
        print('Append {} keys.'.format(self.cache.size))

    def update_record_in_vulnerabilities_table__id(self, item_to_update, item_id_in_database):
        """
        Update record in vulnerabilities table and return its ID
        :param item_to_update:
        :param item_id_in_database:
        :return: vulner_id
        """
        was_modified = False
        vulner_from_database = VULNERABILITIES.get(VULNERABILITIES.id == item_id_in_database)
        vulner = vulner_from_database.to_json


        if vulner["data_type"] != item_to_update["data_type"]:
            was_modified = True
            vulner_from_database.data_type = item_to_update["data_type"]
        if vulner["data_format"] != item_to_update["data_format"]:
            was_modified = True
            vulner_from_database.data_format = item_to_update["data_format"]
        if vulner["data_version"] != item_to_update["data_version"]:
            was_modified = True
            vulner_from_database.data_version = item_to_update["data_version"]
        if vulner["cwe"] != item_to_update["cwe"]:
            was_modified = True
            vulner_from_database.cwe = item_to_update["cwe"]
        if vulner["references"] != item_to_update["references"]:
            was_modified = True
            vulner_from_database.references = item_to_update["references"]
        if vulner["description"] != item_to_update["description"]:
            was_modified = True
            vulner_from_database.description = item_to_update["description"]
        if vulner["vulnerable_configuration"] != item_to_update["vulnerable_configuration"]:
            was_modified = True
            vulner_from_database.vulnerable_configuration = item_to_update["vulnerable_configuration"]
        if unify_time(vulner["published"]) != unify_time(item_to_update["published"]):
            was_modified = True
            vulner_from_database.published = unify_time(item_to_update["published"])
        if unify_time(vulner["modified"]) != unify_time(item_to_update["modified"]):
            was_modified = True
            vulner_from_database.modified = unify_time(item_to_update["modified"])
        if was_modified:
            vulner_from_database.save()

        return vulner_from_database.id

    def update_vulnerabilities_table_for_modified_and_recent_cves(self, items_to_update):
        """
        Update vulnerabilities table
        :param items_to_update:
        :return: count of new records, count of updated records and time delta
        """
        start_time = time.time()
        count_of_new_records = 0
        count_of_updated_records = 0

        connect_database()

        # For every item in items to update
        # for one_item in items_to_update:
        for one_item in progressbar(items_to_update):
            # Check if exists
            component = one_item.get("component", None)
            version = one_item.get("version", None)
            cve_id = one_item.get("cve_id", None)
            if component is not None and \
                    version is not None and \
                    cve_id is not None:
                if_records_exists_in_database__ids = self.if_item_already_exists_in_vulnerabilities_table(
                    component, version, cve_id)
                if len(if_records_exists_in_database__ids) > 0:
                    for item_id_in_database in if_records_exists_in_database__ids:
                        _id = self.update_record_in_vulnerabilities_table__id(one_item, item_id_in_database)
                        count_of_updated_records += 1
                else:
                    _id = self.create_record_in_vulnerabilities_table__id(one_item)
                    count_of_new_records += 1
            one_item["id"] = _id
            pass

        disconnect_database()

        return count_of_new_records, count_of_updated_records, time.time() - start_time

    def update_vulnerabilities_table_in_postgres_for_cached_items(self):
        database.connect()
        keys = self.cache.cache.keys()

        for key in progressbar(keys):
            items = self.cache.get(key)
            for item in items:
                self.create_record_in_vulnerabilities_table__id(item)

        database.close()

    def update_modified_vulners_from_source(self):
        """
        Update modified elements in vulnerabilities table
        :return: count of new records to update, count of updated records and time delta
        """
        start_time = time.time()
        count_of_parsed_cve_items = 0
        count_of_updated_items = 0

        modified_items, CVE_data_timestamp, response = self.download_cve_file(self.cve_modified)
        modified_parsed = self.parse_cve_file(modified_items, CVE_data_timestamp)

        last_modified = parse_datetime(response.headers["last-modified"], ignoretz=True)

        info, created = INFO.get_or_create(name="cve-modified")
        if not created:
            if info.last_modified != "":
                info_last_modified = datetime.strptime(info.last_modified, '%Y-%m-%d %H:%M:%S')
            else:
                info_last_modified = datetime.strptime(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                                       '%Y-%m-%d %H:%M:%S')
        else:
            info_last_modified = datetime.strptime(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), '%Y-%m-%d %H:%M:%S')

        if info_last_modified != last_modified:
            info.last_modified = last_modified
            info.save()

            items_to_update = self.filter_items_to_update(modified_parsed)

            # Update vulners in Postgres
            self.update_vulnerabilities_table_for_modified_and_recent_cves(items_to_update)

            # Push ~modified~ items into collection ~modified~ in Redis

            for one_item_to_update in items_to_update:
                try:
                    queue.rpush(
                        self.modified_queue,
                        serialize_as_json__for_cache(
                            reformat_vulner_for_output(one_item_to_update)
                        )
                    )
                except Exception as ex:
                    print(ex)

            # Publish message
            queue.publish(
                self.channel_to_publish,
                self.modified_queue
            )

            count_of_parsed_cve_items = len(modified_parsed)
            count_of_updated_items = len(items_to_update)

        return count_of_parsed_cve_items, count_of_updated_items, time.time() - start_time

    def update_recent_vulners_from_source(self):
        """
        Update recent elements in vulnerabilities table
        :return: count of new records to update, count of updated records and time delta
        """
        start_time = time.time()
        count_of_parsed_cve_items = 0
        count_of_updated_items = 0

        recent_items, CVE_data_timestamp, response = self.download_cve_file(self.cve_recent)
        recent_parsed = self.parse_cve_file(recent_items, CVE_data_timestamp)

        last_modified = parse_datetime(response.headers["last-modified"], ignoretz=True)

        info, created = INFO.get_or_create(name="cve-recent")
        if not created:
            if info.last_modified != "":
                info_last_modified = datetime.strptime(info.last_modified, '%Y-%m-%d %H:%M:%S')
            else:
                info_last_modified = datetime.strptime(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                                       '%Y-%m-%d %H:%M:%S')
        else:
            info_last_modified = datetime.strptime(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), '%Y-%m-%d %H:%M:%S')

        if info_last_modified != last_modified:
            info.last_modified = last_modified
            info.save()

            items_to_update = self.filter_items_to_update(recent_parsed)

            # Update vulners in Postgres
            self.update_vulnerabilities_table_for_modified_and_recent_cves(items_to_update)

            # Push ~recent~ items into collection ~new~ in Redis
            for one_item_to_update in items_to_update:
                try:
                    queue.rpush(
                        self.new_queue,
                        serialize_as_json__for_cache(
                            reformat_vulner_for_output(one_item_to_update)
                        )
                    )
                except Exception as ex:
                    pass

            # Publish message
            queue.publish(
                self.channel_to_publish,
                self.new_queue
            )
            count_of_parsed_cve_items = len(recent_parsed)
            count_of_updated_items = len(items_to_update)

        return count_of_parsed_cve_items, count_of_updated_items, time.time() - start_time

    #
    # Populaters
    #

    def populate_vulners_in_memory_than_postgres__counts(self):
        start_time = time.time()
        # start_year = SETTINGS.get("start_year", 2002)
        current_year = datetime.now().year
        count_of_parsed_cve_items = 0
        count_of_populated_items = 0
        for year in range(self.start_year, current_year + 1):
            print("Populate CVE-{}".format(year))
            source = self.cve_base + str(year) + self.cve_base_postfix
            cve_item, cve_data_timestamp, response = self.download_cve_file(source)

            parsed_cve_items = self.parse_cve_file(cve_item, cve_data_timestamp)

            items_to_populate = self.filter_items_to_update(parsed_cve_items)

            self.update_vulnerabilities_table_in_memory__counts(items_to_populate)

            count_of_parsed_cve_items += len(parsed_cve_items)
            count_of_populated_items += len(items_to_populate)

        self.update_vulnerabilities_table_in_postgres_for_cached_items()

        return count_of_parsed_cve_items, count_of_populated_items, time.time() - start_time

    #
    # Actions
    #

    def drop_all_tables_in_postgres(self):
        print('Tables will be drop from PostgresQL')
        drop_all_tables_in_postgres()

    def create_tables_in_postgres(self):
        print('Tables will be created in PostgresQL')
        create_tables_in_postgres()

    def action_update_cwe(self):
        action_update_cwe()

    def action_update_capec(self):
        action_update_capec()

    def action_populate_databases(self):
        print("Start population of database")
        count_of_parsed_cve_items, count_of_populated_items, time_delta = self.populate_vulners_in_memory_than_postgres__counts()
        print("Cache stats: {} elements".format(self.cache.stats))
        print('Dumped into: {}'.format(self.cache.dump_cache_into_json_file__with_ts()))
        print("Get        {} populated elements from source".format(count_of_parsed_cve_items))
        print("Append     {} populated elements from source in database".format(count_of_populated_items))
        print("TimeDelta  %.2f sec." % (time_delta))

    def action_update_modified_elements(self):
        print("Start update modified of database")
        count_of_parsed_cve_items, count_of_updated_items, time_delta = self.update_modified_vulners_from_source()
        print("Get        {} modified elements from source".format(count_of_parsed_cve_items))
        print("Append     {} modified elements from source in database".format(count_of_updated_items))
        print("TimeDelta  %.2f sec." % (time_delta))

    def action_update_recent_elements(self):
        print("Start update recent of database")
        count_of_parsed_cve_items, count_of_updated_items, time_delta = self.update_recent_vulners_from_source()
        print("Get        {} recent elements from source".format(count_of_parsed_cve_items))
        print("Append     {} recent elements from souce in database".format(count_of_updated_items))
        print("TimeDelta  %.2f sec." % (time_delta))

    def run(self):
        self.drop_all_tables_in_postgres()
        self.create_tables_in_postgres()
        self.action_update_cwe()
        self.action_update_capec()
        self.action_populate_databases()
        self.action_update_modified_elements()
        self.action_update_recent_elements()


def main():
    print('Updater started...')
    updater = Updater()
    updater.run()
    print("Complete updating database.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
