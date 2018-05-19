from upd_vulners import *
from upd_cwe import action_update_cwe
from upd_capec import action_update_capec
from searcher import *
from utils import drop_all_tables_in_postgres, create_tables_in_postgres

from cve_populater import CVEUpdaterDownloader


def action_populate_databases():
    print("Start population of database")
    count_of_parsed_cve_items, count_of_populated_items, time_delta = populate_vulners_from_source()
    print("Get        {} populated elements from source".format(count_of_parsed_cve_items))
    print("Append     {} populated elements from source in database".format(count_of_populated_items))
    print("TimeDelta  %.2f sec." % (time_delta))


def action_update_modified_elements():
    print("Start update modified of database")
    count_of_parsed_cve_items, count_of_updated_items, time_delta = update_modified_vulners_from_source()
    print("Get        {} modified elements from source".format(count_of_parsed_cve_items))
    print("Append     {} modified elements from source in database".format(count_of_updated_items))
    print("TimeDelta  %.2f sec." % (time_delta))


def action_update_recent_elements():
    print("Start update recent of database")
    count_of_parsed_cve_items, count_of_updated_items, time_delta = update_recent_vulners_from_source()
    print("Get        {} recent elements from source".format(count_of_parsed_cve_items))
    print("Append     {} recent elements from souce in database".format(count_of_updated_items))
    print("TimeDelta  %.2f sec." % (time_delta))


def main():
    drop_all_tables_in_postgres()
    create_tables_in_postgres()
    print(action_update_cwe())
    print(action_update_capec())
    # action_populate_databases()
    # print()
    action_update_modified_elements()
    print()
    action_update_recent_elements()

    d = CVEUpdaterDownloader()
    print(d.populate())
    print("Cache stats: {} elements".format(d.cache.stats))

    print('Dumped into: {}'.format(
        d.cache.dump_cache_into_json_file__with_ts()
    ))


if __name__ == '__main__':
    sys.exit(main())
