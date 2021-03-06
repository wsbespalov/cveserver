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
    "minimum_year": 2002,
    "postgres": {
        "user": 'admin',
        "password": '123',
        "database": "updater_db",
        "host": "localhost",
        "port": "5432",
        "drop_before": False,
        "cache_size_mb": 64
    },
    "memcached": {
        "key_prefix": "index",
        "separator": "::",
        "drop_cache_before": True,
        "store_dumps_on_disk":True,
        "dump_directory": "/tmp",
        "dump_file_name_base": "dump",
        "dump_file_extension": "json"
    },
    "cache": {
        "host": 'localhost',
        "port": 6379,
        "db": 3,
        "separator": "::",
        "index": "index",
        "key_expire_time_in_sec": 120 # 1 minute for tests
    },
    "queue": {
        "host": 'localhost',
        "port": 6379,
        "db": 0,
        "prefix_requests": "search::",
        "prefix_results": "create::",
        "channel": "start_processing",
        "message_to_start_search": "start_search",
        "channel_complete": "search_complete",
        "complete_message": "create::",
        "complete_get_vulnerability": "result::",
        "vulnerability_channel": "vulnerabilityServiceChannel",
        "message_to_get_vulnerability": "getVulnerability",
        "message_to_kill_search": "message_to_kill_search",
        "modified_queue": "VulnerabilityManagement-CVE:modified",
        "new_queue": "VulnerabilityManagement-CVE:new"
    },
    "search": {
        "output_only_one": True,    # True - output only one result with the same component:version
                                    # junos:14.1:rc1, junos:14.1:rc2, junos:14.1:rc3, ... -> junos:14.1:rc1
                                    # False - output all found
    },
    "debug": True
}
