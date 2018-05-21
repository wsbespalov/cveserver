import os
import re
import ast
import bz2
import gzip
import json
import sys
from math import floor
import urllib.request as req
import zipfile
from datetime import datetime
from io import BytesIO
import platform

from models import VULNERABILITIES, INFO, CAPEC, CWE
from database import *

from dateutil.parser import parse as parse_datetime


def to_string_formatted_cpe(cpe, autofill=False):
    """Convert CPE to formatted string"""
    cpe = cpe.strip()
    if not cpe.startswith('cpe:2.3:'):
        if not cpe.startswith('cpe:/'):
            return False
        cpe = cpe.replace('cpe:/', 'cpe:2.3:')
        cpe = cpe.replace('::', ':-:')
        cpe = cpe.replace('~-', '~')
        cpe = cpe.replace('~', ':-:')
        cpe = cpe.replace('::', ':')
        cpe = cpe.strip(':-')
    if autofill:
        element = cpe.split(':')
        for _ in range(0, 13 - len(element)):
            cpe += ':-'
    return cpe


def convert_list_data_to_json(data):
    if isinstance(data, list):
        serialized = []
        for element in data:
            serialized.append(json.dumps(element))
        return serialized
    else:
        return []


def unify_time(dt):
    if isinstance(dt, str):
        if 'Z' in dt:
            dt = dt.replace('Z', '')
        return parse_datetime(dt)

    if isinstance(dt, datetime):
        return parse_datetime(str(dt))


def print_list(items_to_print):
    for item in items_to_print:
        print("-> {}".format(item))


def print_short(items_to_print):
    for item in items_to_print:
        print("Component: {}, version: {}, CVE: {}, CP: {}, VCONF: {}".format(
            item["component"],
            item["version"],
            item["cve_id"],
            item["cpe"],
            item["vulnerable_configuration"]["data"]))


def serialize_json__for_postgres(source):
    try:
        return json.dumps(ast.literal_eval(source))
    except ValueError:
        return json.dumps(source)


def deserialize_json__for_postgres(source):
    if isinstance(source, list):
        return source
    else:
        a = ast.literal_eval(source)
    if isinstance(a, dict):
        return a
    return json.loads(a)


def serialize_as_json__for_cache(element):
    def dt_converter(o):
        if isinstance(o, datetime):
            return o.__str__()
    try:
        return json.dumps(element, default=dt_converter)
    except Exception as ex:
        print("{}".format(ex))
        return None


def deserialize_as_json__for_cache(element):
    try:
        return json.loads(element)
    except:
        return None


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


def get_file(getfile, unpack=True, raw=False, HTTP_PROXY=None):
    if platform.system().lower() == "linux":
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
                    current_directory = os.path.dirname(os.path.abspath(__file__))
                    tmp_file = "data.json"
                    full_path = "".join([
                        current_directory, "/", tmp_file
                    ])
                    with open(full_path, "wb") as outfile:
                        outfile.write(gzip.decompress(response.read()))
                    out = open(full_path, 'r').read()
                    return out, response
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


    elif platform.system().lower() == "darwin":
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


def reformat_vulner_for_output(item_to_reformat):
    """
    Reformat vulner for Response
    :param item_to_reformat:
    :return: reformatted item for response
    """
    id = item_to_reformat["id"]
    published = unify_time(item_to_reformat.get("publushed", datetime.utcnow()))
    modified = unify_time(item_to_reformat.get("modified", datetime.utcnow()))
    access_in_item = item_to_reformat.get("access", dict(
        vector="",
        complexity="",
        authentication=""
    ))
    if isinstance(access_in_item, str):
        access = deserialize_json__for_postgres(access_in_item)
    else:
        access = access_in_item

    impact_in_item = item_to_reformat.get("impact", dict(
        confidentiality="",
        integrity="",
        availability=""
    ))
    if isinstance(impact_in_item, str):
        impact = deserialize_json__for_postgres(impact_in_item)
    else:
        impact = impact_in_item

    vector_string = item_to_reformat.get("vector_string", "")
    cvss_time = unify_time(item_to_reformat.get("cvss_time", datetime.utcnow()))
    cvss = item_to_reformat.get("cvss", 0.0)
    cwe_in_item = item_to_reformat.get("cwe", [])
    cwe_list = deserialize_json__for_postgres(cwe_in_item)
    cwe_id_list = []
    for cwe_in_list in cwe_list:
        cwe_id_list.append(re.sub("\D", "", cwe_in_list))
    title = item_to_reformat.get("cve_id", "")
    description = item_to_reformat.get("description", "")

    rank = floor(cvss)

    __v = 0

    capec_list = item_to_reformat.get("capec", [])
    capec = []  # not yet

    for capec_in_list in capec_list:
        if isinstance(capec_in_list, str):
            capec.append(json.loads(capec_in_list))
        elif isinstance(capec_in_list, dict):
            capec.append(capec_in_list)

    vulnerable_configurations = []

    vulnerable_configuration = item_to_reformat.get("vulnerable_configuration", [])

    cve_references = item_to_reformat.get("references", [])

    template = dict(
        _id=id,
        Published=published,
        Modified=modified,
        access=access,
        impact=impact,
        cvss_time=cvss_time,
        cvss=cvss,
        cwe=cwe_list,
        cwe_id=cwe_id_list,
        title=title,
        description=description,
        rank=rank,
        __v=__v,
        capec=capec,
        vulnerable_configurations=vulnerable_configurations,
        vulnerable_configuration=vulnerable_configuration,
        cve_references=cve_references,
        vector_string=vector_string
    )
    return template


