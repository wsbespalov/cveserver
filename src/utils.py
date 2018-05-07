import urllib.request as req
import zipfile
from io import BytesIO
import gzip
import bz2
import sys
import json


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


def get_file(getfile, unpack=True, raw=False, HTTP_PROXY=None):
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