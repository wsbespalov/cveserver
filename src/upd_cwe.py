import time
from xml.sax import make_parser
from xml.sax.handler import ContentHandler

from datetime import datetime
from dateutil.parser import parse as parse_datetime

from settings import SETTINGS

from database import connect_database
from database import disconnect_database

from utils import get_file
from utils import progressbar

from models import CWE, INFO


class CWEHandler(ContentHandler):
    def __init__(self):
        self.cwe = []
        self.description_summary_tag = False
        self.weakness_tag = False

    def startElement(self, name, attrs):
        if name == 'Weakness':
            self.weakness_tag = True
            self.statement = ""
            self.weaknesses = attrs.get('Weakness_Abstraction')
            self.name = attrs.get('Name')
            self.idname = attrs.get('ID')
            self.status = attrs.get('Status')
            self.cwe.append({
                'name': self.name,
                'id': self.idname,
                'status': self.status,
                'weaknessabs': self.weaknesses})
        elif name == 'Description_Summary' and self.weakness_tag:
            self.description_summary_tag = True
            self.description_summary = ""

    def characters(self, ch):
        if self.description_summary_tag:
            self.description_summary += ch.replace("       ", "")

    def endElement(self, name):
        if name == 'Description_Summary' and self.weakness_tag:
            self.description_summary_tag = False
            self.description_summary = self.description_summary + \
                                       self.description_summary
            self.cwe[-1]['description_summary'] = \
                self.description_summary.replace("\n", "")
        elif name == 'Weakness':
            self.weakness_tag = False


def action_update_cwe():
    connect_database()

    INFO.create_table()

    CWE.create_table()

    start_time = time.time()
    parsed_items = []

    parser = make_parser()
    cwe_handler = CWEHandler()
    parser.setContentHandler(cwe_handler)

    source = SETTINGS["sources"]["cwe"]

    try:
        data, response = get_file(getfile=source)
    except:
        print('Update Database CWE: Cant download file: {}'.format(source))
        disconnect_database()
        return dict(
            items=0,
            time_delta=0,
            message='Update Database CWE: Cant download file: {}'.format(source)
        )

    last_modified = parse_datetime(response.headers['last-modified'], ignoretz=True)

    info, created = INFO.get_or_create(name="cwe")
    if not created:
        if info.last_modified != "":
            info_last_modified = datetime.strptime(info.last_modified, '%Y-%m-%d %H:%M:%S')
        else:
            info_last_modified = datetime.strptime(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), '%Y-%m-%d %H:%M:%S')
    else:
        info_last_modified = datetime.strptime(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), '%Y-%m-%d %H:%M:%S')

    if info_last_modified != last_modified:
        info.last_modified = last_modified
        info.save()

        parser.parse(data)

        for cwe in cwe_handler.cwe:
            cwe['description_summary'] = cwe['description_summary'].replace("\t\t\t\t\t", " ")
            parsed_items.append(cwe)

        for item in progressbar(parsed_items, prefix="Update Database CWE: "):
            item_id = "CWE-" + item["id"]

            item_name = item.get("name", "")
            item_status = item.get("status", "")
            item_weaknesses = item.get("weaknesses", "")
            item_description_summary = item.get("description_summary", "")

            cwe_selected = CWE.get_or_none(CWE.cwe_id == item_id)

            if cwe_selected is None:
                cwe_created = CWE(
                    cwe_id=item_id,
                    name=item_name,
                    status=item_status,
                    weaknesses=item_weaknesses,
                    description_summary=item_description_summary
                )
                cwe_created.save()

            else:
                if cwe_selected.name == item_name and \
                        cwe_selected.status == item_status and \
                        cwe_selected.weaknesses == item_weaknesses and \
                        cwe_selected.description_summary == item_description_summary:
                    pass
                else:
                    cwe_selected.name = item_name
                    cwe_selected.status = item_status
                    cwe_selected.weaknessabs = item_weaknesses
                    cwe_selected.description_summary = item_description_summary
                    cwe_selected.save()

        stop_time = time.time()

        disconnect_database()

        return dict(
            items=len(parsed_items),
            time_delta=stop_time - start_time,
            message="Update Database CWE: Complete."
        )

    return dict(
        items=0,
        time_delta=0,
        message="Update Database CWE: Not modified"
    )
