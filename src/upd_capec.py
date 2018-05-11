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

from models import CAPEC, INFO


class CapecHandler(ContentHandler):

    def __init__(self):
        self.capec = []
        self.Attack_Pattern_Catalog_tag = False
        self.Attack_Patterns_tag = False
        self.Attack_Pattern_tag = False
        self.Description_tag = False
        self.Summary_tag = False
        self.Text_tag = False
        self.Attack_Prerequisites_tag = False
        self.Attack_Prerequisite_tag = False
        self.Solutions_and_Mitigations_tag = False
        self.Solution_or_Mitigation_tag = False
        self.Related_Weaknesses_tag = False
        self.Related_Weakness_tag = False
        self.CWE_ID_tag = False

        self.tag = False

        self.id = ""
        self.name = ""

        self.Summary_ch = ""
        self.Attack_Prerequisite_ch = ""
        self.Solution_or_Mitigation_ch = ""
        self.CWE_ID_ch = ""

        self.Summary = []
        self.Attack_Prerequisite = []
        self.Solution_or_Mitigation = []
        self.Related_Weakness = []

    def startElement(self, name, attrs):

        if name == 'capec:Attack_Pattern_Catalog':
            self.Attack_Pattern_Catalog_tag = True
        if name == 'capec:Attack_Patterns' and self.Attack_Pattern_Catalog_tag:
            self.Attack_Patterns_tag = True
        if name == 'capec:Attack_Pattern' and self.Attack_Patterns_tag:
            self.Attack_Pattern_tag = True

        if self.Attack_Pattern_tag:
            self.tag = name
            if self.tag == 'capec:Attack_Pattern':
                self.id = attrs.getValue('ID')
                self.name = attrs.getValue('Name')

            if self.tag == 'capec:Description':
                self.Description_tag = True
            if name == 'capec:Summary' and self.Description_tag:
                self.Summary_tag = True
            if name == 'capec:Text' and self.Summary_tag:
                self.Text_tag = True
                self.Summary_ch = ""

            if self.tag == 'capec:Attack_Prerequisites':
                self.Attack_Prerequisites_tag = True
            if name == 'capec:Attack_Prerequisite' and \
                    self.Attack_Prerequisites_tag:
                self.Attack_Prerequisite_tag = True
            if name == 'capec:Text' and self.Attack_Prerequisite_tag:
                self.Text_tag = True
                self.Attack_Prerequisite_ch = ""

            if self.tag == 'capec:Solutions_and_Mitigations':
                self.Solutions_and_Mitigations_tag = True
            if name == 'capec:Solution_or_Mitigation' and \
                    self.Solutions_and_Mitigations_tag:
                self.Solution_or_Mitigation_tag = True
            if name == 'capec:Text' and self.Solution_or_Mitigation_tag:
                self.Text_tag = True
                self.Solution_or_Mitigation_ch = ""

            if self.tag == 'capec:Related_Weaknesses':
                self.Related_Weaknesses_tag = True
            if name == 'capec:Related_Weakness' and \
                    self.Related_Weaknesses_tag:
                self.Related_Weakness_tag = True
            if name == 'capec:CWE_ID' and self.Related_Weakness_tag:
                self.CWE_ID_tag = True
                self.CWE_ID_ch = ""

    def characters(self, ch):
        if self.Text_tag:
            if self.Summary_tag:
                self.Summary_ch += ch
            elif self.Attack_Prerequisite_tag:
                self.Attack_Prerequisite_ch += ch
            elif self.Solution_or_Mitigation_tag:
                self.Solution_or_Mitigation_ch += ch
        elif self.CWE_ID_tag:
            self.CWE_ID_ch += ch

    def endElement(self, name):
        if name == 'capec:Summary':
            if self.Summary_ch != "":
                self.Summary_ch = ""
            self.Summary_tag = False
        if name == 'capec:Attack_Prerequisite':
            if self.Attack_Prerequisite_ch != "":
                self.Attack_Prerequisite.append(
                    self.Attack_Prerequisite_ch.rstrip())
            self.Attack_Prerequisite_tag = False
        if name == 'capec:Solution_or_Mitigation':
            if self.Solution_or_Mitigation_ch != "":
                self.Solution_or_Mitigation.append(
                    self.Solution_or_Mitigation_ch.rstrip())
            self.Solution_or_Mitigation_tag = False
        if name == 'capec:Related_Weakness':
            if self.CWE_ID_ch != "":
                self.Related_Weakness.append(self.CWE_ID_ch.rstrip())
            self.Related_Weakness_tag = False

        if name == 'capec:Description':
            self.Description_tag = False
        if name == 'capec:Attack_Prerequisites':
            self.Attack_Prerequisites_tag = False
        if name == 'capec:Solutions_and_Mitigations':
            self.Solutions_and_Mitigations_tag = False
        if name == 'capec:Related_Weaknesses':
            self.Related_Weaknesses_tag = False

        if name == 'capec:Text':
            if self.Summary_tag:
                self.Summary.append(self.Summary_ch.rstrip())
            self.Text_tag = False
        if name == 'capec:CWE_ID':
            self.CWE_ID_tag = False
        if name == 'capec:Attack_Pattern':
            self.capec.append({
                'name': self.name,
                'id': self.id,
                'summary': '\n'.join(self.Summary),
                'prerequisites': '\n'.join(self.Attack_Prerequisite),
                'solutions': '\n'.join(self.Solution_or_Mitigation),
                'related_weakness': self.Related_Weakness})
            self.Summary = []
            self.Attack_Prerequisite = []
            self.Solution_or_Mitigation = []
            self.Related_Weakness = []

            self.Attack_Pattern_tag = False
        if name == 'capec:Attack_Patterns':
            self.Attack_Patterns_tag = False
        if name == 'capec:Attack_Pattern_Catalog':
            self.Attack_Pattern_Catalog_tag = False


def action_update_capec():
    connect_database()

    INFO.create_table()

    CAPEC.create_table()

    start_time = time.time()
    parsed_items = []

    parser = make_parser()
    ch = CapecHandler()
    parser.setContentHandler(ch)

    source = SETTINGS["sources"]["capec"]

    try:
        data, response = get_file(getfile=source)
    except:
        print('Update Database CAPEC: Cant download file: {}'.format(source))
        disconnect_database()
        return dict(
            items=0,
            time_delta=0,
            message='Update Database CAPEC: Cant download file: {}'.format(source)
        )

    last_modified = parse_datetime(response.headers['last-modified'], ignoretz=True)

    info, created = INFO.get_or_create(name="capec")
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

        for item in progressbar(ch.capec, prefix="Update Database CAPEC: "):
            parsed_items.append(item)
            item_id = "CAPEC-" + item["id"]
            item_name = item.get("name", "")
            item_summary = item.get("summary", "")
            item_prerequisites = item.get("prerequisites", "")
            item_solutions = item.get("solutions", "")
            item_related_weakness = item.get("related_weakness", [])

            for i in range(0, len(item_related_weakness)):
                item_related_weakness[i] = ''.join(filter(lambda x: x.isdigit(), item_related_weakness[i]))
                item_related_weakness[i] = 'CWE-' + item_related_weakness[i]

            capec_selected = CAPEC.get_or_none(CAPEC.capec_id == item_id)

            if capec_selected is None:
                capec_created = CAPEC(
                    capec_id=item_id,
                    name=item_name,
                    summary=item_summary,
                    prerequisites=item_prerequisites,
                    solutions=item_solutions,
                    related_weakness=item_related_weakness
                )
                capec_created.save()

            else:
                if capec_selected.name == item_name and \
                        capec_selected.summary == item_summary and \
                        capec_selected.prerequisites == item_prerequisites and \
                        capec_selected.solutions == item_solutions and \
                        capec_selected.related_weakness == item_related_weakness:
                    pass
                else:
                    capec_selected.name = item_name
                    capec_selected.summary = item_summary
                    capec_selected.prerequisites = item_prerequisites
                    capec_selected.solutions = item_solutions
                    capec_selected.related_weakness = item_related_weakness
                    capec_selected.save()

        stop_time = time.time()

        disconnect_database()

        return dict(
            items=len(parsed_items),
            time_delta=stop_time - start_time,
            message="Update Database CAPEC: Complete."
        )

    disconnect_database()

    return dict(
        items=0,
        time_delta=0,
        message="Update Database CAPEC: Not modified"
    )
