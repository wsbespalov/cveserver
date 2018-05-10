import json
from datetime import datetime

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

        # Additional fields
        self.component = ""
        self.version = ""

    def to_json(self):
        return json.dumps(self,
                          default=lambda o: o.__dict__,
                          sort_keys=True)

