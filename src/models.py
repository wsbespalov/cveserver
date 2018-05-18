import peewee
from playhouse.postgres_ext import ArrayField
from datetime import datetime
from settings import SETTINGS

POSTGRES = SETTINGS.get("postgres", {})
database = peewee.PostgresqlDatabase(
    database=POSTGRES.get("database", "updater_db"),
    user=POSTGRES.get("user", "postgres"),
    password=POSTGRES.get("password", "password"),
    host=POSTGRES.get("host", "localhost"),
    port=int(POSTGRES.get("port", 5432))
)


class CWE(peewee.Model):
    class Meta:
        database = database
        ordering = ("cwe_id", )
        table_name = "cwe"

    id = peewee.PrimaryKeyField(null=False, )
    cwe_id = peewee.TextField(default="",)
    name = peewee.TextField(default="",)
    status = peewee.TextField(default="",)
    weaknesses = peewee.TextField(default="",)
    description_summary = peewee.TextField(default="",)

    def __unicode__(self):
        return "cwe"

    def __str__(self):
        return self.cwe_id

    @property
    def to_json(self):
        return dict(
            id=self.id,
            cwe_id=self.cwe_id,
            name=self.name,
            status=self.status,
            weaknesses=self.weaknesses,
            description_summary=self.description_summary
        )


class CAPEC(peewee.Model):
    class Meta:
        database = database
        ordering = ("capec_id",)
        table_name = "capec"

    id = peewee.PrimaryKeyField(null=False, )
    capec_id = peewee.TextField(default="",)
    name = peewee.TextField(default="",)
    summary = peewee.TextField(default="",)
    prerequisites = peewee.TextField(default="",)
    solutions = peewee.TextField(default="",)
    related_weakness = ArrayField(
        peewee.TextField,
        default=[],
        verbose_name='related_weakness'
    )

    def __unicode__(self):
        return "capec"

    def __str__(self):
        return self.capec_id

    @property
    def to_json(self):
        return dict(
            id=self.id,
            capec_id=self.capec_id,
            name=self.name,
            summary=self.summary,
            prerequisites=self.prerequisites,
            solutions=self.solutions,
            related_weakness=self.related_weakness
        )


class vulnerabilities(peewee.Model):
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


class INFO(peewee.Model):
    class Meta:
        database = database
        table_name = "info"

    name = peewee.TextField(
        default="",
        verbose_name="Collection name"
    )
    last_modified = peewee.TextField(
        default="",
        verbose_name="Last modified time"
    )

    def __unicode__(self):
        return "INFO"

    @property
    def data(self):
        info_data = {}
        info_data["id"] = self.id
        info_data["name"] = self.name
        info_data["last_modified"] = self.last_modified
        return info_data

    def save(self, *args, **kwargs):
        super(INFO, self).save(*args, **kwargs)
