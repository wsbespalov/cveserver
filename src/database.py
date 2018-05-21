import peewee
from settings import SETTINGS

from models import CWE
from models import INFO
from models import CAPEC
from models import VULNERABILITIES

POSTGRES = SETTINGS.get("postgres", {})
database = peewee.PostgresqlDatabase(
    database=POSTGRES.get("database", "updater_db"),
    user=POSTGRES.get("user", "postgres"),
    password=POSTGRES.get("password", "password"),
    host=POSTGRES.get("host", "localhost"),
    port=int(POSTGRES.get("port", 5432))
)


def connect_database():
    """
    Connect to PostgresQL DB
    :return:
    """
    # database.pragma('cache_size', -1024 * int(SETTINGS["postgres"]["cache_size"]))
    try:
        if database.is_closed():
            database.connect()
    except peewee.OperationalError as peewee_operational_error:
        pass


def disconnect_database():
    """
    Disconnect from PostgresQL DB
    :return:
    """
    try:
        if not database.is_closed():
            database.close()
    except peewee.OperationalError as peewee_operational_error:
        pass

def drop_all_tables_in_postgres():
    """
    Drop tables from PostgresQL
    :return:
    """
    if SETTINGS["postgres"]["drop_before"]:
        connect_database()
        CAPEC.drop_table()
        CWE.drop_table()
        INFO.drop_table()
        VULNERABILITIES.drop_table()
        disconnect_database()


def create_tables_in_postgres():
    """
    Drop tables from PostgresQL
    :return:
    """
    connect_database()
    CAPEC.create_table()
    CWE.create_table()
    INFO.create_table()
    VULNERABILITIES.create_table()
    disconnect_database()