import peewee
from settings import SETTINGS

from models import vulnerabilities

POSTGRES = SETTINGS.get("postgres", {})
database = peewee.PostgresqlDatabase(
    database=POSTGRES.get("database", "updater_db"),
    user=POSTGRES.get("user", "postgres"),
    password=POSTGRES.get("password", "password"),
    host=POSTGRES.get("host", "localhost"),
    port=int(POSTGRES.get("port", 5432))
)

##############################################################################
# Connect and disconnect Postgres database.
##############################################################################

def connect_database():
    # database.pragma('cache_size', -1024 * int(SETTINGS["postgres"]["cache_size"]))
    try:
        if database.is_closed():
            database.connect()
    except peewee.OperationalError as peewee_operational_error:
        pass

def disconnect_database():
    try:
        if not database.is_closed():
            database.close()
    except peewee.OperationalError as peewee_operational_error:
        pass

