from book_keeper import BookKeeper
from sqlalchemy import create_engine


class RDSBookKeeper(BookKeeper):
    """
    A book keeper that can read book-keeping data from RDS in AWS and provide the list of recently
    updated/inserted EPVs.
    """

    def __init__(self, postgres_host, postgres_port, postgres_user, postgres_pass, postgres_db):
        self.postgres_host = postgres_host
        self.postgres_port = postgres_port
        self.postgres_user = postgres_user
        self.postgres_pass = postgres_pass
        self.postgres_db = postgres_db

    def get_name(self):
        return "RDS database {} from host {}".format(self.postgres_db, self.postgres_host)

    def get_recent_epv(self, min_finished_at):
        """Get all the EPVs that were ingested after the given timestamp"""
        list_epv = []
        try:
            postgres_host = self.POSTGRESQL_HOST
            postgres_port = self.POSTGRESQL_PORT
            postgres_user = self.POSTGRESQL_USER
            postgres_pass = self.POSTGRESQL_PASSWORD
            postgres_db = self.POSTGRESQL_DATABASE

            postgres_conn_str = 'postgres://{user}:{passwd}@{host}:{port}/{db}'
            postgres_conn_str = postgres_conn_str.format(user=postgres_user, passwd=postgres_pass,
                                                         host=postgres_host, port=postgres_port, db=postgres_db)
            engine = create_engine(postgres_conn_str)

            query = """
                SELECT
                  E.NAME AS ECOSYSTEM,
                  P.NAME AS PACKAGE,
                  V.IDENTIFIER AS VERSION,
                  A.FINISHED_AT AS FINISHED_AT
                FROM
                  ANALYSES AS A,
                  VERSIONS AS V,
                  PACKAGES AS P,
                  ECOSYSTEMS AS E
                WHERE
                  A.FINISHED_AT > '{min_finished_at}' AND
                  A.VERSION_ID = V.ID AND
                  V.PACKAGE_ID = P.ID AND
                  P.ECOSYSTEM_ID = E.ID
                ORDER BY
                  A.FINISHED_AT
            """
            query = query.format(min_finished_at=min_finished_at)
            output = engine.execute(query)
            for row in output:
                list_epv.append({'ecosystem': row.ecosystem, 'name': row.package, 'version': row.version})

        except Exception as e:
            msg = "RDSBookKeeper::get_recent_epv() failed with error: %s" % e
            raise RuntimeError(msg)
        return list_epv



