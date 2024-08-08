"""
Create a SQLite for Chaching
"""
from os.path import exists
from sqlite3 import connect
from loader import Loader

def create_database():
    """
    Create  Databae for Trivy CVEs found mre then other Scanners.
    """
    loader = Loader()
    trivy = loader.trivy('json/trivy_backend.json')
    grype = loader.grype('json/grype_backend.json')
    snyk = loader.snyk('json/snyk_backend.json')
    scout = loader.scout('json/scout_backend.json')
    vesta = loader.vesta('json/vesta_backend.json')

    veinmind = set()
    veinmind.add('GHSA-mq26-g339-26xf')
    veinmind.add('CVE-2023-5752')
    veinmind.add('GHSA-r9hx-vwmv-q579')
    veinmind.add('CVE-2022-40897')

    all_without_trivy = grype | snyk | scout | vesta | veinmind

    db_name = 'trivy_backend.db'

    if not exists(db_name):
        conn = connect(db_name)
        cursor = conn.cursor()

        create_table_query = '''
        CREATE TABLE IF NOT EXISTS Vulnerability (
            CVE TEXT PRIMARY KEY,
            Severity TEXT,
            Info TEXT
        );
        '''

        cursor.execute(create_table_query)

        for vuln in trivy.difference(all_without_trivy):
            severity = loader.get_trivy_severity('json/trivy_backend.json', vuln)
            info = loader.get_trivy_description('json/trivy_backend.json', vuln)

            insert_query = 'INSERT INTO Vulnerability (CVE, Severity, Info) VALUES (?, ?, ?)'
            cursor.execute(insert_query, (vuln, severity, info))

        conn.commit()
        conn.close()
