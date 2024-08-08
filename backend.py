"""
Comparison of the scanners in the backend
"""
from sqlite3 import connect
from re import compile
import matplotlib.pyplot as plt
from colorama import Fore, Style
from matplotlib_venn import venn3, venn2
from venn import venn, pseudovenn
from loader import Loader
from create_trivy_backend_db import create_database

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

# Mächtigkeit der Mengen
#print(Fore.GREEN + 'Mächtigkeit:' + Style.RESET_ALL)
#print("Trivy: " + str(len(trivy)))
#print("Grype: " + str(len(grype)))
#print("Snyk:  " + str(len(snyk)))
#print("Scout: " + str(len(scout)))
#print("Vesta: " + str(len(vesta)))
#print("Veinmind: " + str(len(veinmind)))


# Plotten des Venn Diagramms
venn3((trivy, grype, scout), set_labels=('Trivy', 'Grype', 'Scout'))
plt.title('Backend')
plt.savefig('img/backend.png')
plt.clf()

sets = {
    'Trivy': trivy,
    'Grype': grype,
    'Snyk': snyk,
    'Docker Scout': scout,
    'Vesta': vesta,
    'Veinmind': veinmind
}

pseudovenn(sets,  hint_hidden=False, fontsize=14, legend_loc="best", ax=None)
plt.savefig('img/backend_all.png')
plt.clf()


all_without_veinmind = trivy | grype | snyk | scout | vesta
all_without_trivy = grype | snyk | scout | vesta | veinmind
all_without_grype = trivy | snyk | scout | vesta | veinmind
all_without_snyk = trivy | grype | scout | vesta | veinmind
all_without_scout = trivy | grype | snyk | vesta | veinmind
all_without_vesta = trivy | grype | snyk | scout | veinmind

# Teilmengen
#print(Fore.GREEN + 'Teilmengen:' + Style.RESET_ALL)
#print(f'Veinmind - all: {veinmind.difference(all_without_veinmind)}')
#for i in vesta.difference(all_without_vesta):
#    print(f'{loader.get_vesta_description("json/vesta_backend.json", i)}')

#print(f'Docker Scout - all: {scout.difference(all_without_scout)}')
#print(f'Snyk -all: {snyk.difference(all_without_snyk)}')
#print(f'Grype -all: {grype.difference(all_without_grype)}')

# Analyse Trivy
create_database()

def count_severity_vuln(severity: str):
    """
    Get Number of a specific severity.
    """
    conn = connect('trivy_backend.db')
    cursor = conn.cursor()
    query = f'SELECT COUNT(*) FROM Vulnerability WHERE Severity = "{severity}"'
    cursor.execute(query)
    count = cursor.fetchone()[0]
    conn.close()

    return count

severities = ['High', 'Medium', 'Low', 'Unknown']

#for severity in severities:
#    print(f'{severity}: {count_severity_vuln(severity.upper())}')


conn = connect('trivy_backend.db')
cursor = conn.cursor()
all_high_query = f'SELECT * FROM Vulnerability WHERE Severity = "HIGH"'
cursor.execute(all_high_query)
trivy_high = cursor.fetchall()
conn.close()


trivy_high_linux_kernel = set()
trivy_high_set = set()

pattern = compile(r'In the Linux kernel')

for i in trivy_high:
    info = i[2]
    if pattern.search(info):
        trivy_high_linux_kernel.add(i[0])

# Manual checked CVE, adding to trivy_high_linux_kernel
trivy_high_linux_kernel.add('CVE-2024-23307')
trivy_high_linux_kernel.add('CVE-2024-21803')
trivy_high_linux_kernel.add('CVE-2024-0841')
trivy_high_linux_kernel.add('CVE-2023-6270')
trivy_high_linux_kernel.add('CVE-2023-2176')
trivy_high_linux_kernel.add('CVE-2021-3847')
trivy_high_linux_kernel.add('CVE-2013-7445')
trivy_high_linux_kernel.add('CVE-2021-3864')

for i in trivy_high:
    trivy_high_set.add(i[0])

print(f'Trivy High - Linux Kernel: {trivy_high_set.difference(trivy_high_linux_kernel)}')


python = loader.trivy('json_trivy/python.json')
backend = loader.trivy('json_trivy/backend.json')

venn2((backend, python), set_labels=('Backend', 'Python'))
plt.title('Backend vs. Python')
plt.savefig('img/backend_vs_python.png')
plt.clf()