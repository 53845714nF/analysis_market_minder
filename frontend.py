"""
Comparison of the scanners in the frontend
"""
from matplotlib_venn import venn3, venn2
import matplotlib.pyplot as plt
from colorama import Fore, Style
from venn import venn
from loader import Loader

loader = Loader()
trivy = loader.trivy('json/trivy_frontend.json')
grype = loader.grype('json/grype_frontend.json')
snyk = loader.snyk('json/snyk_frontend.json')
scout = loader.scout('json/scout_frontend.json')
vesta = loader.vesta('json/vesta_frontend.json')

# Mächtigkeit der Mengen
print(Fore.GREEN + 'Mächtigkeit:' + Style.RESET_ALL)
print("Trivy: " + str(len(trivy)))
print("Grype: " + str(len(grype)))
print("Snyk:  " + str(len(snyk)))
print("Scout: " + str(len(scout)))
print("Vesta: " + str(len(vesta)))

# Teilmengen
print(Fore.GREEN + 'Teilmengen:' + Style.RESET_ALL)
print(f'Trive - Gype: {trivy.difference(grype)}')
print(f'Trive - Snyk: {trivy.difference(snyk)}')
print(f'Scout - Trive: {scout.difference(trivy)}')
print(f'Gryp - Snyk: {grype.difference(snyk)}')
print(f'Gryp - Scout: {grype.difference(scout)}')

# Plotten des Venn Diagramms
venn_trivy_grype_scout = venn3((trivy, grype, scout), set_labels=('Trivy', 'Grype/Snyk', 'Scout'))
plt.title('Frontend')
plt.savefig('img/frontend.png')
plt.clf()

sets = {
    'Trivy': trivy,
    'Grype/Snyk': grype,
    'Docker Scout': scout,
    'Vesta': vesta
}

venn(sets)
plt.savefig('img/frontend_all.png')
plt.clf()

# Filter severity from grype - scout
severity_map = {}

for vuln in grype.difference(scout):
    severity = loader.get_trivy_severity('json/trivy_frontend.json', vuln)
    if severity not in severity_map:
        severity_map[severity] = {'CVEs': [], 'count': 0}
    severity_map[severity]['CVEs'].append(vuln)
    severity_map[severity]['count'] += 1

print(Fore.GREEN + 'High CVEs from Grype - Scout:' + Style.RESET_ALL)
for severity, info in severity_map.items():
    if severity == 'HIGH':
        for i in info['CVEs']:
            print(f'{i} : {loader.get_trivy_description("json/trivy_frontend.json", i)}')

# Filter severity from trivy - grype
severity_map = {}

for vuln in trivy.difference(grype):
    severity = loader.get_trivy_severity('json/trivy_frontend.json', vuln)
    if severity not in severity_map:
        severity_map[severity] = {'CVEs': [], 'count': 0}
    severity_map[severity]['CVEs'].append(vuln)
    severity_map[severity]['count'] += 1

print(Fore.GREEN + 'Vulns from Trivy - Grype:' + Style.RESET_ALL)
for severity, info in severity_map.items():
        for i in info['CVEs']:
            print(f'{i}')

nginx = loader.trivy('json_trivy/nginx.json')
frontend = loader.trivy('json_trivy/frontend.json')

venn2((frontend, nginx), set_labels=('Frontend', 'Nginx'))
plt.title('Frontend vs. Nginx')
plt.savefig('img/frontend_vs_nginx.png')
plt.clf()

print(Fore.GREEN + 'Check Base Image:' + Style.RESET_ALL)
print(f'Frontend - Nginx: {frontend.difference(nginx)}')

# Vesta vs Trivy
venn_vesta_trivy = venn2((vesta, trivy), set_labels=('Vesta', 'Trivy'))
plt.title('Vesta vs. Trivy')
plt.savefig('img/vesta_vs_trivy_frontend.png')
plt.clf()

print(Fore.GREEN + 'CVEs von Trivy - Vesta:' + Style.RESET_ALL)
for i in vesta.difference(trivy):
    print(f'{loader.get_vesta_description("json/vesta_frontend.json", i)}')
