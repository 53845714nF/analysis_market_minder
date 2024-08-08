"""
Module to load CVEs from Json Files.
"""
from json import load
from re import search

class Loader:
    """
    Class for loading.
    """

    def trivy(self, filename: str) -> set:
        """
        Load Trivy
        """
        with open(filename, 'r', encoding='utf-8') as file:
            trivy = load(file)
        # pylint: disable=line-too-long
        return {vul['VulnerabilityID'] for result in trivy['Results'] for vul in result['Vulnerabilities']}

    def grype(self, filename: str) -> set:
        """
        Load Grype
        """
        with open(filename, 'r', encoding='utf-8') as file:
            grype = load(file)
        return {vul['vulnerability']['id'] for vul in grype['matches']}

    def snyk(self, filename: str) -> set:
        """
        Load Snyk
        """
        snyk_set = set()
        with open(filename, 'r', encoding='utf-8') as file:
            snyk = load(file)

        for vul in snyk['vulnerabilities']:
            if search("^CVE.*", vul['identifiers']['CVE'][0]):
                snyk_set.add(vul['identifiers']['CVE'][0])
        return snyk_set

    def scout(self, filename: str) -> set:
        """
        Load Docker Scout
        """
        scout_set = set()
        with open(filename, 'r', encoding='utf-8') as file:
            scout = load(file)

        for vul in scout['runs'][0]['results']:
            scout_set.add(vul['ruleId'])
        return scout_set

    def vesta(self, filename: str) -> set:
        """
        Load Vesta
        """
        vesta_set = set()
        with open(filename, 'r', encoding='utf-8') as file:
            vesta = load(file)

        for vul in vesta:
            vesta_set.add(vul['CVEID'])
        return vesta_set

    def get_trivy_severity(self, filename: str, search_vul: str) -> str:
        """
        Get the severity for a CVE from a Trivy File
        """
        with open(filename, 'r', encoding='utf-8') as file:
            database = load(file)

        # pylint: disable=line-too-long
        return next((vul['Severity'] for result in database['Results'] for vul in result['Vulnerabilities'] if vul['VulnerabilityID'] == search_vul), None)

    def get_vesta_description(self, filename: str, search_vul: str) -> str:
        """
        Get the description for a CVE from a Vesta File
        """
        with open(filename, 'r', encoding='utf-8') as file:
            database = load(file)

        for vul in database:
            if vul['CVEID'] == search_vul:
                cve = vul['CVEID']
                name = vul['Name']
                severity = vul['Level']
                description = vul['Desc']

                return f"{cve} {name} : {severity} {description}"
        return ""

    def get_trivy_description(self, filename: str, search_vul: str) -> str:
        """
        Get the description for a CVE from a Trivy File
        """
        with open(filename, 'r', encoding='utf-8') as file:
            database = load(file)

        for result in database['Results']:
            for vul in result['Vulnerabilities']:
                if vul['VulnerabilityID'] == search_vul:
                    try:
                        return f'{vul["Description"]} From Package {vul["PkgName"]}.'
                    except KeyError:
                        return ''
        return ''
