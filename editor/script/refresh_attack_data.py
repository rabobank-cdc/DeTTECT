import json
from attackcti import attack_client

FILE_DATA_SOURCES = 'data_sources.json'
FILE_TECHNIQUES = 'techniques.json'
FILE_SOFTWARE = 'software.json'
PLATFORMS = ['Windows', 'Linux', 'macOS', 'PRE', 'AWS', 'GCP', 'Azure', 'Azure AD', 'Office 365', 'SaaS', 'Network']


class ATTACKData():
    """
    Refresh the json data files for the DeTT&CT YAML GUI
    """

    def __init__(self):
        self.mitre = attack_client()
        self.attack_cti_techniques = self.mitre.get_enterprise_techniques()
        self.attack_cti_techniques = self.mitre.remove_revoked(self.attack_cti_techniques)
        self.attack_cti_techniques = self.mitre.remove_deprecated(self.attack_cti_techniques)
        self.attack_cti_software = self.mitre.get_software()
        self.attack_cti_software = self.mitre.remove_deprecated(self.attack_cti_software)

    def dump_data(self, data, filename):
        """
        Write the json data to disk
        :param data: the MITRE ATT&CK data to save
        :param filename: filename of the file written to disk
        """
        with open('../src/data/' + filename, 'w') as f:
            json.dump(data, f, indent=2)

    def execute_refresh(self):
        """
        Execute all methods to refresh all data
        """
        data_sources = self.get_all_mitre_data_sources()
        self.dump_data(data_sources, FILE_DATA_SOURCES)

        techniques = self.get_all_techniques()
        self.dump_data(techniques, FILE_TECHNIQUES)

        software = self.get_all_software()
        self.dump_data(software, FILE_SOFTWARE)

    def get_attack_id(self, tech):
        """
        Get the ATT&CK ID from the provided technique dict
        :param tech: a dictionary containing a ATT&CK technique
        :return: the technique ID
        """
        for e in tech['external_references']:
            source_name = e.get('source_name', None)
            # return source_name
            if source_name == 'mitre-attack':
                return e['external_id']

    def get_all_techniques(self):
        """
        Gets all enterprise techniques and applicable platforms and make a dict
        :return: a list containing all techniques and applicable platforms
        """

        techniques = []
        for t in self.attack_cti_techniques:
            id = self.get_attack_id(t)
            techniques.append({'technique_id': id,
                               'technique_name': t['name'],
                               'platforms': sorted(t['x_mitre_platforms']),
                               'autosuggest': id + ' - ' + t['name']})

        techniques = sorted(techniques, key=lambda t: t['technique_id'])
        return techniques

    def get_all_mitre_data_sources(self):
        """
        Gets all the data sources from the techniques and make a list.
        :return: a sorted list with all data sources
        """

        data_sources = []
        for t in self.attack_cti_techniques:
            if 'x_mitre_data_sources' in t.keys():
                for ds in t['x_mitre_data_sources']:
                    if ds not in data_sources:
                        data_sources.append(ds)
        return sorted(data_sources)

    def get_all_software(self):
        """
        Get a list of dictionaries containing all software within ATT&CK (for enterprise)
        :return: a list containing all software and applicable platforms
        """

        software = []
        all_enterprise_platforms = set(PLATFORMS)
        for s in self.attack_cti_software:
            platforms = set(s.get('x_mitre_platforms', PLATFORMS))

            if len(all_enterprise_platforms.intersection(platforms)) > 0:
                id = self.get_attack_id(s)
                software.append({'software_id': id,
                                 'software_name': s['name'],
                                 'platforms': sorted(list(platforms)),
                                 'autosuggest': id + ' - ' + s['name']})
        software = sorted(software, key=lambda s: s['software_id'])
        return software


if __name__ == "__main__":
    attack_data = ATTACKData()
    attack_data.execute_refresh()
