import os
import re
import sys
import json
import argparse
from shutil import copyfile
from itertools import chain
from logging import getLogger, ERROR as LOGERROR
from stix2 import datastore, Filter
from requests import exceptions
sys.path.append(os.path.dirname(os.path.abspath(__file__).replace('.github/workflows/scripts', '')))
from attack_taxii_client import attack_client

getLogger("taxii2client").setLevel(LOGERROR)

FILE_PATH_EDITOR_DATA = '../../../editor/src/data/'
FILE_PATH_CLI_DATA = '../../../data/'
FILE_PATH_EDITOR_CONSTANTS = '../../../editor/src/constants.js'
FILE_PATH_WIKI = '../../../wiki/'

FILE_DATA_SOURCES = 'data_sources.json'
FILE_TECHNIQUES = 'techniques.json'
FILE_SOFTWARE = 'software.json'
FILE_DATA_SOURCES_PLATFORMS = 'data_source_platforms.json'

FILE_WIKI_DATA_SOURCE_PLATFORMS = 'Data-sources-per-platform.md'

MATRIX_ENTERPRISE = 'mitre-attack'
MATRIX_ICS = 'mitre-ics-attack'
MATRIX_MOBILE = 'mitre-mobile-attack'

WIKI_TEXT_START = ['**Content:**', '- [Enterprise](#enterprise)', '- [Mobile](#mobile)', '- [ICS](#ics)', '', '']
WIKI_TEXT_ENTERPRISE = ['## Enterprise',
                        ''
                        'The below mapping from data sources/data components to platforms is created on the information provided by MITRE within the [data source objects](https://attack.mitre.org/datasources/). Also, note that the below is only listing data components that are actually referenced by a technique. Therefore it does not include all data components as referenced in the STIX repository.',
                        '']
WIKI_TEXT_ICS = ['',
                 '## ICS',
                 '',
                 '**Official platform mapping is missing**',
                 '',
                 'An official mapping for ICS sources/data components to platforms is currently missing. Since v14 release of ATT&CK platforms are not being used anymore for ICS. Therefor we cannot generate data source - platform mappings for ICS.',
                 '',
                 'As we do not consider ourselves experts in the field of ICS, we have not included the DeTT&CT data sources. Any help and thus contributions on that matter are very much appreciated. *Possibly, with future developments of ATT&CK ICS, we could automate this part when Detection objects are introduced. However, it is not certain whether this will provide good results.*']
WIKI_TEXT_MOBILE = ['',
                    '## Mobile',
                    '',
                    'The below mapping from data sources/data components to platforms is created on the information provided by MITRE within the [data source objects](https://attack.mitre.org/datasources/). Also, note that the below is only listing data components that are actually referenced by a technique. Therefore it does not include all data components as referenced in the STIX repository.',
                    '',
                    'At this moment we do not have any DeTT&CT data sources for Mobile. If there is a need or if you do have a suggestion, we will look into this.'
                    ]

class ATTACKData():
    """
    Refresh the json data files for the DeTT&CT Editor and CLI
    """

    def __init__(self, local_stix_path):
        try:
            if local_stix_path is not None:
                self.mitre = attack_client(local_path=local_stix_path)
            else:
                self.mitre = attack_client()
        except (exceptions.ConnectionError, datastore.DataSourceError):
            print("[!] Cannot connect to MITRE's TAXII server")
            quit()
        
        self.attack_data_components_enterprise = self.mitre.get_enterprise_data_components()
        self.attack_data_components_mobile = self.mitre.get_mobile_data_components()
        self.attack_data_components_ics = self.mitre.get_ics_data_components()
        self.attack_data_components_enterprise_ids = {dc['id']: dc for dc in self.attack_data_components_enterprise}
        self.attack_data_components_mobile_ids = {dc['id']: dc for dc in self.attack_data_components_mobile}
        self.attack_data_components_ics_ids = {dc['id']: dc for dc in self.attack_data_components_ics}

        self.attack_detection_strategies_enterprise = self.mitre.get_enterprise_detection_strategies(False)
        self.attack_detection_strategies_mobile = self.mitre.get_mobile_detection_strategies(False)
        self.attack_detection_strategies_ics = self.mitre.get_ics_detection_strategies(False)
        self.attack_detection_strategies_enterprise_ids = {ds['id']: ds for ds in self.attack_detection_strategies_enterprise}
        self.attack_detection_strategies_mobile_ids = {ds['id']: ds for ds in self.attack_detection_strategies_mobile}
        self.attack_detection_strategies_ics_ids = {ds['id']: ds for ds in self.attack_detection_strategies_ics}

        self.attack_analytics_enterprise = self.mitre.get_enterprise_analytics(False)
        self.attack_analytics_mobile = self.mitre.get_mobile_analytics(False)
        self.attack_analytics_ics = self.mitre.get_ics_analytics(False)
        self.attack_analytics_enterprise_ids = {a['id']: a for a in self.attack_analytics_enterprise}
        self.attack_analytics_mobile_ids = {a['id']: a for a in self.attack_analytics_mobile}
        self.attack_analytics_ics_ids = {a['id']: a for a in self.attack_analytics_ics}

        self.attack_techniques_enterprise = self.mitre.get_enterprise_techniques()
        self.attack_techniques_mobile = self.mitre.get_mobile_techniques()
        self.attack_techniques_ics = self.mitre.get_ics_techniques()

        self.data_component_dict_enterprise = self._create_data_component_dict(MATRIX_ENTERPRISE, self.attack_data_components_enterprise_ids, self.attack_analytics_enterprise)
        self.data_component_dict_mobile = self._create_data_component_dict(MATRIX_MOBILE, self.attack_data_components_mobile_ids, self.attack_analytics_mobile)
        self.data_component_dict_ics = self._create_data_component_dict(MATRIX_ICS, self.attack_data_components_ics_ids, self.attack_analytics_ics)

        self.attack_software = self.mitre.get_software()

    def execute_refresh_json_data(self):
        """
        Execute all methods to refresh all json data files for data components, techniques and software
        """
        # ###
        # update 'data_sources.json'
        data_components_enterprise = self._get_data_components_sorted(self.data_component_dict_enterprise)
        self._update_data(data_components_enterprise, 'ATT&CK-Enterprise', FILE_DATA_SOURCES)

        data_components_ics = self._get_data_components_sorted(self.data_component_dict_ics)
        self._update_data(data_components_ics, 'ATT&CK-ICS', FILE_DATA_SOURCES)

        data_components_mobile = self._get_data_components_sorted(self.data_component_dict_mobile)
        self._update_data(data_components_mobile, 'ATT&CK-Mobile', FILE_DATA_SOURCES)

        # ###
        # update 'data_source_platforms.json'
        data_components_enterprise_platform_mapping = self._get_data_components_platform_mapping_from_dict(self.data_component_dict_enterprise)
        self._update_data(data_components_enterprise_platform_mapping, 'ATT&CK-Enterprise', FILE_DATA_SOURCES_PLATFORMS)

        data_components_ics_platform_mapping = self._get_data_components_platform_mapping_from_dict(self.data_component_dict_ics)
        self._update_data(data_components_ics_platform_mapping, 'ATT&CK-ICS', FILE_DATA_SOURCES_PLATFORMS, skip_cli=False)

        data_components_mobile_platform_mapping = self._get_data_components_platform_mapping_from_dict(self.data_component_dict_mobile)
        self._update_data(data_components_mobile_platform_mapping, 'ATT&CK-Mobile', FILE_DATA_SOURCES_PLATFORMS, skip_cli=False)

        # ###
        # update 'techniques.json'
        techniques_enterprise = self._get_techniques(self.attack_techniques_enterprise, MATRIX_ENTERPRISE)
        self._update_data(techniques_enterprise, 'ATT&CK-Enterprise', FILE_TECHNIQUES)

        techniques_ics = self._get_techniques(self.attack_techniques_ics, MATRIX_ICS)
        self._update_data(techniques_ics, 'ATT&CK-ICS', FILE_TECHNIQUES)

        techniques_mobile = self._get_techniques(self.attack_techniques_mobile, MATRIX_MOBILE)
        self._update_data(techniques_mobile, 'ATT&CK-Mobile', FILE_TECHNIQUES)

        # ###
        # update 'software.json'
        software_enterprise = self._get_software(self.attack_techniques_enterprise, MATRIX_ENTERPRISE)
        self._update_data(software_enterprise, 'ATT&CK-Enterprise', FILE_SOFTWARE)

        software_ics = self._get_software(self.attack_techniques_ics, MATRIX_ICS)
        self._update_data(software_ics, 'ATT&CK-ICS', FILE_SOFTWARE)

        software_mobile = self._get_software(self.attack_techniques_mobile, MATRIX_MOBILE)
        self._update_data(software_mobile, 'ATT&CK-Mobile', FILE_SOFTWARE)

    def execute_refresh_wiki(self):
        """
        Execute all methods to refresh this Wiki page 'Data-sources-per-platform.md'
        """
        markdown_lines = self._generate_markdown()
        self._write_to_wiki(markdown_lines, FILE_WIKI_DATA_SOURCE_PLATFORMS)

    def _get_platforms_constants(self, platforms_key):
        """
        Get the ATT&CK platforms from the provided kv pair in constants.js (used by the Editor)
        We only to this because we want to have the correct order which is already saved in the Editor
        :param platforms_key: value of the platforms key
        :return: list with ATT&CK platforms
        """
        with open(FILE_PATH_EDITOR_CONSTANTS, 'r') as f:
            data = f.read()
            platforms_str = re.search(platforms_key + r': \[.+\]', data).group(0)

        platforms_str = platforms_str.replace("'", '"')
        platforms_str = '{' + platforms_str + '}'
        platforms_str = platforms_str.replace(platforms_key, '"' + platforms_key + '"')

        platforms_json = json.loads(platforms_str)
        platforms = platforms_json[platforms_key][1:]  # remove 'all'

        return platforms

    def _generate_md_table(self, platforms):
        """
        Generate a markdown table
        :param platforms: ATT&CK platform list
        :return: markdown table
        """
        lines = []

        l1 = '| Data source | '
        for p in platforms:
            l1 += p + ' | '
        lines.append(l1)

        l2 = '|'
        for i in range(len(platforms) + 1):
            l2 += ' ---- |'
        lines.append(l2)

        return lines

    def _generate_markdown(self):
        """
        Generate the markdown for the Wiki page Data-sources-per-platform.md
        :return: markdown text in a list
        """
        md_lines = WIKI_TEXT_START

        # ###
        # first we generate the Enerprise wiki
        platforms = self._get_platforms_constants('PLATFORMS')

        md_lines += WIKI_TEXT_ENTERPRISE
        md_lines = md_lines + self._generate_md_table(platforms)

        # the first entries of the Markdown table will consist of the DeTT&CT data sources
        dds_json = None
        with open(FILE_PATH_CLI_DATA + FILE_DATA_SOURCES_PLATFORMS, 'r') as f:
            dds_json = json.load(f)['DeTT&CT-Enterprise']

        dds_per_platform = {}  # {dettect data source: set(platforms)}
        for p, ds in dds_json.items():
            for ds in ds:
                if ds not in dds_per_platform:
                    dds_per_platform[ds] = set()
                dds_per_platform[ds].add(p)

        for dds in sorted(dds_per_platform.keys()):
            dds_part_1 = dds.removesuffix(' [DeTT&CT data source]')
            url = 'DeTT&CT-data-sources#' + dds_part_1.replace(' ', '-')
            row = '| [' + dds_part_1 + '](' + url + ') *[DeTT&CT data source]* | '

            for p in platforms:
                if p in dds_per_platform[dds]:
                    row += ' X |'
                else:
                    row += '   |'

            md_lines.append(row)

        # add the ATT&CK data sources to the Markdown table
        for dc in self._get_data_components_sorted(self.data_component_dict_enterprise):
            url = self.data_component_dict_enterprise[dc]['wiki_url'] + '/#' + dc.replace(' ', '%20')
            row = '| [' + dc + '](' + url + ') | '

            for p in platforms:
                if p in self.data_component_dict_enterprise[dc]['platforms']:
                    row += ' X |'
                else:
                    row += '   |'

            md_lines.append(row)

        # ###
        # then we generate the Mobile wiki
        platforms = self._get_platforms_constants('PLATFORMS_MOBILE')

        md_lines += WIKI_TEXT_MOBILE
        md_lines = md_lines + self._generate_md_table(platforms)

        # add the ATT&CK data sources to the Markdown table
        for dc in self._get_data_components_sorted(self.data_component_dict_mobile):
            url = self.data_component_dict_mobile[dc]['wiki_url'] + '/#' + dc.replace(' ', '%20')
            row = '| [' + dc + '](' + url + ') | '

            for p in platforms:
                if p in self.data_component_dict_mobile[dc]['platforms']:
                    row += ' X |'
                else:
                    row += '   |'

            md_lines.append(row)

        # ###
        # time to generete the ICS wiki
        # platforms = self._get_platforms_constants('PLATFORMS_ICS')

        md_lines += WIKI_TEXT_ICS
        # md_lines = md_lines + self._generate_md_table(platforms)

        # for dc in self._get_data_components_sorted(self.data_component_dict_ics):
        #     url = self.data_component_dict_ics[dc]['wiki_url'] + '/#' + dc.replace(' ', '%20')
        #     row = '| [' + dc + '](' + url + ') | '

        #     for p in platforms:
        #         if p in self.data_component_dict_ics[dc]['platforms']:
        #             row += ' X |'
        #         else:
        #             row += '   |'

        #     md_lines.append(row)

        return md_lines

    def _update_data(self, data, key, filename, skip_cli=True):
        """
        Update the json data on disk
        :param data: the MITRE ATT&CK data to update
        :param key: the json kv pair to update / where to store the data
        :param filename: filename of the file written to disk
        :param skip_cli: do not copy this updated file to the CLI directory
        :return:
        """
        json_data = None
        with open(FILE_PATH_EDITOR_DATA + filename, 'r') as f:
            json_data = json.load(f)
            json_data[key] = data

        with open(FILE_PATH_EDITOR_DATA + filename, 'w') as f:
            json.dump(json_data, f, indent=2)

        if not skip_cli:
            # we also need this file in the CLI
            copyfile(FILE_PATH_EDITOR_DATA + filename, FILE_PATH_CLI_DATA + filename)

    def _write_to_wiki(self, text, filename):
        """
        Write the provided text to file to the Wiki
        :param text: the text in a list
        :param filename: filename of the file written to disk
        :return:
        """
        try:
            with open(FILE_PATH_WIKI + filename, 'w') as f:
                f.write('\n'.join(text))
        except Exception as e:
            print("Error writing wiki file. May be local environment? (%s)" % str(e))

    def _get_attack_id(self, technique, matrix):
        """
        Get the ATT&CK ID from the provided technique dict
        :param tech: a dictionary containing a single ATT&CK technique's STIX object
        :param matrix: ATT&CK Matrix
        :return: the technique ID or None if the technique is not matching the provided ATT&CK Matrix
        """
        for e in technique['external_references']:
            source_name = e.get('source_name', None)
            # return source_name
            if source_name == matrix or (matrix == 'mitre-ics-attack' and source_name == 'mitre-attack') or (matrix == 'mitre-mobile-attack' and source_name == 'mitre-attack'):
                return e['external_id']
        return None

    def _get_techniques(self, attack_techniques, matrix):
        """
        Gets all techniques and applicable platforms for the provided ATT&CK Matrix and make a dict.
        :param attack_techniques: a list with ATT&CK technique data
        :param matrix: ATT&CK Matrix
        :return: a list containing all techniques and applicable platforms
        """
        techniques = []
        for t in attack_techniques:
            id = self._get_attack_id(t, matrix)
            techniques.append({'technique_id': id,
                               'technique_name': t['name'],
                               'platforms': ['None'] if 'x_mitre_platforms' not in t.keys() else sorted(t['x_mitre_platforms']),
                               'autosuggest': id + ' - ' + t['name']})

        techniques = sorted(techniques, key=lambda t: t['technique_id'])
        return techniques

    def _get_data_components_platform_mapping_from_techniques(self, attack_techniques):
        """
        Gets all the data components mapped to platforms in the following structure: {platform: [data source, data source]}
        :param attack_techniques: a list with ATT&CK technique data
        :return: a dictionary with the structure: {platform: [data source, data source]}
        """
        ds_per_platform = {}

        for tech in attack_techniques:
            platforms = tech.get('x_mitre_platforms', [])
            data_components = tech.get('x_mitre_data_sources', [])
            data_components = [ds.split(':')[1][1:].lstrip().rstrip() for ds in data_components]

            for p in platforms:
                if p not in ds_per_platform:
                    ds_per_platform[p] = set()
                ds_per_platform[p].update(data_components)

        # transform the set to a list and sort the data sources
        for k, v, in ds_per_platform.items():
            ds_per_platform[k] = list(sorted(v))

        return ds_per_platform

    def _get_data_components_platform_mapping_from_dict(self, data_domponents_dict):
        """
        Gets all the data components mapped to platforms in the following structure: {platform: [data source, data source]}
        :param data_domponents_dict: a dict with the data components as created by the function _create_data_component_dict
        :return: a dictionary with the structure: {platform: [data component, data component, ...]}
        """
        platforms = set()
        for v in data_domponents_dict.values():
            platforms.update(v['platforms'])

        dc_per_platform = {}
        for p in sorted(platforms):
            dc_per_platform[p] = []
            for k, v in data_domponents_dict.items():
                if p in v['platforms']:
                    dc_per_platform[p].append(k)
            dc_per_platform[p].sort()

        return dc_per_platform

    def _get_data_components_sorted(self, data_components_dict):
        """
        Gets all the data components from the provided data components dict and sort it
        :param data_components_dict: a dict with the data components as created by the function _create_data_component_dict
        :return: a sorted list with data data components
        """
        data_components = []
        for k in data_components_dict.keys():
            data_components.append(k)

        return sorted(data_components)

    def _create_data_component_dict(self, matrix, attack_data_components_ids, attack_analytics):
        """
        Create a dictionary with only info on the data sources and components that we need
        :param matrix: ATT&CK Matrix
        :param attack_data_components_ids: ATT&CK data components
        :param attack_analytics: ATT&CK analytics
        :return: a dictionary with the structure: {data source: {data_components: [], platforms: [], wiki_url: ...}}
        """
        dc_dict = {}

        for analytic in attack_analytics:
            for ls in analytic.get('x_mitre_log_source_references', []):
                if ls['x_mitre_data_component_ref'] in attack_data_components_ids:
                    dc = attack_data_components_ids[ls['x_mitre_data_component_ref']]

                    if dc['name'] not in dc_dict.keys():
                        dc_dict[dc['name']] = {}
                        dc_dict[dc['name']]['platforms'] = set()
                        
                        # Add the ATT&CK Wiki URL
                        url = ''
                        for ex_ref in dc['external_references']:
                            if ex_ref['source_name'] == 'mitre-attack':
                                url = ex_ref['url']
                                break
                        dc_dict[dc['name']]['wiki_url'] = url
                    
                    dc_dict[dc['name']]['platforms'].update(set(analytic.get('x_mitre_platforms')))
                else:
                    print(f"Data component {ls['x_mitre_data_component_ref']} not defined in STIX. MITRE should fix this.")

        return dc_dict

    def _get_software(self, attack_techniques, matrix):
        """
        Get a list of dictionaries containing all software within ATT&CK
        :param attack_techniques: a dict with the technique data
        :param matrix: ATT&CK Matrix
        :return: a list containing all software and applicable platforms
        """

        software = []
        all_platforms = self._get_platforms(attack_techniques)

        for s in self.attack_software:
            platforms = set(s.get('x_mitre_platforms', list(all_platforms)))

            if len(all_platforms.intersection(platforms)) > 0:

                id = self._get_attack_id(s, matrix)
                if id:
                    software.append({'software_id': id,
                                     'software_name': s['name'],
                                     'platforms': sorted(list(platforms)),
                                     'autosuggest': id + ' - ' + s['name']})

        software = sorted(software, key=lambda s: s['software_id'])
        return software

    def _get_platforms(self, attack_techniques):
        """
        Retruns a set of all ATT&CK platforms
        :param attack_techniques: a dict with the CTI technique data
        :return: a set with all ATT&CK platforms
        """
        platforms = set()
        for t in attack_techniques:
            platforms.update(t.get('x_mitre_platforms', []))

        return platforms

    def _get_data_components_from_mitre(self, matrix):
        """
        Get all data component STIX objects from CTI for the provided ATT&CK Matrix
        :param matrix: ATT&CK Matrix
        :return: list of data component STIX objects
        """
        if matrix == MATRIX_ENTERPRISE:
            data_components = self.mitre.get_enterprise_data_components()
        elif matrix == MATRIX_ICS:
            data_components = self.mitre.get_ics_data_components()
        elif matrix == MATRIX_MOBILE:
            data_components = self.mitre.get_mobile_data_components()

        return data_components


if __name__ == "__main__":
    menu_parser = argparse.ArgumentParser()
    menu_parser.add_argument('--local-stix-path', help='Path to a local STIX ATT&CK repository')
    args = menu_parser.parse_args()
    
    if args.local_stix_path is not None and not os.path.isdir(os.path.join(args.local_stix_path, 'enterprise-attack')) \
                        and not os.path.isdir(os.path.join(args.local_stix_path, 'ics-attack')) \
                        and not os.path.isdir(os.path.join(args.local_stix_path, 'mobile-attack')):
        print(f'Not a valid local STIX path: {args.local_stix_path}')
        sys.exit(-1)
    
    attack_data = ATTACKData(args.local_stix_path)
    attack_data.execute_refresh_json_data()
    attack_data.execute_refresh_wiki()
