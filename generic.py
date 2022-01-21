import os
import pickle
from datetime import datetime as dt
from io import StringIO
from ruamel.yaml import YAML
from ruamel.yaml.timestamp import TimeStamp as ruamelTimeStamp
from requests import exceptions
from stix2 import datastore
from constants import *
from upgrade import upgrade_yaml_file
from health import check_yaml_file_health
import dateutil.parser

# Due to performance reasons the import of attackcti is within the function that makes use of this library.

local_stix_path = None


def _save_attack_data(data, path):
    """
    Save ATT&CK data to disk for the purpose of caching. Data can be STIX objects our a custom schema.
    :param data: the MITRE ATT&CK data to save
    :param path: file path to write to, including filename
    :return:
    """

    if not os.path.exists('cache/'):
        os.mkdir('cache/')
    with open(path, 'wb') as f:
        pickle.dump([data, dt.now()], f)


def _date_hook(json_dict):
    """
    Parses STIX dates so that they can be used as date object in dictionaries. Function is used as object_hook function in the JSON serialize.
    :param json_dict: the dictionary with STIX data
    :return:
    """
    for (key, value) in json_dict.items():
        if key == 'created':
            json_dict['created'] = dateutil.parser.parse(value)
        elif key == 'modified':
            json_dict['modified'] = dateutil.parser.parse(value)
    return json_dict


def _convert_stix_techniques_to_dict(stix_attack_data):
    """
    Convert the STIX list with AttackPatterns to a dictionary for easier use in python and also include the technique_id and DeTT&CT data sources.
    :param stix_attack_data: the MITRE ATT&CK STIX dataset with techniques
    :return: list with dictionaries containing all techniques from the input stix_attack_data
    """
    attack_data = []
    for stix_tech in stix_attack_data:
        tech = json.loads(stix_tech.serialize(), object_hook=_date_hook)

        # Add technique_id as key, because it's hard to get from STIX:
        tech['technique_id'] = get_attack_id(stix_tech)

        # Create empty x_mitre_data_sources key for techniques without data sources:
        if 'x_mitre_data_sources' not in tech.keys():
            tech['x_mitre_data_sources'] = []

        dds_key = 'dettect_data_sources'
        tech[dds_key] = []
        for dds in DETTECT_DATA_SOURCES:
            if tech['technique_id'] == dds['technique_id']:
                # When a technique has just 1 DeTT&CT data source which is 'Network Traffic Content' then ignore this one. This means that we
                # evaluated if that technique needs a DeTT&CT data source but it has not.
                if not (len(dds[dds_key]) == 1 and dds[dds_key][0] == 'Network Traffic Content'):
                    tech[dds_key] = dds[dds_key]

                    # Remove 'Network Traffic Content' from x_mitre_data_sources when it's not listed as DeTT&CT data source. In this situation
                    # we are intentionally replacing the 'Network Traffic Content' with our DeTT&CT data sources.
                    if 'Network Traffic Content' not in dds[dds_key] and 'Network Traffic: Network Traffic Content' in tech['x_mitre_data_sources']:
                        tech['x_mitre_data_sources'].remove('Network Traffic: Network Traffic Content')

                    # Remove 'Network Traffic Content' from the DeTT&CT data sources list when having both DeTT&CT data sources ánd 'Network Traffic Content'.
                    # That's the case where we keep 'Network Traffic Content' in the x_mitre_data_sources list.
                    if 'Network Traffic Content' in dds[dds_key]:
                        tech[dds_key].remove('Network Traffic Content')
                break

        attack_data.append(tech)

    return attack_data


def _convert_stix_groups_to_dict(stix_attack_data):
    """
    Convert the STIX list with IntrusionSet to a dictionary for easier use in python and also include the group_id.
    :param stix_attack_data: the MITRE ATT&CK STIX dataset with groups
    :return: list with dictionaries containing all groups from the input stix_attack_data
    """
    attack_data = []
    for stix_tech in stix_attack_data:
        tech = json.loads(stix_tech.serialize(), object_hook=_date_hook)

        # Add group_id as key, because it's hard to get from STIX:
        tech['group_id'] = get_attack_id(stix_tech)

        attack_data.append(tech)

    return attack_data


def load_attack_data(data_type):
    """
    By default the ATT&CK data is loaded from the online TAXII server or from the local cache directory. The
    local cache directory will be used if the file is not expired (data file on disk is older then EXPIRE_TIME
    seconds). When the local_stix_path option is given, the ATT&CK data will be loaded from the given path of
    a local STIX repository.
    :param data_type: the desired data type, see DATATYPE_XX constants.
    :return: MITRE ATT&CK data object (STIX or custom schema)
    """
    from attackcti import attack_client
    if local_stix_path is not None:
        if local_stix_path is not None and os.path.isdir(os.path.join(local_stix_path, 'enterprise-attack')) \
                and os.path.isdir(os.path.join(local_stix_path, 'pre-attack')) \
                and os.path.isdir(os.path.join(local_stix_path, 'mobile-attack')):
            mitre = attack_client(local_path=local_stix_path)
        else:
            print('[!] Not a valid local STIX path: ' + local_stix_path)
            quit()
    else:
        if os.path.exists("cache/" + data_type):
            with open("cache/" + data_type, 'rb') as f:
                cached = pickle.load(f)
                write_time = cached[1]
                if not (dt.now() - write_time).total_seconds() >= EXPIRE_TIME:
                    # the first item in the list contains the ATT&CK data
                    return cached[0]
        try:
            mitre = attack_client()
        except (exceptions.ConnectionError, datastore.DataSourceError):
            print("[!] Cannot connect to MITRE's CTI TAXII server")
            quit()

    attack_data = None
    if data_type == DATA_TYPE_STIX_ALL_RELATIONSHIPS:
        attack_data = mitre.get_relationships()
    elif data_type == DATA_TYPE_STIX_ALL_TECH_ENTERPRISE:
        stix_attack_data = mitre.get_enterprise_techniques()
        attack_data = _convert_stix_techniques_to_dict(stix_attack_data)
    elif data_type == DATA_TYPE_STIX_ALL_TECH_ICS:
        stix_attack_data = mitre.get_ics_techniques()
        attack_data = _convert_stix_techniques_to_dict(stix_attack_data)
    elif data_type == DATA_TYPE_CUSTOM_TECH_BY_GROUP:
        # First we need to know which technique references (STIX Object type 'attack-pattern') we have for all
        # groups. This results in a dict: {group_id: Gxxxx, technique_ref/attack-pattern_ref: ...}
        groups = load_attack_data(DATA_TYPE_STIX_ALL_GROUPS)
        relationships = load_attack_data(DATA_TYPE_STIX_ALL_RELATIONSHIPS)
        all_groups_relationships = []
        for g in groups:
            for r in relationships:
                if g['id'] == r['source_ref'] and r['relationship_type'] == 'uses' and \
                        r['target_ref'].startswith('attack-pattern--'):
                    # much more information on the group can be added. Only the minimal required data is now added.
                    all_groups_relationships.append(
                        {
                            'group_id': get_attack_id(g),
                            'name': g['name'],
                            'aliases': g.get('aliases', None),
                            'technique_ref': r['target_ref']
                        })

        # Now we start resolving this part of the dict created above: 'technique_ref/attack-pattern_ref'.
        # and we add some more data to the final result.
        all_group_use = []
        techniques = load_attack_data(DATA_TYPE_STIX_ALL_TECH)
        for gr in all_groups_relationships:
            for t in techniques:
                if t['id'] == gr['technique_ref']:
                    all_group_use.append(
                        {
                            'group_id': gr['group_id'],
                            'name': gr['name'],
                            'aliases': gr['aliases'],
                            'technique_id': get_attack_id(t),
                            'x_mitre_platforms': t.get('x_mitre_platforms', None),
                            'matrix': t['external_references'][0]['source_name']
                        })

        attack_data = all_group_use

    elif data_type == DATA_TYPE_STIX_ALL_TECH:
        stix_attack_data = mitre.get_techniques()
        attack_data = _convert_stix_techniques_to_dict(stix_attack_data)
    elif data_type == DATA_TYPE_STIX_ALL_GROUPS:
        stix_attack_data = mitre.get_groups()
        attack_data = _convert_stix_groups_to_dict(stix_attack_data)
    elif data_type == DATA_TYPE_STIX_ALL_SOFTWARE:
        attack_data = mitre.get_software()
    elif data_type == DATA_TYPE_CUSTOM_TECH_BY_SOFTWARE:
        # First we need to know which technique references (STIX Object type 'attack-pattern') we have for all software
        # This results in a dict: {software_id: Sxxxx, technique_ref/attack-pattern_ref: ...}
        software = load_attack_data(DATA_TYPE_STIX_ALL_SOFTWARE)
        relationships = load_attack_data(DATA_TYPE_STIX_ALL_RELATIONSHIPS)
        all_software_relationships = []
        for s in software:
            for r in relationships:
                if s['id'] == r['source_ref'] and r['relationship_type'] == 'uses' and \
                        r['target_ref'].startswith('attack-pattern--'):
                    # much more information (e.g. description, aliases, platform) on the software can be added to the
                    # dict if necessary. Only the minimal required data is now added.
                    all_software_relationships.append({'software_id': get_attack_id(s), 'technique_ref': r['target_ref']})

        # Now we start resolving this part of the dict created above: 'technique_ref/attack-pattern_ref'
        techniques = load_attack_data(DATA_TYPE_STIX_ALL_TECH)
        all_software_use = []
        for sr in all_software_relationships:
            for t in techniques:
                if t['id'] == sr['technique_ref']:
                    # much more information on the technique can be added to the dict. Only the minimal required data
                    # is now added (i.e. resolving the technique ref to an actual ATT&CK ID)
                    all_software_use.append({'software_id': sr['software_id'], 'technique_id': get_attack_id(t)})

        attack_data = all_software_use

    elif data_type == DATA_TYPE_CUSTOM_SOFTWARE_BY_GROUP:
        # First we need to know which software references (STIX Object type 'malware' or 'tool') we have for all
        # groups. This results in a dict: {group_id: Gxxxx, software_ref/malware-tool_ref: ...}
        groups = load_attack_data(DATA_TYPE_STIX_ALL_GROUPS)
        relationships = load_attack_data(DATA_TYPE_STIX_ALL_RELATIONSHIPS)
        all_groups_relationships = []
        for g in groups:
            for r in relationships:
                if g['id'] == r['source_ref'] and r['relationship_type'] == 'uses' and \
                        (r['target_ref'].startswith('tool--') or r['target_ref'].startswith('malware--')):
                    # much more information on the group can be added. Only the minimal required data is now added.
                    all_groups_relationships.append(
                        {
                            'group_id': get_attack_id(g),
                            'name': g['name'],
                            'aliases': g.get('aliases', None),
                            'software_ref': r['target_ref']
                        })

        # Now we start resolving this part of the dict created above: 'software_ref/malware-tool_ref'.
        # and we add some more data to the final result.
        all_group_use = []
        software = load_attack_data(DATA_TYPE_STIX_ALL_SOFTWARE)
        for gr in all_groups_relationships:
            for s in software:
                if s['id'] == gr['software_ref']:
                    all_group_use.append(
                        {
                            'group_id': gr['group_id'],
                            'name': gr['name'],
                            'aliases': gr['aliases'],
                            'software_id': get_attack_id(s),
                            'x_mitre_platforms': s.get('x_mitre_platforms', None),
                            'matrix': s['external_references'][0]['source_name']
                        })
        attack_data = all_group_use

    elif data_type == DATA_TYPE_STIX_ALL_ENTERPRISE_MITIGATIONS:
        attack_data = mitre.get_enterprise_mitigations()
        attack_data = mitre.remove_revoked_deprecated(attack_data)

    elif data_type == DATA_TYPE_STIX_ALL_MOBILE_MITIGATIONS:
        attack_data = mitre.get_mobile_mitigations()
        attack_data = mitre.remove_revoked_deprecated(attack_data)

    elif data_type == DATA_TYPE_STIX_ALL_ICS_MITIGATIONS:
        attack_data = mitre.get_ics_mitigations()
        attack_data = mitre.remove_revoked_deprecated(attack_data)

    # Only use cache when using online TAXII server:
    if local_stix_path is None:
        _save_attack_data(attack_data, "cache/" + data_type)

    return attack_data


def init_yaml():
    """
    Initialize ruamel.yaml with the correct settings
    :return: am uamel.yaml object
    """
    _yaml = YAML()
    _yaml.Representer.ignore_aliases = lambda *args: True  # disable anchors/aliases
    return _yaml


def get_attack_id(stix_obj):
    """
    Get the Technique, Group or Software ID from the STIX object
    :param stix_obj: STIX object (Technique, Software or Group)
    :return: ATT&CK ID
    """
    for ext_ref in stix_obj['external_references']:
        if ext_ref['source_name'] in ['mitre-attack', 'mitre-mobile-attack', 'mitre-ics-attack']:
            return ext_ref['external_id']


def get_tactics(technique):
    """
    Get all tactics from a given technique
    :param technique: technique STIX object
    :return: list with tactics
    """
    tactics = []
    if 'kill_chain_phases' in technique:
        for phase in technique['kill_chain_phases']:
            tactics.append(phase['phase_name'])

    return tactics


def get_technique(techniques, technique_id):
    """
    Generic function to lookup a specific technique_id in a list of dictionaries with techniques.
    :param techniques: list with all techniques
    :param technique_id: technique_id to look for
    :return: the technique you're searching for. None if not found.
    """
    for tech in techniques:
        if technique_id == get_attack_id(tech):
            return tech
    return None


def ask_yes_no(question):
    """
    Ask the user to a question that needs to be answered with yes or no.
    :param question: The question to be asked
    :return: boolean value indicating a yes (True) or no (False0
    """
    yes_no = ''
    while not re.match('^(y|yes|n|no)$', yes_no, re.IGNORECASE):
        yes_no = input(question + '\n >>   y(yes) / n(no): ')
        print('')

    if re.match('^(y|yes)$', yes_no, re.IGNORECASE):
        return True
    else:
        return False


def ask_multiple_choice(question, list_answers):
    """
    Ask a multiple choice question.
    :param question: the question to ask
    :param list_answers: a list of answer
    :return: the answer
    """
    answer = ''
    answers = ''
    x = 1
    for a in list_answers:
        a = a.replace('\n', '\n     ')
        answers += '  ' + str(x) + ') ' + a + '\n'
        x += 1

    # noinspection Annotator
    while not re.match('(^[1-' + str(len(list_answers)) + ']{1}$)', answer):
        print(question)
        print(answers)
        answer = input(' >>   ')
        print('')

    return int(answer)


def fix_date_and_remove_null(yaml_file, date, input_type='ruamel'):
    """
    Remove the single quotes around the date key-value pair in the provided yaml_file and remove any 'null' values
    :param yaml_file: ruamel.yaml instance or location of YAML file
    :param date: string date value (e.g. 2019-01-01)
    :param input_type: input type can be a ruamel.yaml instance or list
    :return: YAML file lines in a list
    """
    _yaml = init_yaml()
    if input_type == 'ruamel':
        # ruamel does not support output to a variable. Therefore we make use of StringIO.
        file = StringIO()
        _yaml.dump(yaml_file, file)
        file.seek(0)
        new_lines = file.readlines()
    elif input_type == 'list':
        new_lines = yaml_file
    elif input_type == 'file':
        new_lines = yaml_file.readlines()

    fixed_lines = [l.replace('\'' + str(date) + '\'', str(date)).replace('null', '')
                   if REGEX_YAML_DATE.match(l) else
                   l.replace('null', '') for l in new_lines]

    return fixed_lines


def get_latest_score_obj(yaml_object):
    """
    Get the the score object in the score_logbook by date
    :param yaml_object: a detection or visibility YAML object
    :return: the latest score object
    """
    if not isinstance(yaml_object['score_logbook'], list):
        yaml_object['score_logbook'] = [yaml_object['score_logbook']]

    if len(yaml_object['score_logbook']) > 0 and 'date' in yaml_object['score_logbook'][0]:
        # for some weird reason 'sorted()' provides inconsistent results
        newest_score_obj = None
        newest_date = None
        for score_obj in yaml_object['score_logbook']:
            score_obj_date = score_obj['date']

            if not newest_score_obj or (score_obj_date and score_obj_date > newest_date):
                newest_date = score_obj_date
                newest_score_obj = score_obj

        return newest_score_obj
    else:
        return None


def get_latest_comment(yaml_object):
    """
    Return the latest comment present in the score_logbook
    :param yaml_object: a detection or visibility YAML object
    :return: comment
    """
    score_obj = get_latest_score_obj(yaml_object)
    if score_obj:
        if score_obj['comment'] == '' or not score_obj['comment']:
            return ''
        else:
            return score_obj['comment']
    else:
        return ''


def get_latest_date(yaml_object):
    """
    Return the latest date present in the score_logbook
    :param yaml_object: a detection or visibility YAML object
    :return: date as a datetime object or None
    """
    score_obj = get_latest_score_obj(yaml_object)
    if score_obj:
        return score_obj['date']
    else:
        return None


def get_latest_auto_generated(yaml_object):
    """
    Return the latest auto_generated value present in the score_logbook
    :param yaml_object: a visibility YAML object
    :return: True or False
    """
    score_obj = get_latest_score_obj(yaml_object)
    if score_obj:
        if 'auto_generated' in score_obj:
            return score_obj['auto_generated']
        else:
            return False
    else:
        return False


def get_latest_score(yaml_object):
    """
    Return the latest score present in the score_logbook
    :param yaml_object: a detection or visibility YAML object
    :return: score as an integer or None
    """
    score_obj = get_latest_score_obj(yaml_object)
    if score_obj:
        return score_obj['score']
    else:
        return None


def platform_to_name(platform, domain, separator='-'):
    """
    Makes a filename friendly version of the platform parameter which can be a string or list.
    :param platform: the platform variable (a string or a list)
    :param domain: the specified domain
    :param separator: a string value that separates multiple platforms. Default is '-'
    :return: a filename friendly representation of the value of platform
    """
    platforms = PLATFORMS_ENTERPRISE if domain == 'enterprise-attack' else PLATFORMS_ICS
    if set(platform) == set(platforms.values()) or platform == 'all' or 'all' in platform:
        return 'all'
    elif isinstance(platform, list):
        return separator.join(sorted(platform))
    else:
        return ''


def get_applicable_data_sources_platform(platforms, domain):
    """
    Get the applicable ATT&CK data sources for the provided platform(s)
    :param platforms: the ATT&CK platform(s)
    :param domain: the specified domain
    :return: a list of applicable ATT&CK data sources
    """
    applicable_data_sources = set()

    data_sources = DATA_SOURCES_ENTERPRISE if domain == 'enterprise-attack' else DATA_SOURCES_ICS
    for p in platforms:
        applicable_data_sources.update(data_sources[p])

    return list(applicable_data_sources)


def get_applicable_dettect_data_sources_platform(platforms, domain):
    """
    Get the applicable DeTT&CT data sources for the provided platform(s)
    :param platforms: the ATT&CK platform(s)
    :param domain: the specified domain
    :return: a list of applicable ATT&CK data sources
    """
    applicable_dettect_data_sources = set()

    dettect_data_sources = DETTECT_DATA_SOURCES_PLATFORMS_ENTERPRISE if domain == 'enterprise-attack' else DETTECT_DATA_SOURCES_PLATFORMS_ICS
    for p in platforms:
        applicable_dettect_data_sources.update(dettect_data_sources[p])

    return list(applicable_dettect_data_sources)


def get_applicable_data_sources_technique(technique_data_sources, platform_applicable_data_sources):
    """
    Get the applicable ATT&CK data sources for the provided technique's data sources (for which the source is ATT&CK CTI)
    :param technique_data_sources: the ATT&CK technique's data sources
    :param platform_applicable_data_sources: a list of applicable ATT&CK data sources based on 'DATA_SOURCES'
    :return: a list of applicable data sources
    """
    applicable_data_sources = set()

    for ds in technique_data_sources:
        if ':' in ds:  # the param technique_data_sources comes from STIX
            ds = ds.split(':')[1][1:]
        if ds in platform_applicable_data_sources:
            applicable_data_sources.add(ds)

    return list(applicable_data_sources)


def get_applicable_dettect_data_sources_technique(technique_dettect_data_sources, platform_applicable_dettect_data_sources):
    """
    Get the applicable DeTT&CT data sources for the provided technique's DeTT&CT data sources.
    :param technique_data_sources: the ATT&CK technique's DeTT&CT data sources
    :param platform_applicable_data_sources: a list of applicable DeTT&CT data sources based on 'DETTECT_DATA_SOURCES_PLATFORMS'
    :return: a list of applicable data sources
    """
    applicable_dettect_data_sources = set()

    for ds in technique_dettect_data_sources:
        if ds in platform_applicable_dettect_data_sources:
            applicable_dettect_data_sources.add(ds)

    return list(applicable_dettect_data_sources)


def _check_data_quality(data_quality, filter_empty_scores):
    """
    Checks if at least one of the data quality dimensions is greater than 0, and therefore is considered to be available.
    :param data_quality: data source data quality YAML object.
    :param filter_empty_scores: set the data source as available if set to 'False' despite its data quality.
    :return: True if the data source is available otherwise False.
    """
    if not filter_empty_scores:
        return True
    elif data_quality['device_completeness'] > 0 or data_quality['data_field_completeness'] > 0 or \
            data_quality['timeliness'] > 0 or data_quality['consistency'] > 0 or data_quality['retention'] > 0:
        return True


def load_data_sources(file, filter_empty_scores=True):
    """
    Loads the data sources (including all properties) from the given YAML file.
    :param file: the file location of the YAML file containing the data sources administration or a dict.
    :param filter_empty_scores: include all data source details objects if set to False despite the data quality.
    :return: dictionary with data sources, name, systems and exceptions list.
    """
    my_data_sources = {}

    if isinstance(file, dict):
        # file is a dict created due to the use of an EQL query by the user
        yaml_content = file
    else:
        # file is a file location on disk
        _yaml = init_yaml()
        with open(file, 'r') as yaml_file:
            yaml_content = _yaml.load(yaml_file)

    # we have todo this in two phases to bring the 'systems' kv-pair applicable_to values in sync with the data sources details object's applicable_to values
    # phase 1:
    #  - keep data sources which are enabled (DQ check)
    #  - add the data source to a dictionary we can iterate over more easily (my_data_sources)
    for ds_global in yaml_content['data_sources']:
        if isinstance(ds_global['data_source'], dict):  # There is just one data source entry
            if _check_data_quality(ds_global['data_source']['data_quality'], filter_empty_scores):
                _add_entry_to_list_in_dictionary(my_data_sources, ds_global['data_source_name'], 'data_source', ds_global['data_source'])
        elif isinstance(ds_global['data_source'], list):  # There are multiple data source entries
            for ds_details in ds_global['data_source']:
                if _check_data_quality(ds_details['data_quality'], filter_empty_scores):
                    _add_entry_to_list_in_dictionary(my_data_sources, ds_global['data_source_name'], 'data_source', ds_details)

    # phase 2:
    # - put all system's applicable_to values into a list (all_systems_applicable_to) and only keep:
    #   * not equal to 'all' (because it's a hardcoded value which translates to all applicable_to values from the data source details objects)
    # - iterate over all data sources details objects and replace 'all' with all_systems_applicable_to
    systems = yaml_content['systems']
    systems = [k for k in systems if k['applicable_to'].lower() != 'all']

    all_systems_applicable_to = [k['applicable_to'] for k in systems]

    for k, v in my_data_sources.items():
        for ds_detail in v['data_source']:
            if 'all' in [a.lower() for a in ds_detail['applicable_to'] if a is not None]:
                ds_detail['applicable_to'] = all_systems_applicable_to
            ds_detail = set_yaml_dv_comments(ds_detail)

    domain = 'enterprise' if 'domain' not in yaml_content.keys() else yaml_content['domain']

    # make sure the platform values are compliant (including casing) with the ATT&CK platforms
    platforms = PLATFORMS_ENTERPRISE if domain == 'enterprise-attack' else PLATFORMS_ICS
    for s in systems:
        s['platform'] = [p.lower() for p in s['platform'] if p is not None]
        if 'all' in s['platform']:
            s['platform'] = list(platforms.values())
        else:
            valid_platform_list = []
            for p in s['platform']:
                if p in platforms.keys():
                    valid_platform_list.append(platforms[p])
            s['platform'] = valid_platform_list

    exceptions = []
    if 'exceptions' in yaml_content:
        exceptions = [t['technique_id'].upper() for t in yaml_content['exceptions'] if t['technique_id'] is not None]

    name = yaml_content['name']

    return my_data_sources, name, systems, exceptions, domain


def load_techniques(file):
    """
    Loads the techniques (including detection and visibility properties).
    :param file: the file location of the YAML file or a dict containing the techniques administration
    :return: dictionary with techniques (incl. properties), name and platform
    """
    my_techniques = {}

    if isinstance(file, dict):
        # file is a dict and created due to the use of an EQL query by the user
        yaml_content = file
    else:
        # file is a file location on disk
        _yaml = init_yaml()
        with open(file, 'r') as yaml_file:
            yaml_content = _yaml.load(yaml_file)

    yaml_content = _traverse_modify_date(yaml_content)

    for d in yaml_content['techniques']:
        if 'detection' in d:
            # Add detection items:
            if isinstance(d['detection'], dict):  # There is just one detection entry
                d['detection'] = set_yaml_dv_comments(d['detection'])
                _add_entry_to_list_in_dictionary(my_techniques, d['technique_id'], 'detection', d['detection'])
            elif isinstance(d['detection'], list):  # There are multiple detection entries
                for de in d['detection']:
                    de = set_yaml_dv_comments(de)
                    _add_entry_to_list_in_dictionary(my_techniques, d['technique_id'], 'detection', de)

        if 'visibility' in d:
            # Add visibility items
            if isinstance(d['visibility'], dict):  # There is just one visibility entry
                d['visibility'] = set_yaml_dv_comments(d['visibility'])
                _add_entry_to_list_in_dictionary(my_techniques, d['technique_id'], 'visibility', d['visibility'])
            elif isinstance(d['visibility'], list):  # There are multiple visibility entries
                for de in d['visibility']:
                    de = set_yaml_dv_comments(de)
                    _add_entry_to_list_in_dictionary(my_techniques, d['technique_id'], 'visibility', de)

    name = yaml_content['name']
    domain = 'enterprise' if 'domain' not in yaml_content.keys() else yaml_content['domain']
    platform = get_platform_from_yaml(yaml_content, domain)

    return my_techniques, name, platform, domain


def calculate_score(list_yaml_objects, zero_value=0):
    """
    Calculates the average score in the given list which may contain multiple detection or visibility dictionaries
    :param list_yaml_objects: list of detection or visibility objects
    :param zero_value: the value when no scores are there, default 0
    :return: average score
    """
    avg_score = 0
    number = 0
    for v in list_yaml_objects:
        score = get_latest_score(v)
        if score is not None and score >= 0:
            avg_score += score
            number += 1

    avg_score = int(round(avg_score / number, 0) if number > 0 else zero_value)
    return avg_score


def _add_entry_to_list_in_dictionary(dictionary, key_dict, key_list, entry):
    """
    Ensures a list will be created if it doesn't exist in the given dict[key_dict][key_list] and adds the entry to the
    list. If the dict[key_dict] doesn't exist yet, it will be created.
    :param dictionary: the dictionary
    :param key_dict: the key name in de main dict
    :param key_list: the key name where the list in the dictionary resides
    :param entry: the entry to add to the list
    :return:
    """
    if key_dict not in dictionary.keys():
        dictionary[key_dict] = {}
    if key_list not in dictionary[key_dict].keys():
        dictionary[key_dict][key_list] = []
    dictionary[key_dict][key_list].append(entry)


def set_yaml_dv_comments(yaml_object):
    """
    Set all comments in the detection, visibility or data source details YAML object when the 'comment' key-value pair is missing or is None.
    This gives the user the flexibility to have YAML files with missing 'comment' key-value pairs.
    :param yaml_object: detection or visibility object
    :return: detection or visibility object for which empty comments are filled with an empty string
    """
    yaml_object['comment'] = yaml_object.get('comment', '')
    if yaml_object['comment'] is None:
        yaml_object['comment'] = ''
    if 'score_logbook' in yaml_object:
        for score_obj in yaml_object['score_logbook']:
            score_obj['comment'] = score_obj.get('comment', '')
            if score_obj['comment'] is None:
                score_obj['comment'] = ''

    return yaml_object


def traverse_dict(obj, callback=None):
    """
    Traverse all items in a dictionary
    :param obj: dictionary, list or value
    :param callback: a function that will be called to modify a value
    :return: value or call callback function
    """
    if isinstance(obj, dict):
        value = {k: traverse_dict(v, callback)
                 for k, v in obj.items()}
    elif isinstance(obj, list):
        value = [traverse_dict(elem, callback)
                 for elem in obj]
    else:
        value = obj

    if callback is None:  # if a callback is provided, call it to get the new value
        return value
    else:
        return callback(value)


def _traverse_modify_date(obj):
    """
    Make sure that all dates are of the type datetime.date
    :param obj: dictionary
    :return: function call
    """
    def _transformer(value):
        if type(value) == dt:
            value = value.date()
        elif type(value) == ruamelTimeStamp:
            value = ruamelTimeStamp.date(value)

        return value

    return traverse_dict(obj, callback=_transformer)


def _check_file_type(filename, file_type=None):
    """
    Check if the provided YAML file has the key 'file_type' and possible if that key matches a specific value.
    :param filename: path to a YAML file
    :param file_type: value to check against the 'file_type' key in the YAML file
    :return: the file_type if present, else None is returned
    """
    if not os.path.exists(filename):
        print('[!] File: \'' + filename + '\' does not exist')
        return None

    _yaml = init_yaml()
    with open(filename, 'r') as yaml_file:
        try:
            yaml_content = _yaml.load(yaml_file)
        except Exception as e:
            print('[!] File: \'' + filename + '\' is not a valid YAML file.')
            print('  ' + str(e))  # print more detailed error information to help the user in fixing the error.
            return None

        # This check is performed because a text file will also be considered to be valid YAML. But, we are using
        # key-value pairs within the YAML files.
        if not hasattr(yaml_content, 'keys'):
            print('[!] File: \'' + filename + '\' is not a valid YAML file.')
            return None

        if 'file_type' not in yaml_content.keys():
            print('[!] File: \'' + filename + '\' does not contain a file_type key.')
            return None
        elif file_type:
            if file_type != yaml_content['file_type']:
                print('[!] File: \'' + filename + '\' is not a file type of: \'' + file_type + '\'')
                return None
            else:
                return yaml_content
        else:
            return yaml_content


def _check_for_old_data_sources(filename):
    """
    Check if the data source administration YAML file contains ATT&CK v8 data sources.
    :param filename: path to data source YAML file
    :return: True if no ATT&CK v8 data sources are found, else False is returned
    """
    _yaml = init_yaml()
    with open(filename, 'r') as yaml_file:
        yaml_content = _yaml.load(yaml_file)

    data_sources = set([ds['data_source_name'] for ds in yaml_content['data_sources']])

    if data_sources.intersection(DATA_SOURCES_ATTACK_V8):
        print('[!] File: \'' + filename + '\' needs to be manually updated to have the new ATT&CK v9 '
              'data sources/data components as it currently contains ATT&CK v8 data sources.\n' '    Not having the new '
              'data sources/data components will result in reduced functionality of DeTT&CT.')
        return False
    else:
        return True


def check_file(filename, file_type=None, health_is_called=False):
    """
    Calls four functions to perform the following checks: is the file a valid YAML file, needs the file to be upgraded,
    or does the file contain errors.
    :param filename: path to a YAML file
    :param file_type: value to check against the 'file_type' key in the YAML file
    :param health_is_called: boolean that specifies if detailed errors in the file will be printed by the function 'check_yaml_file_health'
    :return: the file_type if present, else None is returned
    """

    yaml_content = _check_file_type(filename, file_type)

    # if the file is a valid YAML, continue. Else, return None
    if yaml_content:
        upgrade_yaml_file(filename, file_type, yaml_content['version'])
        check_yaml_file_health(filename, file_type, health_is_called)

        if file_type == FILE_TYPE_DATA_SOURCE_ADMINISTRATION:
            if not _check_for_old_data_sources(filename):
                return None

        return yaml_content['file_type']

    return yaml_content  # value is None


def get_platform_from_yaml(yaml_content, domain):
    """
    Read the platform field from the YAML file supporting both string and list values.
    :param yaml_content: the content of the YAML file containing the platform field
    :return: the platform value
    """
    platform = yaml_content.get('platform', None)
    if platform is None:
        return []
    if isinstance(platform, str):
        platform = [platform]
    platform = [p.lower() for p in platform if p is not None]
    selected_platforms = PLATFORMS_ENTERPRISE if domain == 'enterprise-attack' else PLATFORMS_ICS

    if 'all' in platform:
        platform = list(selected_platforms.values())
    else:
        valid_platform_list = []
        for p in platform:
            if p in selected_platforms.keys():
                valid_platform_list.append(selected_platforms[p])
        platform = valid_platform_list
    return platform


def get_technique_from_yaml(yaml_content, technique_id):
    """
    Generic function to lookup a specific technique_id in the YAML content.
    :param techniques: list with all techniques
    :param technique_id: technique_id to look for
    :return: the technique you're searching for. None if not found.
    """
    for tech in yaml_content['techniques']:
        if tech['technique_id'] == technique_id:
            return tech
