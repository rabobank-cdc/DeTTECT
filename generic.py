import os
import pickle
from datetime import datetime as dt
import yaml
from upgrade import upgrade_yaml_file
from constants import *
from difflib import SequenceMatcher

# Due to performance reasons the import of attackcti is within the function that makes use of this library.


def try_get_key(dictionary, key):
    """
    Return None if the key does not exists within the provided dict
    :param dictionary: dictionary
    :param key: key
    :return: key value or None
    """
    if key in dictionary:
        return dictionary[key]
    return None


def try_except(self, stix_objects, object_type, nested_value=None):
    if object_type in stix_objects:
        specific_stix_object = stix_objects[object_type]
        if isinstance(specific_stix_object, list):
            if nested_value is None:
                lists = self.handle_list(stix_objects, object_type)
                return lists
            else:
                nested_result = self.handle_nested(stix_objects, object_type, nested_value)
                return nested_result
        else:
            return stix_objects[object_type]
    else:
        return None


def save_attack_data(data, path):
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


def load_attack_data(data_type):
    """
    Load the cached ATT&CK data from disk, if not expired (data file on disk is older then EXPIRE_TIME seconds).
    :param data_type: the desired data type, see DATATYPE_XX constants.
    :return: MITRE ATT&CK data object (STIX or custom schema)
    """
    if os.path.exists("cache/" + data_type):
        with open("cache/" + data_type, 'rb') as f:
            cached = pickle.load(f)
            write_time = cached[1]
            if not (dt.now() - write_time).total_seconds() >= EXPIRE_TIME:
                # the first item in the list contains the ATT&CK data
                return cached[0]

    from attackcti import attack_client
    mitre = attack_client()

    attack_data = None
    if data_type == DATA_TYPE_STIX_ALL_RELATIONSHIPS:
        attack_data = mitre.get_all_relationships()
    if data_type == DATA_TYPE_STIX_ALL_TECH_ENTERPRISE:
        attack_data = mitre.get_all_enterprise_techniques()
    if data_type == DATA_TYPE_CUSTOM_TECH_BY_GROUP:
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
                            'aliases': try_get_key(g, 'aliases'),
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
                            'x_mitre_platforms': try_get_key(t, 'x_mitre_platforms'),
                            'matrix': t['external_references'][0]['source_name']
                        })

        attack_data = all_group_use

    elif data_type == DATA_TYPE_STIX_ALL_TECH:
        attack_data = mitre.get_all_techniques()
    elif data_type == DATA_TYPE_STIX_ALL_GROUPS:
        attack_data = mitre.get_all_groups()
    elif data_type == DATA_TYPE_STIX_ALL_SOFTWARE:
        attack_data = mitre.get_all_software()
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
                            'aliases': try_get_key(g, 'aliases'),
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
                            'x_mitre_platforms': try_get_key(s, 'x_mitre_platforms'),
                            'matrix': s['external_references'][0]['source_name']
                        })
        attack_data = all_group_use

    save_attack_data(attack_data, "cache/" + data_type)

    return attack_data


def _get_base_template(name, description, stage, platform, sorting):
    """
    Prepares a base template for the json layer file that can be loaded into the MITRE ATT&CK Navigator.
    More information on the version 2.1 layer format:
    https://github.com/mitre/attack-navigator/blob/master/layers/LAYERFORMATv2_1.md
    :param name: name
    :param description: description
    :param stage: stage (act | prepare)
    :param platform: platform
    :param sorting: sorting
    :return: layer template dictionary
    """
    layer = {}
    layer['name'] = name
    layer['version'] = '2.1'
    layer['domain'] = 'mitre-enterprise'
    layer['description'] = description

    if platform == 'all':
        platform = ['windows', 'linux', 'mac']
    else:
        platform = [platform.lower()]

    if stage == 'attack':
        layer['filters'] = {'stages': ['act'], 'platforms': platform}
    else:
        layer['filters'] = {'stages': ['prepare'], 'platforms': platform}

    layer['sorting'] = sorting
    layer['viewMode'] = 0
    layer['hideDisable'] = False
    layer['techniques'] = []

    layer['showTacticRowBackground'] = False
    layer['tacticRowBackground'] = COLOR_TACTIC_ROW_BACKGRND
    layer['selectTechniquesAcrossTactics'] = True
    return layer


def get_layer_template_groups(name, max_count, description, stage, platform, overlay_type):
    """
    Prepares a base template for the json layer file that can be loaded into the MITRE ATT&CK Navigator.
    More information on the version 2.1 layer format:
    https://github.com/mitre/attack-navigator/blob/master/layers/LAYERFORMATv2_1.md
    :param name: name
    :param max_count: the sum of all count values
    :param description: description
    :param stage: stage (act | prepare)
    :param platform: platform
    :param overlay_type: group, visibility or detection
    :return: layer template dictionary
    """
    layer = _get_base_template(name, description, stage, platform, 3)
    layer['gradient'] = {'colors': [COLOR_GRADIENT_MIN, COLOR_GRADIENT_MAX], 'minValue': 0, 'maxValue': max_count}
    layer['legendItems'] = []
    layer['legendItems'].append({'label': 'Tech. not often used', 'color': COLOR_GRADIENT_MIN})
    layer['legendItems'].append({'label': 'Tech. used frequently', 'color': COLOR_GRADIENT_MAX})

    if overlay_type == OVERLAY_TYPE_GROUP:
        layer['legendItems'].append({'label': 'Groups overlay: tech. in group + overlay', 'color': COLOR_GROUP_OVERLAY_MATCH})
        layer['legendItems'].append({'label': 'Groups overlay: tech. in overlay', 'color': COLOR_GROUP_OVERLAY_NO_MATCH})
        layer['legendItems'].append({'label': 'Src. of tech. is only software', 'color': COLOR_SOFTWARE})
        layer['legendItems'].append({'label': 'Src. of tech. is group(s)/overlay + software', 'color': COLOR_GROUP_AND_SOFTWARE})
    elif overlay_type == OVERLAY_TYPE_DETECTION:
        layer['legendItems'].append({'label': 'Tech. in group + detection', 'color': COLOR_GROUP_OVERLAY_MATCH})
        layer['legendItems'].append({'label': 'Tech. in detection', 'color': COLOR_GROUP_OVERLAY_ONLY_DETECTION})
    elif overlay_type == OVERLAY_TYPE_VISIBILITY:
        layer['legendItems'].append({'label': 'Tech. in group + visibility', 'color': COLOR_GROUP_OVERLAY_MATCH})
        layer['legendItems'].append({'label': 'Tech. in visibility', 'color': COLOR_GROUP_OVERLAY_ONLY_VISIBILITY})

    return layer


def get_layer_template_detections(name, description, stage, platform):
    """
    Prepares a base template for the json layer file that can be loaded into the MITRE ATT&CK Navigator.
    More information on the version 2.1 layer format:
    https://github.com/mitre/attack-navigator/blob/master/layers/LAYERFORMATv2_1.md
    :param name: name
    :param description: description
    :param stage: stage (act | prepare)
    :param platform: platform
    :return: layer template dictionary
    """
    layer = _get_base_template(name, description, stage, platform, 0)
    layer['legendItems'] = \
        [
            {'label': 'Detection score 0: Forensics/Context', 'color': COLOR_D_0},
            {'label': 'Detection score 1: Basic', 'color': COLOR_D_1},
            {'label': 'Detection score 2: Fair', 'color': COLOR_D_2},
            {'label': 'Detection score 3: Good', 'color': COLOR_D_3},
            {'label': 'Detection score 4: Very good', 'color': COLOR_D_4},
            {'label': 'Detection score 5: Excellent', 'color': COLOR_D_5}
        ]
    return layer


def get_layer_template_data_sources(name, description, stage, platform):
    """
    Prepares a base template for the json layer file that can be loaded into the MITRE ATT&CK Navigator.
    More information on the version 2.1 layer format:
    https://github.com/mitre/attack-navigator/blob/master/layers/LAYERFORMATv2_1.md
    :param name: name
    :param description: description
    :param stage: stage (act | prepare)
    :param platform: platform
    :return: layer template dictionary
    """
    layer = _get_base_template(name, description, stage, platform, 0)
    layer['legendItems'] = \
        [
            {'label': '1-25% of data sources available', 'color': COLOR_DS_25p},
            {'label': '26-50% of data sources available', 'color': COLOR_DS_50p},
            {'label': '51-75% of data sources available', 'color': COLOR_DS_75p},
            {'label': '76-99% of data sources available', 'color': COLOR_DS_99p},
            {'label': '100% of data sources available', 'color': COLOR_DS_100p}
        ]
    return layer


def get_layer_template_visibility(name, description, stage, platform):
    """
    Prepares a base template for the json layer file that can be loaded into the MITRE ATT&CK Navigator.
    More information on the version 2.1 layer format:
    https://github.com/mitre/attack-navigator/blob/master/layers/LAYERFORMATv2_1.md
    :param name: name
    :param description: description
    :param stage: stage (act | prepare)
    :param platform: platform
    :return: layer template dictionary
    """
    layer = _get_base_template(name, description, stage, platform, 0)
    layer['legendItems'] = \
        [
            {'label': 'Visibility score 1: Minimal', 'color': COLOR_V_1},
            {'label': 'Visibility score 2: Medium', 'color': COLOR_V_2},
            {'label': 'Visibility score 3: Good', 'color': COLOR_V_3},
            {'label': 'Visibility score 4: Excellent', 'color': COLOR_V_4}
        ]
    return layer


def get_layer_template_layered(name, description, stage, platform):
    """
    Prepares a base template for the json layer file that can be loaded into the MITRE ATT&CK Navigator.
    More information on the version 2.1 layer format:
    https://github.com/mitre/attack-navigator/blob/master/layers/LAYERFORMATv2_1.md
    :param name: name
    :param description: description
    :param stage: stage (act | prepare)
    :param platform: platform
    :return: layer template dictionary
    """
    layer = _get_base_template(name, description, stage, platform, 0)
    layer['legendItems'] = \
        [
            {'label': 'Visibility', 'color': COLOR_OVERLAY_VISIBILITY},
            {'label': 'Detection', 'color': COLOR_OVERLAY_DETECTION},
            {'label': 'Visibility and detection', 'color': COLOR_OVERLAY_BOTH}
        ]
    return layer


def get_attack_id(stix_obj):
    """
    Get the Technique, Group or Software ID from the STIX object
    :param stix_obj: STIX object (Technique, Software or Group)
    :return: ATT&CK ID
    """
    for ext_ref in stix_obj['external_references']:
        if ext_ref['source_name'] in ['mitre-attack', 'mitre-mobile-attack', 'mitre-pre-attack']:
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


def normalize_name_to_filename(name):
    """
    Normalize the input filename to a lowercase filename and replace spaces with dashes.
    :param name: input filename
    :return: normalized filename
    """
    return name.lower().replace(' ', '-')


def map_techniques_to_data_sources(techniques, my_data_sources):
    """
    This function maps the MITRE ATT&CK techniques to your data sources.
    :param techniques: list with all MITRE ATT&CK techniques
    :param my_data_sources: your configured data sources
    :return: a dictionary containing techniques that can be used in the layer output file.
    """
    my_techniques = {}
    for i_ds in my_data_sources.keys():
        # Loop through all techniques, to find techniques using that data source:
        for t in techniques:
            # If your data source is in the list of data sources for this technique AND if the
            # technique isn't added yet (by an other data source):
            tech_id = get_attack_id(t)
            if 'x_mitre_data_sources' in t:
                if i_ds in t['x_mitre_data_sources'] and tech_id not in my_techniques.keys():
                    my_techniques[tech_id] = {}
                    my_techniques[tech_id]['my_data_sources'] = [i_ds, ]
                    my_techniques[tech_id]['data_sources'] = t['x_mitre_data_sources']
                    # create a list of tactics
                    my_techniques[tech_id]['tactics'] = list(map(lambda k: k['phase_name'], try_get_key(t, 'kill_chain_phases')))
                    my_techniques[tech_id]['products'] = set(my_data_sources[i_ds]['products'])
                elif t['x_mitre_data_sources'] and i_ds in t['x_mitre_data_sources'] and tech_id in my_techniques.keys():
                    my_techniques[tech_id]['my_data_sources'].append(i_ds)
                    my_techniques[tech_id]['products'].update(my_data_sources[i_ds]['products'])

    return my_techniques


def get_all_mitre_data_sources():
    """
    Gets all the data sources from the techniques and make a unique sorted list of it.
    :return: a sorted list with all data sources
    """
    techniques = load_attack_data(DATA_TYPE_STIX_ALL_TECH)

    data_sources = set()
    for t in techniques:
        if 'x_mitre_data_sources' in t.keys():
            for ds in t['x_mitre_data_sources']:
                data_sources.add(ds)
    return sorted(data_sources)


def calculate_score(l, zero_value=0):
    """
    Calculates the average score in the given list which contains dictionaries with 'score' field.
    :param l: list
    :param zero_value: the value when no scores are there, default 0
    :return: average score
    """
    s = 0
    number = 0
    for v in l:
        if v['score'] >= 0:
            s += v['score']
            number += 1
    s = int(round(s / number, 0) if number > 0 else zero_value)
    return s


def _add_entry_to_list_in_dictionary(dict, technique_id, key, entry):
    """
    Ensures a list will be created if it doesn't exist in the given dict[technique_id][key] and adds the entry to the
    list. If the dict[technique_id] doesn't exist yet, it will be created.
    :param dict: the dictionary
    :param technique_id: the id of the technique in the main dict
    :param key: the key where the list in the dictionary resides
    :param entry: the entry to add to the list
    :return:
    """
    if technique_id not in dict.keys():
        dict[technique_id] = {}
    if not key in dict[technique_id].keys():
        dict[technique_id][key] = []
    dict[technique_id][key].append(entry)


def load_techniques(filename, detection_or_visibility='all', filter_applicable_to='all'):
    """
    Loads the techniques (including detection and visibility properties) from the given yaml file.
    :param filename: the filename of the yaml file containing the techniques administration
    :param detection_or_visibility: used to indicate to filter applicable_to field for detection or visibility. When
                                    using 'all' no filtering will be applied.
    :param filter_applicable_to: filter techniques based on applicable_to field in techniques administration YAML file
    :return: dictionary with techniques (incl. properties), name and platform
    """

    my_techniques = {}
    with open(filename, 'r') as yaml_file:
        yaml_content = yaml.load(yaml_file, Loader=yaml.FullLoader)
        for d in yaml_content['techniques']:
            # Add detection items:
            if type(d['detection']) == dict:  # There is just one detection entry
                if detection_or_visibility == 'all' or filter_applicable_to == 'all' or filter_applicable_to in d[detection_or_visibility]['applicable_to'] or 'all' in d[detection_or_visibility]['applicable_to']:
                    _add_entry_to_list_in_dictionary(my_techniques, d['technique_id'], 'detection', d['detection'])
            elif type(d['detection']) == list:  # There are multiple detection entries
                for de in d['detection']:
                    if detection_or_visibility == 'all' or filter_applicable_to == 'all' or filter_applicable_to in de['applicable_to'] or 'all' in de['applicable_to']:
                        _add_entry_to_list_in_dictionary(my_techniques, d['technique_id'], 'detection', de)

            # Add visibility items
            if type(d['visibility']) == dict:  # There is just one visibility entry
                if detection_or_visibility == 'all' or filter_applicable_to == 'all' or filter_applicable_to in d[detection_or_visibility]['applicable_to'] or 'all' in d[detection_or_visibility]['applicable_to']:
                    _add_entry_to_list_in_dictionary(my_techniques, d['technique_id'], 'visibility', d['visibility'])
            elif type(d['visibility']) == list:  # There are multiple visibility entries
                for de in d['visibility']:
                    if detection_or_visibility == 'all' or filter_applicable_to == 'all' or filter_applicable_to in de['applicable_to'] or 'all' in de['applicable_to']:
                        _add_entry_to_list_in_dictionary(my_techniques, d['technique_id'], 'visibility', de)

        name = yaml_content['name']
        platform = yaml_content['platform']
    return my_techniques, name, platform


def _print_error_msg(msg, print_error):
    if print_error:
        print(msg)
    return True


def check_yaml_file_health(filename, file_type, health_is_called):
    """
    Check on error in the provided YAML file.
    :param filename: YAML file location
    :param file_type: currently only 'FILE_TYPE_TECHNIQUE_ADMINISTRATION' is being supported
    :param health_is_called: boolean that specifies if detailed errors in the file will be printed and then quit()
    :return:
    """

    has_error = False
    if file_type == FILE_TYPE_TECHNIQUE_ADMINISTRATION:
        # check for duplicate tech IDs
        with open(filename, 'r') as yaml_file:
            yaml_content = yaml.load(yaml_file, Loader=yaml.FullLoader)

            tech_ids = list(map(lambda x: x['technique_id'], yaml_content['techniques']))
            tech_dup = []
            for tech in tech_ids:
                if tech not in tech_dup:
                    tech_dup.append(tech)
                else:
                    has_error = _print_error_msg('[!] Duplicate technique ID: ' + tech, health_is_called)

        # checks on:
        # - empty key-value pairs: 'date_implemented', 'date_registered', 'location', 'applicable_to', 'score'
        # - invalid date format for: 'date_implemented', 'date_registered'
        # - detection or visibility score out-of-range
        # - missing key-value pairs: 'applicable_to', 'date_registered', 'date_implemented', 'score', 'location', 'comment'
        # - check on 'applicable_to' values which are very similar

        all_applicable_to = set()
        techniques = load_techniques(filename)
        for tech, v in techniques[0].items():

            for key in ['detection', 'visibility']:
                if key not in v:
                    has_error = _print_error_msg('[!] Technique ID: ' + tech + ' is MISSING ' + key, health_is_called)
                else:
                    # create at set containing all values for 'applicable_to'
                    all_applicable_to.update([a for v in v[key] for a in v['applicable_to']])

            for detection in v['detection']:
                for key in ['applicable_to', 'date_registered', 'date_implemented', 'score', 'location', 'comment']:
                    if key not in detection:
                        has_error = _print_error_msg('[!] Technique ID: ' + tech + ' is MISSING the key-value pair in detection: ' + key, health_is_called)

                try:
                    if detection['score'] is None:
                        has_error = _print_error_msg('[!] Technique ID: ' + tech + ' is has an EMPTY key-value pair in detection: score', health_is_called)

                    elif not (detection['score'] >= -1 and detection['score'] <= 5):
                        has_error = _print_error_msg('[!] Technique ID: ' + tech + ' has an INVALID detection score: '
                                                     + str(detection['score']) + ' (should be between -1 and 5)', health_is_called)

                    elif detection['score'] > -1:
                        for key in ['date_implemented', 'date_registered']:
                            if not detection[key]:
                                has_error = _print_error_msg('[!] Technique ID: ' + tech + ' is has an EMPTY key-value pair in detection: ' + key, health_is_called)
                                break
                            try:
                                detection[key].year
                                detection[key].month
                                detection[key].day
                            except AttributeError:
                                has_error = _print_error_msg('[!] Technique ID: ' + tech +
                                                             ' has an INVALID data format for the key-value pair in detection: ' +
                                                             key + '  (should be YYYY-MM-DD)', health_is_called)
                    for key in ['location', 'applicable_to']:
                        if not isinstance(detection[key], list):
                            has_error = _print_error_msg('[!] Technique ID: ' + tech + ' has for the key-value pair \''
                                                         + key + '\' a string value assigned (should be a list)', health_is_called)
                        else:
                            try:
                                if detection[key][0] is None:
                                    has_error = _print_error_msg('[!] Technique ID: ' + tech + ' is has an EMPTY key-value pair in detection: ' + key, health_is_called)
                            except TypeError:
                                has_error = _print_error_msg('[!] Technique ID: ' + tech + ' is has an EMPTY key-value pair in detection: ' + key, health_is_called)
                except KeyError:
                    pass

            for visibility in v['visibility']:
                for key in ['applicable_to', 'score', 'comment']:
                    if key not in visibility:
                        has_error = _print_error_msg('[!] Technique ID: ' + tech + ' is MISSING the key-value pair in visibility: ' + key, health_is_called)

                try:
                    if visibility['score'] is None:
                        has_error = _print_error_msg('[!] Technique ID: ' + tech + ' is has an EMPTY key-value pair in visibility: score', health_is_called)
                    elif not (visibility['score'] >= 0 and visibility['score'] <= 4):
                        has_error = _print_error_msg('[!] Technique ID: ' + tech + ' has an INVALID visibility score: '
                                                     + str(detection['score']) + ' (should be between 0 and 4)', health_is_called)
                except KeyError:
                    pass

        # get values within the key-value pair 'applicable_to' which are a very close match
        similar = set()
        for i1 in all_applicable_to:
            for i2 in all_applicable_to:
                match_value = SequenceMatcher(None, i1, i2).ratio()
                if match_value > 0.8 and match_value != 1:
                    similar.add(i1)
                    similar.add(i2)

        if len(similar) > 0:
            has_error = _print_error_msg('[!] There are values in the key-value pair \'applicable_to\' which are very similar. Correct where necessary:', health_is_called)
            for s in similar:
                _print_error_msg('    - ' + s, health_is_called)

        if has_error and not health_is_called:
            print('[!] The below YAML file contains possible errors. It\'s recommended to check via the \'--health\' '
                  'argument or using the option in the interactive menu: \n    - ' + filename)

        if has_error:
            print('')  # print a newline


def check_file_type(filename, file_type=None):
    """
    Check if the provided YAML file has the key 'file_type' and possible if that key matches a specific value.
    :param filename: path to a YAML file
    :param file_type: value to check against the 'file_type' key in the YAML file
    :return: the file_type if present, else None is returned
    """
    if not os.path.exists(filename):
        print('[!] File: \'' + filename + '\' does not exist')
        return None
    with open(filename, 'r') as yaml_file:
        try:
            yaml_content = yaml.load(yaml_file, Loader=yaml.FullLoader)
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


def check_file(filename, file_type=None, health_is_called=False):
    """
    Calls three functions to perform the following checks: is the file a valid YAML file, needs the file to be upgrade,
    does the file contain errors.
    :param filename: path to a YAML file
    :param file_type: value to check against the 'file_type' key in the YAML file
    :param health_is_called: boolean that specifies if detailed errors in the file will be printed by the function 'check_yaml_file_health' and then quit()
    :return: the file_type if present, else None is returned
    """

    yaml_content = check_file_type(filename, file_type)

    # if the file is a valid YAML, continue. Else, return None
    if yaml_content:
        upgrade_yaml_file(filename, file_type, yaml_content['version'], load_attack_data(DATA_TYPE_STIX_ALL_TECH))
        check_yaml_file_health(filename, file_type, health_is_called)

        return yaml_content['file_type']

    return yaml_content  # value is None
