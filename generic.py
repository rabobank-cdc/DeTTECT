import os
import shutil
import pickle
from datetime import datetime as dt
from io import StringIO
from ruamel.yaml import YAML
from ruamel.yaml.timestamp import TimeStamp as ruamelTimeStamp
from upgrade import upgrade_yaml_file, check_yaml_updated_to_sub_techniques
from constants import *
from health import check_yaml_file_health

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


def remove_deprecated(stix_objects):
    """
    Remove deprecated STIX objects
    :param stix_objects: list of STIX objects
    :return: a list of STIX objects
    """
    handle_deprecated = list()
    for obj in stix_objects:
        if not('x_mitre_deprecated' in obj.keys() and obj['x_mitre_deprecated'] == True):
            handle_deprecated.append(obj)
    return handle_deprecated


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

        mitre = attack_client()

    attack_data = None
    if data_type == DATA_TYPE_STIX_ALL_RELATIONSHIPS:
        attack_data = mitre.get_relationships()
        attack_data = mitre.remove_revoked(attack_data)
        attack_data = remove_deprecated(attack_data)
    elif data_type == DATA_TYPE_STIX_ALL_TECH_ENTERPRISE:
        attack_data = mitre.get_enterprise_techniques()
        attack_data = mitre.remove_revoked(attack_data)
        attack_data = remove_deprecated(attack_data)
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
        attack_data = mitre.get_techniques()
        attack_data = mitre.remove_revoked(attack_data)
        attack_data = remove_deprecated(attack_data)
    elif data_type == DATA_TYPE_STIX_ALL_GROUPS:
        attack_data = mitre.get_groups()
        attack_data = mitre.remove_revoked(attack_data)
        attack_data = remove_deprecated(attack_data)
    elif data_type == DATA_TYPE_STIX_ALL_SOFTWARE:
        attack_data = mitre.get_software()
        attack_data = mitre.remove_revoked(attack_data)
        attack_data = remove_deprecated(attack_data)
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
        attack_data = mitre.remove_revoked(attack_data)
        attack_data = remove_deprecated(attack_data)

    elif data_type == DATA_TYPE_STIX_ALL_MOBILE_MITIGATIONS:
        attack_data = mitre.get_mobile_mitigations()
        attack_data = mitre.remove_revoked(attack_data)
        attack_data = remove_deprecated(attack_data)

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


def _get_base_template(name, description, stage, platform, sorting):
    """
    Prepares a base template for the json layer file that can be loaded into the MITRE ATT&CK Navigator.
    More information on the layer format can be found here: https://github.com/mitre/attack-navigator/blob/master/layers/
    :param name: name
    :param description: description
    :param stage: stage (act | prepare)
    :param platform: platform
    :param sorting: sorting
    :return: layer template dictionary
    """
    layer = dict()
    layer['name'] = name
    layer['version'] = '3.0'
    layer['domain'] = 'mitre-enterprise'
    layer['description'] = description

    if platform == 'all':
        platform = list(PLATFORMS.values())

    if stage == 'attack':
        layer['filters'] = {'stages': ['act'], 'platforms': platform}
    else:
        layer['filters'] = {'stages': ['prepare'], 'platforms': platform}

    layer['sorting'] = sorting
    layer['layout'] = {"layout": "flat", "showName": True, "showID": False}
    layer['hideDisable'] = False
    layer['selectSubtechniquesWithParent'] = False
    layer['techniques'] = []

    layer['showTacticRowBackground'] = False
    layer['tacticRowBackground'] = COLOR_TACTIC_ROW_BACKGRND
    layer['selectTechniquesAcrossTactics'] = True
    return layer


def get_layer_template_groups(name, max_count, description, stage, platform, overlay_type):
    """
    Prepares a base template for the json layer file that can be loaded into the MITRE ATT&CK Navigator.
    More information on the layer format can be found here: https://github.com/mitre/attack-navigator/blob/master/layers/
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
        layer['legendItems'].append({'label': 'Tech. in group + detection score 0: Forensics/Context', 'color': COLOR_O_0})
        layer['legendItems'].append({'label': 'Tech. in group + detection score 1: Basic', 'color': COLOR_O_1})
        layer['legendItems'].append({'label': 'Tech. in group + detection score 2: Fair', 'color': COLOR_O_2})
        layer['legendItems'].append({'label': 'Tech. in group + detection score 3: Good', 'color': COLOR_O_3})
        layer['legendItems'].append({'label': 'Tech. in group + detection score 4: Very good', 'color': COLOR_O_4})
        layer['legendItems'].append({'label': 'Tech. in group + detection score 5: Excellent', 'color': COLOR_O_5})
        layer['legendItems'].append({'label': 'Tech. in detection, score 0: Forensics/Context', 'color': COLOR_D_0})
        layer['legendItems'].append({'label': 'Tech. in detection, score 1: Basic', 'color': COLOR_D_1})
        layer['legendItems'].append({'label': 'Tech. in detection, score 2: Fair', 'color': COLOR_D_2})
        layer['legendItems'].append({'label': 'Tech. in detection, score 3: Good', 'color': COLOR_D_3})
        layer['legendItems'].append({'label': 'Tech. in detection, score 4: Very good', 'color': COLOR_D_4})
        layer['legendItems'].append({'label': 'Tech. in detection, score 5: Excellent', 'color': COLOR_D_5})
    elif overlay_type == OVERLAY_TYPE_VISIBILITY:
        layer['legendItems'].append({'label': 'Tech. in group + visibility score 1: Minimal', 'color': COLOR_O_1})
        layer['legendItems'].append({'label': 'Tech. in group + visibility score 2: Medium', 'color': COLOR_O_2})
        layer['legendItems'].append({'label': 'Tech. in group + visibility score 3: Good', 'color': COLOR_O_3})
        layer['legendItems'].append({'label': 'Tech. in group + visibility score 4: Excellent', 'color': COLOR_O_4})
        layer['legendItems'].append({'label': 'Tech. in visibility, score 1: Minimal', 'color': COLOR_V_1})
        layer['legendItems'].append({'label': 'Tech. in visibility, score 2: Medium', 'color': COLOR_V_2})
        layer['legendItems'].append({'label': 'Tech. in visibility, score 3: Good', 'color': COLOR_V_3})
        layer['legendItems'].append({'label': 'Tech. in visibility, score 4: Excellent', 'color': COLOR_V_4})

    return layer


def get_layer_template_detections(name, description, stage, platform):
    """
    Prepares a base template for the json layer file that can be loaded into the MITRE ATT&CK Navigator.
    More information on the layer format can be found here: https://github.com/mitre/attack-navigator/blob/master/layers/
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
    More information on the layer format can be found here: https://github.com/mitre/attack-navigator/blob/master/layers/
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
    More information on the layer format can be found here: https://github.com/mitre/attack-navigator/blob/master/layers/
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
    More information on the layer format can be found here: https://github.com/mitre/attack-navigator/blob/master/layers/
    :param name: name
    :param description: description
    :param stage: stage (act | prepare)
    :param platform: platform
    :return: layer template dictionary
    """
    layer = _get_base_template(name, description, stage, platform, 0)
    layer['legendItems'] = \
        [
            {'label': 'Visibility and detection', 'color': COLOR_OVERLAY_BOTH},
            {'label': 'Visibility score 1: Minimal', 'color': COLOR_V_1},
            {'label': 'Visibility score 2: Medium', 'color': COLOR_V_2},
            {'label': 'Visibility score 3: Good', 'color': COLOR_V_3},
            {'label': 'Visibility score 4: Excellent', 'color': COLOR_V_4},
            {'label': 'Detection score 1: Basic', 'color': COLOR_D_1},
            {'label': 'Detection score 2: Fair', 'color': COLOR_D_2},
            {'label': 'Detection score 3: Good', 'color': COLOR_D_3},
            {'label': 'Detection score 4: Very good', 'color': COLOR_D_4},
            {'label': 'Detection score 5: Excellent', 'color': COLOR_D_5}
    ]
    return layer


def create_output_filename(filename_prefix, filename):
    """
    Creates a filename using pre determined convention.
    :param filename_prefix: prefix part of the filename
    :param filename: filename
    :return:
    """
    return '%s_%s' % (filename_prefix, normalize_name_to_filename(filename))


def write_file(filename, content):
    """
    Writes content to a file and ensures if the file already exists it won't be overwritten by appending a number
    as suffix.
    :param filename: filename
    :param content: the content of the file that needs to be written to the file
    :return:
    """
    output_filename = 'output/%s' % clean_filename(filename)
    output_filename = get_non_existing_filename(output_filename, 'json')

    with open(output_filename, 'w') as f:
        f.write(content)

    print('File written:   ' + output_filename)


def get_non_existing_filename(filename, extension):
    """
    Generates a filename that doesn't exist based on the given filename by appending a number as suffix.
    :param filename:
    :param extension:
    :return:
    """
    if filename.endswith('.' + extension):
        filename = filename.replace('.' + extension, '')
    if os.path.exists('%s.%s' % (filename, extension)):
        suffix = 1
        while os.path.exists('%s_%s.%s' % (filename, suffix, extension)):
            suffix += 1
        output_filename = '%s_%s.%s' % (filename, suffix, extension)
    else:
        output_filename = '%s.%s' % (filename, extension)
    return output_filename


def backup_file(filename):
    """
    Create a backup of the provided file
    :param filename: existing YAML filename
    :return:
    """
    suffix = 1
    backup_filename = filename.replace('.yaml', '_backup_' + str(suffix) + '.yaml')
    while os.path.exists(backup_filename):
        backup_filename = backup_filename.replace('_backup_' + str(suffix) + '.yaml', '_backup_' + str(suffix + 1) + '.yaml')
        suffix += 1

    shutil.copy2(filename, backup_filename)
    print('Written backup file:   ' + backup_filename + '\n')


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

    return list_answers[int(answer) - 1]


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

            if not newest_score_obj or score_obj_date > newest_date:
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


def normalize_name_to_filename(name):
    """
    Normalize the input filename to a lowercase filename and replace spaces with dashes.
    :param name: input filename
    :return: normalized filename
    """
    return name.lower().replace(' ', '-')


def platform_to_name(platform, separator='-'):
    """
    Makes a filename friendly version of the platform parameter which can be a string or list.
    :param platform: the platform variable (a string or a list)
    :param separator: a string value that separates multiple platforms. Default is '-'
    :return: a filename friendly representation of the value of platform
    """
    if platform == 'all':
        return 'all'
    elif isinstance(platform, list):
        return separator.join(platform)
    else:
        return ''


def get_applicable_data_sources_platform(platforms):
    """
    Get the applicable ATT&CK data sources for the provided platform(s)
    :param platforms: the ATT&CK platform(s)
    :return: a list of applicable ATT&CK data sources
    """
    applicable_data_sources = set()
    if platforms == 'all' or 'all' in platforms:
        for v in DATA_SOURCES.values():
            applicable_data_sources.update(v)
    else:
        for p in platforms:
            applicable_data_sources.update(DATA_SOURCES[p])

    return list(applicable_data_sources)


def get_applicable_data_sources_technique(technique_data_sources, platform_applicable_data_sources):
    """
    Get the applicable ATT&CK data sources for the provided technique's data sources (for which the source is ATT&CK CTI)
    :param technique_data_sources: the ATT&CK technique's data sources
    :param platform_applicable_data_sources: a list of applicable ATT&CK data sources based on 'DATA_SOURCES'
    :return: a list of applicable data sources
    """
    applicable_data_sources = set()
    for ds in technique_data_sources:
        if ds in platform_applicable_data_sources:
            applicable_data_sources.add(ds)

    return list(applicable_data_sources)


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
                    my_techniques[tech_id]['tactics'] = list(map(lambda k: k['phase_name'], t.get('kill_chain_phases', None)))
                    my_techniques[tech_id]['products'] = set(my_data_sources[i_ds]['products'])
                elif t['x_mitre_data_sources'] and i_ds in t['x_mitre_data_sources'] and tech_id in my_techniques.keys():
                    my_techniques[tech_id]['my_data_sources'].append(i_ds)
                    my_techniques[tech_id]['products'].update(my_data_sources[i_ds]['products'])

    return my_techniques


def get_all_mitre_data_sources():
    """
    Gets all the data sources from the techniques and make a set.
    :return: a sorted list with all data sources
    """
    techniques = load_attack_data(DATA_TYPE_STIX_ALL_TECH)

    data_sources = set()
    for t in techniques:
        if 'x_mitre_data_sources' in t.keys():
            for ds in t['x_mitre_data_sources']:
                data_sources.add(ds)
    return data_sources


def calculate_score(list_detections, zero_value=0):
    """
    Calculates the average score in the given list which may contain multiple detection dictionaries
    :param list_detections: list
    :param zero_value: the value when no scores are there, default 0
    :return: average score
    """
    avg_score = 0
    number = 0
    for v in list_detections:
        score = get_latest_score(v)
        if score is not None and score >= 0:
            avg_score += score
            number += 1

    avg_score = int(round(avg_score / number, 0) if number > 0 else zero_value)
    return avg_score


def add_entry_to_list_in_dictionary(dictionary, technique_id, key, entry):
    """
    Ensures a list will be created if it doesn't exist in the given dict[technique_id][key] and adds the entry to the
    list. If the dict[technique_id] doesn't exist yet, it will be created.
    :param dictionary: the dictionary
    :param technique_id: the id of the technique in the main dict
    :param key: the key where the list in the dictionary resides
    :param entry: the entry to add to the list
    :return:
    """
    if technique_id not in dictionary.keys():
        dictionary[technique_id] = {}
    if key not in dictionary[technique_id].keys():
        dictionary[technique_id][key] = []
    dictionary[technique_id][key].append(entry)


def set_yaml_dv_comments(yaml_object):
    """
    Set all comments in the detection or visibility YAML object when the 'comment' key-value pair is missing or is None.
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
                add_entry_to_list_in_dictionary(my_techniques, d['technique_id'], 'detection', d['detection'])
            elif isinstance(d['detection'], list):  # There are multiple detection entries
                for de in d['detection']:
                    de = set_yaml_dv_comments(de)
                    add_entry_to_list_in_dictionary(my_techniques, d['technique_id'], 'detection', de)

        if 'visibility' in d:
            # Add visibility items
            if isinstance(d['visibility'], dict):  # There is just one visibility entry
                d['visibility'] = set_yaml_dv_comments(d['visibility'])
                add_entry_to_list_in_dictionary(my_techniques, d['technique_id'], 'visibility', d['visibility'])
            elif isinstance(d['visibility'], list):  # There are multiple visibility entries
                for de in d['visibility']:
                    de = set_yaml_dv_comments(de)
                    add_entry_to_list_in_dictionary(my_techniques, d['technique_id'], 'visibility', de)

        name = yaml_content['name']

        platform = get_platform_from_yaml(yaml_content)

    return my_techniques, name, platform


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


def check_file(filename, file_type=None, health_is_called=False):
    """
    Calls four functions to perform the following checks: is the file a valid YAML file, needs the file to be upgraded,
    does the file contain errors or does the file need a sub-techniques upgrade.
    :param filename: path to a YAML file
    :param file_type: value to check against the 'file_type' key in the YAML file
    :param health_is_called: boolean that specifies if detailed errors in the file will be printed by the function 'check_yaml_file_health'
    :return: the file_type if present, else None is returned
    """

    yaml_content = _check_file_type(filename, file_type)

    # if the file is a valid YAML, continue. Else, return None
    if yaml_content:
        upgrade_yaml_file(filename, file_type, yaml_content['version'], load_attack_data(DATA_TYPE_STIX_ALL_TECH))
        check_yaml_file_health(filename, file_type, health_is_called)

        if file_type == FILE_TYPE_TECHNIQUE_ADMINISTRATION:
            if not check_yaml_updated_to_sub_techniques(filename):
                return None

        return yaml_content['file_type']

    return yaml_content  # value is None


def make_layer_metadata_compliant(metadata):
    """
    Make sure the metadata values in the Navigator layer file are compliant with the expected data structure
    from the latest version on: https://github.com/mitre-attack/attack-navigator/tree/master/layers
    :param metadata: list of metadata dictionaries
    :return: compliant list of metadata dictionaries
    """
    for md_item in metadata:
        if not md_item['value'] or md_item['value'] == '':
            md_item['value'] = '-'

    return metadata


def add_metadata_technique_object(technique, obj_type, metadata):
    """
    Add the metadata for a detection or visibility object as used within any type of overlay.
    :param technique: technique object containing both the visibility and detection object
    :param obj_type: valid values are 'detection' and 'visibility'
    :param metadata: a list to which the metadata will be added
    :return: the created metadata as a list
    """
    if obj_type not in ['detection', 'visibility']:
        raise Exception("Invalid value for 'obj_type' provided.")

    metadata.append({'name': '------', 'value': ' '})
    metadata.append({'name': 'Applicable to', 'value': ', '.join(set([a for v in technique[obj_type] for a in v['applicable_to']]))})  # noqa
    metadata.append({'name': '' + obj_type.capitalize() + ' score', 'value': ', '.join([str(calculate_score(technique[obj_type]))])})  # noqa
    if obj_type == 'detection':
        metadata.append({'name': '' + obj_type.capitalize() + ' location', 'value': ', '.join(set([a for v in technique[obj_type] for a in v['location']]))})  # noqa
    metadata.append({'name': '' + obj_type.capitalize() + ' comment', 'value': ' | '.join(set(filter(lambda x: x != '', map(lambda k: k['comment'], technique[obj_type]))))})  # noqa
    metadata.append({'name': '' + obj_type.capitalize() + ' score comment', 'value': ' | '.join(set(filter(lambda x: x != '', map(lambda i: get_latest_comment(i), technique[obj_type]))))})  # noqa

    return metadata


def get_updates(update_type, sort='modified'):
    """
    Print a list of updates for a techniques, groups or software. Sort by modified or creation date.
    :param update_type: the type of update: techniques, groups or software
    :param sort: sort the list by modified or creation date
    :return:
    """
    if update_type[:-1] == 'technique':
        techniques = load_attack_data(DATA_TYPE_STIX_ALL_TECH)
        sorted_techniques = sorted(techniques, key=lambda k: k[sort])

        for t in sorted_techniques:
            print(get_attack_id(t) + ' ' + t['name'])
            print(' ' * 6 + 'created:  ' + t['created'].strftime('%Y-%m-%d'))
            print(' ' * 6 + 'modified: ' + t['modified'].strftime('%Y-%m-%d'))
            print(' ' * 6 + 'matrix:   ' + t['external_references'][0]['source_name'][6:])
            tactics = get_tactics(t)
            if tactics:
                print(' ' * 6 + 'tactic:   ' + ', '.join(tactics))
            else:
                print(' ' * 6 + 'tactic:   None')
            print('')

    elif update_type[:-1] == 'group':
        groups = load_attack_data(DATA_TYPE_STIX_ALL_GROUPS)
        sorted_groups = sorted(groups, key=lambda k: k[sort])

        for g in sorted_groups:
            print(get_attack_id(g) + ' ' + g['name'])
            print(' ' * 6 + 'created:  ' + g['created'].strftime('%Y-%m-%d'))
            print(' ' * 6 + 'modified: ' + g['modified'].strftime('%Y-%m-%d'))
            print('')

    elif update_type == 'software':
        software = load_attack_data(DATA_TYPE_STIX_ALL_SOFTWARE)
        sorted_software = sorted(software, key=lambda k: k[sort])

        for s in sorted_software:
            print(get_attack_id(s) + ' ' + s['name'])
            print(' ' * 6 + 'created:  ' + s['created'].strftime('%Y-%m-%d'))
            print(' ' * 6 + 'modified: ' + s['modified'].strftime('%Y-%m-%d'))
            print(' ' * 6 + 'matrix:   ' + s['external_references'][0]['source_name'][6:])
            print(' ' * 6 + 'type:     ' + s['type'])
            if 'x_mitre_platforms' in s:
                print(' ' * 6 + 'platform: ' + ', '.join(s['x_mitre_platforms']))
            else:
                print(' ' * 6 + 'platform: None')
            print('')


def get_statistics_mitigations(matrix):
    """
    Print out statistics related to mitigations and how many techniques they cover
    :return:
    """

    if matrix == 'enterprise':
        mitigations = load_attack_data(DATA_TYPE_STIX_ALL_ENTERPRISE_MITIGATIONS)
    elif matrix == 'mobile':
        mitigations = load_attack_data(DATA_TYPE_STIX_ALL_MOBILE_MITIGATIONS)

    mitigations_dict = dict()
    for m in mitigations:
        if m['external_references'][0]['external_id'].startswith('M'):
            mitigations_dict[m['id']] = {'mID': m['external_references'][0]['external_id'], 'name': m['name']}

    relationships = load_attack_data(DATA_TYPE_STIX_ALL_RELATIONSHIPS)
    relationships_mitigates = [r for r in relationships
                               if r['relationship_type'] == 'mitigates'
                               if r['source_ref'].startswith('course-of-action')
                               if r['target_ref'].startswith('attack-pattern')
                               if r['source_ref'] in mitigations_dict]

    # {id: {name: ..., count: ..., name: ...} }
    count_dict = dict()
    for r in relationships_mitigates:
        src_ref = r['source_ref']

        m = mitigations_dict[src_ref]
        if m['mID'] not in count_dict:
            count_dict[m['mID']] = dict()
            count_dict[m['mID']]['count'] = 1
            count_dict[m['mID']]['name'] = m['name']
        else:
            count_dict[m['mID']]['count'] += 1

    count_dict_sorted = dict(sorted(count_dict.items(), key=lambda kv: kv[1]['count'], reverse=True))

    str_format = '{:<6s} {:<14s} {:s}'
    print(str_format.format('Count', 'Mitigation ID', 'Name'))
    print('-' * 60)
    for k, v in count_dict_sorted.items():
        print(str_format.format(str(v['count']), k, v['name']))


def get_statistics_data_sources():
    """
    Print out statistics related to data sources and how many techniques they cover.
    :return:
    """
    techniques = load_attack_data(DATA_TYPE_STIX_ALL_TECH)

    # {data_source: {techniques: [T0001, ...}, count: ...}
    data_sources_dict = {}
    for tech in techniques:
        tech_id = get_attack_id(tech)
        # Not every technique has a data source listed
        data_sources = tech.get('x_mitre_data_sources', None)
        if data_sources:
            for ds in data_sources:
                if ds not in data_sources_dict:
                    data_sources_dict[ds] = {'techniques': [tech_id], 'count': 1}
                else:
                    data_sources_dict[ds]['techniques'].append(tech_id)
                    data_sources_dict[ds]['count'] += 1

    # sort the dict on the value of 'count'
    data_sources_dict_sorted = dict(sorted(data_sources_dict.items(), key=lambda kv: kv[1]['count'], reverse=True))
    str_format = '{:<6s} {:s}'
    print(str_format.format('Count', 'Data Source'))
    print('-' * 50)
    for k, v in data_sources_dict_sorted.items():
        print(str_format.format(str(v['count']), k))


def get_platform_from_yaml(yaml_content):
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

    if platform == ['all']:
        platform = 'all'
    else:
        valid_platform_list = []
        for p in platform:
            if p in PLATFORMS.keys():
                valid_platform_list.append(PLATFORMS[p])
        platform = valid_platform_list
    return platform


def clean_filename(filename):
    """
    Remove invalid characters from filename and maximize it to 200 characters
    :param filename: Input filename
    :return: sanitized filename
    """
    return filename.replace('/', '').replace('\\', '').replace(':', '')[:200]


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


def remove_technique_from_yaml(yaml_content, technique_id):
    """
    Function to delete a specific technique in the YAML content.
    :param techniques: list with all techniques
    :param technique_id: technique_id to look for
    :return: none
    """
    for tech in yaml_content['techniques']:
        if tech['technique_id'] == technique_id:
            yaml_content['techniques'].remove(tech)
            return


def determine_and_set_show_sub_techniques(techniques_layer):
    """
    Function to determine if showSubtechniques should be set. And if so, it will be set in the layer dict.
    :param techniques_layer: dict with items for the Navigator layer file
    :return:
    """
    # determine if technique needs to be collapsed to show sub-techniques
    # show subtechniques when technique contains subtechniques:
    for t in techniques_layer:
        if len(t['techniqueID']) == 5:
            show_sub_techniques = False
            for subtech in techniques_layer:
                if len(subtech['techniqueID']) == 9:
                    if t['techniqueID'] in subtech['techniqueID']:
                        show_sub_techniques = True
                        break
            t['showSubtechniques'] = show_sub_techniques
    # add technique with showSubtechnique attribute, when sub-technique is present and technique isn't:
    techniques_to_add = {}
    for subtech in techniques_layer:
        if len(subtech['techniqueID']) == 9:
            technique_present = False
            # Is technique already added:
            if subtech['techniqueID'][:5] in techniques_to_add.keys():
                technique_present = True
            # Is technique already in the techniques_layer:
            else:
                for t in techniques_layer:
                    if len(t['techniqueID']) == 5:
                        if t['techniqueID'] in subtech['techniqueID']:
                            technique_present = True
            if not technique_present:
                new_tech = dict()
                new_tech['techniqueID'] = subtech['techniqueID'][:5]
                new_tech['showSubtechniques'] = True
                techniques_to_add[new_tech['techniqueID']] = new_tech
    techniques_layer.extend(list(techniques_to_add.values()))
