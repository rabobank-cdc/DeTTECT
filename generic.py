import os
import pickle
from datetime import datetime as dt
import yaml
# Due to performance reasons the import of attackcti is within the function that makes use of this library.

APP_NAME = 'DeTT&CT'
APP_DESC = 'Detect Tactics, Techniques & Combat Threats'
VERSION = '1.0'

EXPIRE_TIME = 60*60*24

DATATYPE_TECH_BY_GROUP = 'mitre_techniques_used_by_group'
DATATYPE_ALL_TECH = 'mitre_all_techniques'
DATATYPE_ALL_GROUPS = 'mitre_all_groups'
DATATYPE_ALL_SOFTWARE = 'mitre_all_software'
DATATYPE_TECH_BY_SOFTWARE = 'mitre_techniques_used_by_software'
DATATYPE_SOFTWARE_BY_GROUP = 'mitre_software_used_by_group'

# Group colors
COLOR_GROUP_OVERLAY_MATCH = '#f9a825'            # orange
COLOR_GROUP_OVERLAY_NO_MATCH = '#ffee58'         # yellow
COLOR_SOFTWARE = '#0d47a1 '                      # dark blue
COLOR_GROUP_AND_SOFTWARE = '#64b5f6 '            # light blue
COLOR_GRADIENT_MIN = '#ffcece'                   # light red
COLOR_GRADIENT_MAX = '#ff0000'                   # red
COLOR_TACTIC_ROW_BACKGRND = '#dddddd'            # light grey
COLOR_GROUP_OVERLAY_ONLY_DETECTION = '#8BC34A'   # green
COLOR_GROUP_OVERLAY_ONLY_VISIBILITY = '#1976D2'  # blue

# data source colors (purple range)
COLOR_DS_25p = '#E1BEE7'
COLOR_DS_50p = '#CE93D8'
COLOR_DS_75p = '#AB47BC'
COLOR_DS_99p = '#7B1FA2'
COLOR_DS_100p = '#4A148C'

# data source colors HAPPY (green range)
COLOR_DS_25p_HAPPY = '#DCEDC8'
COLOR_DS_50p_HAPPY = '#AED581'
COLOR_DS_75p_HAPPY = '#8BC34A'
COLOR_DS_99p_HAPPY = '#689F38'
COLOR_DS_100p_HAPPY = '#33691E'

# Detection colors (green range)
COLOR_D_0 = '#64B5F6'  # Blue: Forensics/Context
COLOR_D_1 = '#DCEDC8'
COLOR_D_2 = '#AED581'
COLOR_D_3 = '#8BC34A'
COLOR_D_4 = '#689F38'
COLOR_D_5 = '#33691E'

# Visibility colors (blue range)
COLOR_V_1 = '#BBDEFB'
COLOR_V_2 = '#64B5F6'
COLOR_V_3 = '#1976D2'
COLOR_V_4 = '#0D47A1'

# Detection and visibility overlay color:
COLOR_OVERLAY_VISIBILITY = COLOR_V_3
COLOR_OVERLAY_DETECTION = COLOR_D_3
COLOR_OVERLAY_BOTH = COLOR_GROUP_OVERLAY_MATCH

FILE_TYPE_DATA_SOURCE_ADMINISTRATION = 'data-source-administration'
FILE_TYPE_TECHNIQUE_ADMINISTRATION = 'technique-administration'
FILE_TYPE_GROUP_ADMINISTRATION = 'group-administration'


def save_attack_data(data, path):
    """
    Save ATT&CK data to disk for the purpose of caching.
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
    :return: MITRE ATT&CK data object
    """
    if os.path.exists("cache/" + data_type):
        with open("cache/" + data_type, 'rb') as f:
            cached = pickle.load(f)
            write_time = cached[1]
            if not (dt.now() - write_time).total_seconds() >= EXPIRE_TIME:
                return cached[0]

    from attackcti import attack_client
    mitre = attack_client()

    json_data = None
    if data_type == DATATYPE_TECH_BY_GROUP:
        json_data = mitre.get_techniques_used_by_group()
    elif data_type == DATATYPE_ALL_TECH:
        json_data = mitre.get_all_techniques()
    elif data_type == DATATYPE_ALL_GROUPS:
        json_data = mitre.get_all_groups()
    elif data_type == DATATYPE_ALL_SOFTWARE:
        json_data = mitre.get_all_software()
    elif data_type == DATATYPE_TECH_BY_SOFTWARE:
        json_data = mitre.get_techniques_used_by_software()
    elif data_type == DATATYPE_SOFTWARE_BY_GROUP:
        json_data = mitre.get_software_used_by_group()

    save_attack_data(json_data, "cache/" + data_type)

    return json_data


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


def get_layer_template_groups(name, max_score, description, stage, platform):
    """
    Prepares a base template for the json layer file that can be loaded into the MITRE ATT&CK Navigator.
    More information on the version 2.1 layer format:
    https://github.com/mitre/attack-navigator/blob/master/layers/LAYERFORMATv2_1.md
    :param name: name
    :param max_score: max_score
    :param description: description
    :param stage: stage (act | prepare)
    :param platform: platform
    :return: layer template dictionary
    """
    layer = _get_base_template(name, description, stage, platform, 3)
    layer['gradient'] = {'colors': [COLOR_GRADIENT_MIN, COLOR_GRADIENT_MAX], 'minValue': 0, 'maxValue': max_score}
    layer['legendItems'] = \
        [
            {'label': 'Tech. ref. for ' + str(1) + ' group', 'color': COLOR_GRADIENT_MIN},
            {'label': 'Tech. ref. for ' + str(max_score) + ' groups', 'color': COLOR_GRADIENT_MAX},
            {'label': 'Groups overlay: tech. in group + overlay', 'color': COLOR_GROUP_OVERLAY_MATCH},
            {'label': 'Groups overlay: tech. in overlay', 'color': COLOR_GROUP_OVERLAY_NO_MATCH},
            {'label': 'Src. of tech. is only software', 'color': COLOR_SOFTWARE},
            {'label': 'Src. of tech. is group(s)/overlay + software', 'color': COLOR_GROUP_AND_SOFTWARE}
        ]
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


def get_technique(techniques, technique_id):
    """
    Generic function to lookup a specific technique_id in a list of dictionaries with techniques.
    :param techniques: list with all techniques
    :param technique_id: technique_id to look for
    :return: the technique you're searching for. None if not found.
    """
    for t in techniques:
        if technique_id == t['technique_id']:
            return t
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
            if t['data_sources'] and i_ds in t['data_sources'] and t['technique_id'] not in my_techniques.keys():
                my_techniques[t['technique_id']] = {}
                my_techniques[t['technique_id']]['my_data_sources'] = [i_ds, ]
                my_techniques[t['technique_id']]['data_sources'] = t['data_sources']
                my_techniques[t['technique_id']]['tactics'] = t['tactic']
                my_techniques[t['technique_id']]['products'] = my_data_sources[i_ds]['products']
            elif t['data_sources'] and i_ds in t['data_sources'] and t['technique_id'] in my_techniques.keys():
                my_techniques[t['technique_id']]['my_data_sources'].append(i_ds)
    return my_techniques


def get_all_mitre_data_sources():
    """
    Gets all the data sources from the techniques and make a unique sorted list of it.
    :return: a sorted list with all data sources
    """
    techniques = load_attack_data(DATATYPE_ALL_TECH)
    data_sources = set()
    for t in techniques:
        if t['data_sources']:
            for ds in t['data_sources']:
                if ds not in data_sources:
                    data_sources.add(ds)
    return sorted(data_sources)


def check_file_type(filename, file_type=None):
    """
    Check if the provided YAML file has the key 'file_type' and possible if that key matches a specific value.
    :param filename: path to a YAML file
    :param file_type: value to check against the 'file_type' key in the YAML file
    :return: the file_type if present, else None is returned.
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
                return yaml_content['file_type']
        else:
            return yaml_content['file_type']



def upgrade_technique_yaml_10_to_11(filename):
    # Load the file:
    with open(filename, 'r') as yaml_file:
        yaml_content = yaml.load(yaml_file, Loader=yaml.FullLoader)

    for t in yaml_content['techniques']:
        t['technique']

    # Save the file:
    yaml_string = '%YAML 1.2\n---\n' + yaml.dump(yaml_content, sort_keys=False).replace('null', '')
    output_filename = filename.replace('.yaml', '_copy.yaml')
    with open(output_filename, 'w') as f:
        f.write(yaml_string)

