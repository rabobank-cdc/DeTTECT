from constants import *
from generic import *
from copy import deepcopy


def _get_base_template(name, description, platform, sorting, domain, layer_settings):
    """
    Prepares a base template for the json layer file that can be loaded into the MITRE ATT&CK Navigator.
    More information on the layer format can be found here: https://github.com/mitre/attack-navigator/blob/master/layers/
    :param name: name
    :param description: description
    :param platform: platform
    :param sorting: sorting
    :param domain: the specified domain
    :param layer_settings: settings for the Navigator layer
    :return: layer template dictionary
    """
    layer = dict()
    layer['name'] = name
    layer['versions'] = {'navigator': ATTACK_NAVIGATOR_VERSION, 'layer': ATTACK_LAYER_VERSION}
    if 'includeAttackVersion' in layer_settings.keys() and layer_settings['includeAttackVersion'] == 'True':
        layer['versions']['attack'] = ATTACK_VERSION
    layer['domain'] = domain
    layer['description'] = description

    layer['filters'] = {'platforms': platform}
    layer['sorting'] = sorting
    layer['layout'] = {"layout": "flat", "aggregateFunction": "sum",
                       "showAggregateScores": False, "countUnscored": False,
                       "showName": True, "showID": False}

    # Override layout settings with settings that are given at the CLI:
    for setting_key, setting_value in layer_settings.items():
        for k, v in LAYER_SETTINGS.items():
            if setting_key == k and setting_value.lower() in [val.lower() for val in v] and setting_key in LAYER_LAYOUT_SETTINGS:
                if setting_value.lower() in ("true", "false"):
                    layer['layout'][setting_key] = True if setting_value.lower() == "true" else False
                else:
                    layer['layout'][setting_key] = setting_value.lower()

    layer['hideDisabled'] = False
    layer['selectSubtechniquesWithParent'] = False
    layer['techniques'] = []

    layer['showTacticRowBackground'] = False
    layer['tacticRowBackground'] = COLOR_TACTIC_ROW_BACKGRND
    layer['selectTechniquesAcrossTactics'] = True
    return layer


def determine_and_set_show_sub_techniques(techniques_layer, techniques, layer_settings):
    """
    Function to determine if showSubtechniques should be set. And if so, it will be set in the layer dict.
    :param techniques_layer: dict with items for the Navigator layer file
    :param techniques: dict with all ATT&CK techniques
    :param layer_settings: settings for the Navigator layer
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
    techniques_to_add = []
    already_added = set()
    for subtech in techniques_layer:
        if len(subtech['techniqueID']) == 9:
            technique_present = False
            # Is technique already in the techniques_layer:
            for t in techniques_layer:
                if len(t['techniqueID']) == 5:
                    if t['techniqueID'] in subtech['techniqueID']:
                        technique_present = True
            if not technique_present:
                technique_id = subtech['techniqueID'][:5]
                technique = get_technique(techniques, technique_id)
                
                tactics = []
                if 'includeTactic' in layer_settings.keys() and layer_settings['includeTactic'] == 'True':
                    for kill_chain_phase in technique['kill_chain_phases']:
                        if kill_chain_phase['kill_chain_name'] == 'mitre-attack':
                            tactics.append(kill_chain_phase['phase_name'])
                else:
                    tactics.append(None)
                
                new_tech = dict()
                new_tech['techniqueID'] = technique_id
                new_tech['showSubtechniques'] = True
                
                for tactic in tactics:
                    already_added_key = technique_id +'-' +str(tactic)
                    if already_added_key not in already_added:
                        if tactic is not None:
                            new_tech['tactic'] = tactic
                        
                        techniques_to_add.append(deepcopy(new_tech))
                        already_added.add(already_added_key)
    
    techniques_layer.extend(techniques_to_add)


def get_layer_template_groups(name, max_count, description, platform, overlay_type, domain, layer_settings):
    """
    Prepares a base template for the json layer file that can be loaded into the MITRE ATT&CK Navigator.
    More information on the layer format can be found here: https://github.com/mitre/attack-navigator/blob/master/layers/
    :param name: name
    :param max_count: the sum of all count values
    :param description: description
    :param platform: platform
    :param overlay_type: group, visibility or detection
    :param domain: the specified domain
    :param layer_settings: settings for the Navigator layer
    :return: layer template dictionary
    """
    layer = _get_base_template(name, description, platform, 3, domain, layer_settings)
    layer['gradient'] = {'colors': [COLOR_GRADIENT_MIN, COLOR_GRADIENT_MAX], 'minValue': 0, 'maxValue': max_count}
    layer['legendItems'] = []
    layer['legendItems'].append({'label': 'Tech. not often used', 'color': COLOR_GRADIENT_MIN})
    layer['legendItems'].append({'label': 'Tech. used frequently', 'color': COLOR_GRADIENT_MAX})

    if overlay_type in (OVERLAY_TYPE_GROUP, OVERLAY_TYPE_CAMPAIGN):
        title = 'Groups' if overlay_type == OVERLAY_TYPE_GROUP else 'Campaigns'
        layer['legendItems'].append({'label': f'{title} overlay: tech. in group/campaign + overlay', 'color': COLOR_GROUP_OVERLAY_MATCH})
        layer['legendItems'].append({'label': f'{title} overlay: tech. in overlay', 'color': COLOR_GROUP_OVERLAY_NO_MATCH})
        layer['legendItems'].append({'label': 'Src. of tech. is only software', 'color': COLOR_SOFTWARE})
        layer['legendItems'].append({'label': 'Src. of tech. is group/campaign/overlay + software', 'color': COLOR_GROUP_AND_SOFTWARE})
    elif overlay_type == OVERLAY_TYPE_DETECTION:
        layer['legendItems'].append({'label': 'Tech. in group/campaign + detection score 0: Forensics/Context', 'color': COLOR_O_0})
        layer['legendItems'].append({'label': 'Tech. in group/campaign + detection score 1: Basic', 'color': COLOR_O_1})
        layer['legendItems'].append({'label': 'Tech. in group/campaign + detection score 2: Fair', 'color': COLOR_O_2})
        layer['legendItems'].append({'label': 'Tech. in group/campaign + detection score 3: Good', 'color': COLOR_O_3})
        layer['legendItems'].append({'label': 'Tech. in group/campaign + detection score 4: Very good', 'color': COLOR_O_4})
        layer['legendItems'].append({'label': 'Tech. in group/campaign + detection score 5: Excellent', 'color': COLOR_O_5})
        layer['legendItems'].append({'label': 'Tech. in detection, score 0: Forensics/Context', 'color': COLOR_D_0})
        layer['legendItems'].append({'label': 'Tech. in detection, score 1: Basic', 'color': COLOR_D_1})
        layer['legendItems'].append({'label': 'Tech. in detection, score 2: Fair', 'color': COLOR_D_2})
        layer['legendItems'].append({'label': 'Tech. in detection, score 3: Good', 'color': COLOR_D_3})
        layer['legendItems'].append({'label': 'Tech. in detection, score 4: Very good', 'color': COLOR_D_4})
        layer['legendItems'].append({'label': 'Tech. in detection, score 5: Excellent', 'color': COLOR_D_5})
    elif overlay_type == OVERLAY_TYPE_VISIBILITY:
        layer['legendItems'].append({'label': 'Tech. in group/campaign + visibility score 1: Minimal', 'color': COLOR_O_1})
        layer['legendItems'].append({'label': 'Tech. in group/campaign + visibility score 2: Medium', 'color': COLOR_O_2})
        layer['legendItems'].append({'label': 'Tech. in group/campaign + visibility score 3: Good', 'color': COLOR_O_3})
        layer['legendItems'].append({'label': 'Tech. in group/campaign + visibility score 4: Excellent', 'color': COLOR_O_4})
        layer['legendItems'].append({'label': 'Tech. in visibility, score 1: Minimal', 'color': COLOR_V_1})
        layer['legendItems'].append({'label': 'Tech. in visibility, score 2: Medium', 'color': COLOR_V_2})
        layer['legendItems'].append({'label': 'Tech. in visibility, score 3: Good', 'color': COLOR_V_3})
        layer['legendItems'].append({'label': 'Tech. in visibility, score 4: Excellent', 'color': COLOR_V_4})

    return layer


def get_layer_template_detections(name, description, platform, domain, layer_settings):
    """
    Prepares a base template for the json layer file that can be loaded into the MITRE ATT&CK Navigator.
    More information on the layer format can be found here: https://github.com/mitre/attack-navigator/blob/master/layers/
    :param name: name
    :param description: description
    :param platform: platform
    :param domain: the specified domain
    :param layer_settings: settings for the Navigator layer
    :return: layer template dictionary
    """
    layer = _get_base_template(name, description, platform, 0, domain, layer_settings)
    layer['gradient'] = {'colors': [COLOR_GRADIENT_DISABLE, COLOR_GRADIENT_DISABLE], 'minValue': 0, 'maxValue': 10000}
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


def get_layer_template_data_sources(name, description, platform, domain, layer_settings):
    """
    Prepares a base template for the json layer file that can be loaded into the MITRE ATT&CK Navigator.
    More information on the layer format can be found here: https://github.com/mitre/attack-navigator/blob/master/layers/
    :param name: name
    :param description: description
    :param platform: platform
    :param domain: the specified domain
    :param layer_settings: settings for the Navigator layer
    :return: layer template dictionary
    """
    layer = _get_base_template(name, description, platform, 0, domain, layer_settings)
    layer['legendItems'] = \
        [
            {'label': '1-25% of data sources available', 'color': COLOR_DS_25p},
            {'label': '26-50% of data sources available', 'color': COLOR_DS_50p},
            {'label': '51-75% of data sources available', 'color': COLOR_DS_75p},
            {'label': '76-99% of data sources available', 'color': COLOR_DS_99p},
            {'label': '100% of data sources available', 'color': COLOR_DS_100p}
    ]
    return layer


def get_layer_template_visibility(name, description, platform, domain, layer_settings):
    """
    Prepares a base template for the json layer file that can be loaded into the MITRE ATT&CK Navigator.
    More information on the layer format can be found here: https://github.com/mitre/attack-navigator/blob/master/layers/
    :param name: name
    :param description: description
    :param platform: platform
    :param domain: the specified domain
    :param layer_settings: settings for the Navigator layer
    :return: layer template dictionary
    """
    layer = _get_base_template(name, description, platform, 0, domain, layer_settings)
    layer['gradient'] = {'colors': [COLOR_GRADIENT_DISABLE, COLOR_GRADIENT_DISABLE], 'minValue': 0, 'maxValue': 10000}
    layer['legendItems'] = \
        [
            {'label': 'Visibility score 1: Minimal', 'color': COLOR_V_1},
            {'label': 'Visibility score 2: Medium', 'color': COLOR_V_2},
            {'label': 'Visibility score 3: Good', 'color': COLOR_V_3},
            {'label': 'Visibility score 4: Excellent', 'color': COLOR_V_4}
    ]
    return layer


def get_layer_template_layered(name, description, platform, domain, layer_settings):
    """
    Prepares a base template for the json layer file that can be loaded into the MITRE ATT&CK Navigator.
    More information on the layer format can be found here: https://github.com/mitre/attack-navigator/blob/master/layers/
    :param name: name
    :param description: description
    :param platform: platform
    :param domain: the specified domain
    :param layer_settings: settings for the Navigator layer
    :return: layer template dictionary
    """
    layer = _get_base_template(name, description, platform, 0, domain, layer_settings)
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


def make_layer_metadata_compliant(metadata):
    """
    Make sure the metadata values in the Navigator layer file are compliant with the expected data structure
    from the latest version on: https://github.com/mitre-attack/attack-navigator/tree/master/layers
    :param metadata: list of metadata dictionaries
    :return: compliant list of metadata dictionaries
    """
    for md_item in metadata:
        if not 'divider' in md_item.keys() and (not md_item['value'] or md_item['value'] == ''):
            md_item['value'] = '-'

    return metadata


def add_metadata_technique_object(technique, obj_type, metadata, count_detections):
    """
    Add the metadata for a detection or visibility object as used within any type of overlay.
    :param technique: technique object containing both the visibility and detection object
    :param obj_type: valid values are 'detection' and 'visibility'
    :param metadata: a list to which the metadata will be added
    :param count_detections: option for the Navigator layer output: count detections instead of listing detections
    :return: the created metadata as a list
    """
    from generic import calculate_score, get_latest_comment, count_detections_in_location

    if obj_type not in ['detection', 'visibility']:
        raise Exception("Invalid value for 'obj_type' provided.")

    metadata.append({'divider': True})
    metadata.append({'name': 'Applicable to', 'value': ', '.join(set([a for v in technique[obj_type] for a in v['applicable_to']]))})  # noqa
    metadata.append({'name': '' + obj_type.capitalize() + ' score', 'value': ', '.join([str(calculate_score(technique[obj_type]))])})  # noqa
    if obj_type == 'detection':
        location = ''
        if count_detections:
            location_count = {}

            for applicable_to in technique['detection']:
                for l in applicable_to['location']:
                    location_splitted = l.split(': ')
                    if len(location_splitted) == 2:
                        if location_splitted[0] not in location_count.keys():
                            location_count[location_splitted[0]] = 0
                        location_count[location_splitted[0]] += 1
                    else:
                        if 'Detections' not in location_count.keys():
                            location_count['Detections'] = 0
                        location_count['Detections'] += 1

            for l, c in location_count.items():
                location += f"{l}: {c}. "
        else:
            location = ', '.join(set([a for v in technique[obj_type] for a in v['location']]))
        metadata.append({'name': '' + obj_type.capitalize() + ' location', 'value': location})  # noqa
    metadata.append({'name': '' + obj_type.capitalize() + ' comment', 'value': ' | '.join(set(filter(lambda x: x != '', map(lambda k: k['comment'], technique[obj_type]))))})  # noqa
    metadata.append({'name': '' + obj_type.capitalize() + ' score comment', 'value': ' | '.join(set(filter(lambda x: x != '', map(lambda i: get_latest_comment(i), technique[obj_type]))))})  # noqa

    return metadata
