from constants import *


def _get_base_template(name, description, platform, sorting):
    """
    Prepares a base template for the json layer file that can be loaded into the MITRE ATT&CK Navigator.
    More information on the layer format can be found here: https://github.com/mitre/attack-navigator/blob/master/layers/
    :param name: name
    :param description: description
    :param platform: platform
    :param sorting: sorting
    :return: layer template dictionary
    """
    layer = dict()
    layer['name'] = name
    layer['versions'] = {'navigator': '4.4', 'layer': '4.2'}
    layer['domain'] = 'enterprise-attack'
    layer['description'] = description

    layer['filters'] = {'platforms': platform}
    layer['sorting'] = sorting
    layer['layout'] = {"layout": "flat", "aggregateFunction": "sum",
                       "showAggregateScores": True, "countUnscored": False,
                       "showName": True, "showID": False}
    layer['hideDisable'] = False
    layer['selectSubtechniquesWithParent'] = False
    layer['techniques'] = []

    layer['showTacticRowBackground'] = False
    layer['tacticRowBackground'] = COLOR_TACTIC_ROW_BACKGRND
    layer['selectTechniquesAcrossTactics'] = True
    return layer


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


def get_layer_template_groups(name, max_count, description, platform, overlay_type):
    """
    Prepares a base template for the json layer file that can be loaded into the MITRE ATT&CK Navigator.
    More information on the layer format can be found here: https://github.com/mitre/attack-navigator/blob/master/layers/
    :param name: name
    :param max_count: the sum of all count values
    :param description: description
    :param platform: platform
    :param overlay_type: group, visibility or detection
    :return: layer template dictionary
    """
    layer = _get_base_template(name, description, platform, 3)
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


def get_layer_template_detections(name, description, platform):
    """
    Prepares a base template for the json layer file that can be loaded into the MITRE ATT&CK Navigator.
    More information on the layer format can be found here: https://github.com/mitre/attack-navigator/blob/master/layers/
    :param name: name
    :param description: description
    :param platform: platform
    :return: layer template dictionary
    """
    layer = _get_base_template(name, description, platform, 0)
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


def get_layer_template_data_sources(name, description, platform):
    """
    Prepares a base template for the json layer file that can be loaded into the MITRE ATT&CK Navigator.
    More information on the layer format can be found here: https://github.com/mitre/attack-navigator/blob/master/layers/
    :param name: name
    :param description: description
    :param platform: platform
    :return: layer template dictionary
    """
    layer = _get_base_template(name, description, platform, 0)
    layer['legendItems'] = \
        [
            {'label': '1-25% of data sources available', 'color': COLOR_DS_25p},
            {'label': '26-50% of data sources available', 'color': COLOR_DS_50p},
            {'label': '51-75% of data sources available', 'color': COLOR_DS_75p},
            {'label': '76-99% of data sources available', 'color': COLOR_DS_99p},
            {'label': '100% of data sources available', 'color': COLOR_DS_100p}
    ]
    return layer


def get_layer_template_visibility(name, description, platform):
    """
    Prepares a base template for the json layer file that can be loaded into the MITRE ATT&CK Navigator.
    More information on the layer format can be found here: https://github.com/mitre/attack-navigator/blob/master/layers/
    :param name: name
    :param description: description
    :param platform: platform
    :return: layer template dictionary
    """
    layer = _get_base_template(name, description, platform, 0)
    layer['legendItems'] = \
        [
            {'label': 'Visibility score 1: Minimal', 'color': COLOR_V_1},
            {'label': 'Visibility score 2: Medium', 'color': COLOR_V_2},
            {'label': 'Visibility score 3: Good', 'color': COLOR_V_3},
            {'label': 'Visibility score 4: Excellent', 'color': COLOR_V_4}
    ]
    return layer


def get_layer_template_layered(name, description, platform):
    """
    Prepares a base template for the json layer file that can be loaded into the MITRE ATT&CK Navigator.
    More information on the layer format can be found here: https://github.com/mitre/attack-navigator/blob/master/layers/
    :param name: name
    :param description: description
    :param platform: platform
    :return: layer template dictionary
    """
    layer = _get_base_template(name, description, platform, 0)
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


def add_metadata_technique_object(technique, obj_type, metadata):
    """
    Add the metadata for a detection or visibility object as used within any type of overlay.
    :param technique: technique object containing both the visibility and detection object
    :param obj_type: valid values are 'detection' and 'visibility'
    :param metadata: a list to which the metadata will be added
    :return: the created metadata as a list
    """
    from generic import calculate_score, get_latest_comment

    if obj_type not in ['detection', 'visibility']:
        raise Exception("Invalid value for 'obj_type' provided.")

    metadata.append({'divider': True})
    metadata.append({'name': 'Applicable to', 'value': ', '.join(set([a for v in technique[obj_type] for a in v['applicable_to']]))})  # noqa
    metadata.append({'name': '' + obj_type.capitalize() + ' score', 'value': ', '.join([str(calculate_score(technique[obj_type]))])})  # noqa
    if obj_type == 'detection':
        metadata.append({'name': '' + obj_type.capitalize() + ' location', 'value': ', '.join(set([a for v in technique[obj_type] for a in v['location']]))})  # noqa
    metadata.append({'name': '' + obj_type.capitalize() + ' comment', 'value': ' | '.join(set(filter(lambda x: x != '', map(lambda k: k['comment'], technique[obj_type]))))})  # noqa
    metadata.append({'name': '' + obj_type.capitalize() + ' score comment', 'value': ' | '.join(set(filter(lambda x: x != '', map(lambda i: get_latest_comment(i), technique[obj_type]))))})  # noqa

    return metadata
