import simplejson
from generic import *

CG_GROUPS = {}


def is_in_group(json_groups, argument_groups):
    """
    Check if the two dicts (json_groups and argument_groups) have any groups in common based on their names/aliases.
    :param json_groups: group aliases from ATT&CK
    :param argument_groups: group names provided via the command line by the user
    :return: true or false
    """
    json_groups = list(map(lambda x: x.lower(), json_groups))

    for group in argument_groups:
        if group in json_groups:
            return True

    return False


def is_group_found(groups_found, argument_groups):
    """
    Check if a group that has been provided using '-g/--groups'/'-o/--overlay' is present within MITRE ATT&CK.
    :param groups_found: groups that are found in the ATT&CK data
    :param argument_groups: groups provided via the command line by the user
    :return: returns boolean that indicates if the group is found
    """
    groups = load_attack_data(DATA_TYPE_STIX_ALL_GROUPS)

    for group_arg in argument_groups:
        if group_arg == 'all':  # this one will be ignored as it does not make any sense for this function
            return True

        group_id = None

        for group in groups:  # is the group provided via the command line known in ATT&CK?
            if 'aliases' in group:
                group_aliases_lower = list(map(lambda x: x.lower(), group['aliases']))
                if group_arg in group_aliases_lower or group_arg == get_attack_id(group).lower():
                    group_id = get_attack_id(group)

        if not group_id:  # the group that has been provided through the command line cannot be found in ATT&CK
            print('[!] Unknown group: ' + group_arg)
            return False
        elif group_id not in groups_found:  # group not present in filtered data sate (i.e. platform and stage)
            print('[!] Group not part of the data set: ' + group_arg)
            return False
        else:
            return True


def get_software_techniques(groups, stage, platform):
    """
    Get all techniques (in a dict) from the provided list of groups in relation to the software these groups use,
    and hence techniques they support.
    :param groups: ATT&CK groups
    :param stage: attack or pre-attack
    :param platform: the applicable platform
    :return: dictionary with info on groups
    """
    # { group_id: {group_name: NAME, techniques: set{id, ...} } }
    groups_dict = {}

    tech_by_software = load_attack_data(DATA_TYPE_CUSTOM_TECH_BY_SOFTWARE)

    # { software_id: [technique, ...] }
    software_dict = {}
    for tech in tech_by_software:
        if tech['software_id'] not in software_dict:
            software_dict[tech['software_id']] = set([tech['technique_id']])
        else:
            software_dict[tech['software_id']].add(tech['technique_id'])

    # groups is a YAML file
    if os.path.isfile(str(groups)):
        with open(groups, 'r') as yaml_file:
            config = yaml.load(yaml_file, Loader=yaml.FullLoader)

        for group in config['groups']:
            if group['enabled']:
                group_id = generate_group_id(group['group_name'], group['campaign'])
                groups_dict[group_id] = dict()

                groups_dict[group_id]['group_name'] = group['group_name']
                groups_dict[group_id]['techniques'] = set()
                groups_dict[group_id]['campaign'] = group['campaign']
                groups_dict[group_id]['software'] = group['software_id']

                if group['software_id']:
                    for soft_id in group['software_id']:
                        try:
                            groups_dict[group_id]['techniques'].update(software_dict[soft_id])
                        except KeyError:
                            print('[!] unknown ATT&CK software ID: ' + soft_id)

    # groups are provided as arguments via the command line
    else:
        software_by_group = load_attack_data(DATA_TYPE_CUSTOM_SOFTWARE_BY_GROUP)

        for s in software_by_group:
            # software matches the ATT&CK Matrix and platform
            # and the group is a group we are interested in
            if s['x_mitre_platforms']:  # their is some software that do not have a platform, skip those
                if s['matrix'] == 'mitre-'+stage and (platform in s['x_mitre_platforms'] or platform == 'all') and \
                        (groups[0] == 'all' or s['group_id'].lower() in groups or is_in_group(s['aliases'], groups)):
                    if s['group_id'] not in groups_dict:
                        groups_dict[s['group_id']] = {'group_name': s['name']}
                        groups_dict[s['group_id']]['techniques'] = set()
                    groups_dict[s['group_id']]['techniques'].update(software_dict[s['software_id']])

    return groups_dict


def generate_group_id(group_name, campaign):
    # CG_GROUPS = { group_name+campaign: id } }
    """
    Generate a custom group id.
    :param group_name: group name as used within the YAML file
    :param campaign: campaign as used within the YAML file
    :return: custom group identifier string (e.g. CG0001)
    """
    global CG_GROUPS

    if not CG_GROUPS:
        new_id = 1
    elif group_name + campaign not in CG_GROUPS:
        new_id = len(CG_GROUPS) + 1

    if group_name + campaign not in CG_GROUPS:
        length = len(str(new_id))
        if length > 9:
            cg_id = 'CG00' + str(new_id)
        elif length > 99:
            cg_id = 'CG0' + str(new_id)
        elif length > 999:
            cg_id = 'CG' + str(new_id)
        else:
            cg_id = 'CG000' + str(new_id)

        CG_GROUPS[group_name + campaign] = cg_id

    return CG_GROUPS[group_name + campaign]


def get_group_techniques(groups, stage, platform, file_type):
    """
    Get all techniques (in a dict) from the provided list of groups
    :param groups: group ID, group name/alias or a YAML file with group(s) data
    :param stage: attack or pre-attack
    :param platform: all, Linux, macOS, Windows
    :param file_type: the file type of the YAML file as present in the key 'file_type'
    :return: returns dictionary with all techniques from the provided list of groups or -1 when group is not found
    """
    # { group_id: {group_name: NAME, techniques: set{id, ...} } }
    groups_dict = {}
    groups_found = set()

    # groups is a YAML file
    if file_type == FILE_TYPE_GROUP_ADMINISTRATION:
        with open(groups, 'r') as yaml_file:
            config = yaml.load(yaml_file, Loader=yaml.FullLoader)

        for group in config['groups']:
            if group['enabled']:
                campaign = group['campaign'] if group['campaign'] else ''
                group_id = generate_group_id(group['group_name'], campaign)
                groups_dict[group_id] = dict()

                groups_dict[group_id]['group_name'] = group['group_name']
                if type(group['technique_id']) == list:
                    groups_dict[group_id]['techniques'] = set(group['technique_id'])
                    groups_dict[group_id]['weight'] = dict((i, 1) for i in group['technique_id'])
                elif type(group['technique_id']) == dict:
                    groups_dict[group_id]['techniques'] = set(group['technique_id'].keys())
                    groups_dict[group_id]['weight'] = group['technique_id']
                groups_dict[group_id]['campaign'] = group['campaign']
                groups_dict[group_id]['software'] = group['software_id']
    else:
        # groups are provided as arguments via the command line
        all_groups_tech = load_attack_data(DATA_TYPE_CUSTOM_TECH_BY_GROUP)

        for gr in all_groups_tech:
            platforms = gr['x_mitre_platforms']
            if not platforms:
                # we just set this to an random legit value, because for pre-attack 'platform' is not used
                platforms = 'Windows'

            # group matches the: matrix/stage, platform and the group(s) we are interested in
            if gr['matrix'] == 'mitre-'+stage and (platform in platforms or platform == 'all') and \
                    (groups[0] == 'all' or gr['group_id'].lower() in groups or is_in_group(gr['aliases'], groups)):
                if gr['group_id'] not in groups_dict:
                    groups_found.add(gr['group_id'])
                    groups_dict[gr['group_id']] = {'group_name': gr['name']}
                    groups_dict[gr['group_id']]['techniques'] = set()
                    groups_dict[gr['group_id']]['weight'] = dict()

                groups_dict[gr['group_id']]['techniques'].add(gr['technique_id'])
                groups_dict[gr['group_id']]['weight'][gr['technique_id']] = 1

        # do not call 'is_group_found' when groups is a YAML file
        # (this could contain groups that do not exists within ATT&CK)
        if not os.path.isfile(str(groups)):
            found = is_group_found(groups_found, groups)
            if not found:
                return -1

    return groups_dict


def get_detection_techniques(filename, filter_applicable_to):
    """
    Get all techniques (in a dict) from the detection administration
    :param filename: path to the YAML technique administration file
    :param filter_applicable_to: filter techniques based on applicable_to field in techniques administration YAML file
    :return: groups dictionary, loaded techniques from administration YAML file
    """
    # { group_id: {group_name: NAME, techniques: set{id, ...} } }
    groups_dict = {}

    detection_techniques, name, platform = load_techniques(filename, 'detection', filter_applicable_to)

    group_id = 'DETECTION'
    groups_dict[group_id] = {}
    groups_dict[group_id]['group_name'] = 'Detection'
    groups_dict[group_id]['techniques'] = set()
    groups_dict[group_id]['weight'] = dict()
    for t, v in detection_techniques.items():
        s = calculate_score(v['detection'])
        if s > 0:
            groups_dict[group_id]['techniques'].add(t)
            groups_dict[group_id]['weight'][t] = 1

    return groups_dict, detection_techniques


def get_visibility_techniques(filename, filter_applicable_to):
    """
    Get all techniques (in a dict) from the detections administration
    :param filename: path to the YAML technique administration file
    :param filter_applicable_to: filter techniques based on applicable_to field in techniques administration YAML file
    :return: dictionary
    """
    # { group_id: {group_name: NAME, techniques: set{id, ...} } }
    groups_dict = {}

    visibility_techniques, name, platform = load_techniques(filename, 'visibility', filter_applicable_to)

    group_id = 'VISIBILITY'
    groups_dict[group_id] = {}
    groups_dict[group_id]['group_name'] = 'Visibility'
    groups_dict[group_id]['techniques'] = set()
    groups_dict[group_id]['weight'] = dict()
    for t, v in visibility_techniques.items():
        s = calculate_score(v['visibility'])
        if s > 0:
            groups_dict[group_id]['techniques'].add(t)
            groups_dict[group_id]['weight'][t] = 1

    return groups_dict, visibility_techniques


def get_technique_count(groups, groups_overlay, groups_software, overlay_type, all_techniques):
    """
    Create a dict with all involved techniques and their relevant count/score
    :param groups: a dict with data on groups
    :param groups_overlay: a dict with data on the groups to overlay
    :param groups_software: a dict with with data on which techniques are used within related software
    :param overlay_type: group, visibility or detection
    :param all_techniques: dict containing all technique data for visibility or detection
    :return: dictionary, max_count
    """
    # { technique_id: {count: ..., groups: set{} }
    techniques_dict = {}

    for group, v in groups.items():
        for tech in v['techniques']:
            if tech not in techniques_dict:
                techniques_dict[tech] = dict()
                techniques_dict[tech]['groups'] = set()
                techniques_dict[tech]['count'] = v['weight'][tech]

            # We only want to increase the score when comparing groups and not for visibility or detection.
            # This allows to have proper sorting of the heat map, which in turn improves the ability to visually
            # compare this heat map with the detection/visibility ATT&CK Navigator layers.
            else:
                techniques_dict[tech]['count'] += v['weight'][tech]
            techniques_dict[tech]['groups'].add(group)

    max_count = max(techniques_dict.values(), key=lambda v: v['count'])['count']

    # create dict {tech_id: score+max_tech_count} to be used for when doing an overlay of the type visibility or detection
    if overlay_type != OVERLAY_TYPE_GROUP:
        dict_tech_score = {}
        list_tech = groups_overlay[overlay_type.upper()]['techniques']
        for tech in list_tech:
            dict_tech_score[tech] = calculate_score(all_techniques[tech][overlay_type]) + max_count

    for group, v in groups_overlay.items():
        for tech in v['techniques']:
            if tech not in techniques_dict:
                techniques_dict[tech] = dict()
                techniques_dict[tech]['groups'] = set()
                if overlay_type == OVERLAY_TYPE_GROUP:
                    techniques_dict[tech]['count'] = v['weight'][tech]
                else:
                    techniques_dict[tech]['count'] = dict_tech_score[tech]
            elif group in groups:
                if tech not in groups[group]['techniques']:
                    if overlay_type == OVERLAY_TYPE_GROUP:
                        techniques_dict[tech]['count'] += v['weight'][tech]
                    else:
                        techniques_dict[tech]['count'] = dict_tech_score[tech]
                    # Only do this when it was not already counted by being part of 'groups'.
                    # Meaning the group in 'groups_overlay' was also part of 'groups' (match on Group ID) and the
                    # technique was already counted for that group / it is not a new technique for that group coming
                    # from a YAML file
            else:
                if overlay_type == OVERLAY_TYPE_GROUP:
                    # increase count when the group in the YAML file is a custom group
                    techniques_dict[tech]['count'] += v['weight'][tech]
                else:
                    techniques_dict[tech]['count'] = dict_tech_score[tech]

            techniques_dict[tech]['groups'].add(group)

    for group, v in groups_software.items():
        for tech in v['techniques']:
            if tech not in techniques_dict:
                techniques_dict[tech] = dict()
                techniques_dict[tech]['count'] = 0
                # we will not adjust the scoring for groups_software. We will just set the the score to 0.
                # This will later be used for the colouring of the heat map.
            if 'groups' not in techniques_dict[tech]:
                techniques_dict[tech]['groups'] = set()
            techniques_dict[tech]['groups'].add(group)

    return techniques_dict, max_count


def get_technique_layer(techniques_count, groups, overlay, groups_software, overlay_file_type, overlay_type,
                        all_techniques):
    """
    Create the technique layer that will be part of the ATT&CK navigator json file
    :param techniques_count: involved techniques with count (to be used within the scores)
    :param groups: a dict with data on groups
    :param overlay: a dict with data on the groups to overlay
    :param groups_software: a dict with with data on which techniques are used within related software
    :param overlay_file_type: the file type of the YAML file as present in the key 'file_type'
    :param overlay_type: group, visibility or detection
    :param all_techniques: dictionary with all techniques loaded from techniques administration YAML file
    :return: dictionary
    """
    techniques_layer = []

    # { technique_id: {count: ..., groups: set{} }
    # add the technique count/scoring
    for tech, v in techniques_count.items():
        t = dict()
        t['techniqueID'] = tech
        t['score'] = v['count']
        t['metadata'] = []
        metadata_dict = dict()

        for group, values in groups.items():
            if tech in values['techniques']:  # we do not color this one because that's done using the scoring
                if 'Groups' not in metadata_dict:
                    metadata_dict['Groups'] = set()
                metadata_dict['Groups'].add(values['group_name'])

                # this will only be effective when loading a YAML files that have a value for the key 'campaign'
                if 'campaign' in values:
                    if 'Campaign' not in metadata_dict:
                        metadata_dict['Campaign'] = set()
                    metadata_dict['Campaign'].add(values['campaign'])

        # change the color and add metadata to make the groups overlay visible
        for group, values in overlay.items():
            if tech in values['techniques']:
                # Determine color:
                if len(v['groups'].intersection(set(groups.keys()))) > 0:
                    # if the technique is both present in the group (-g/--groups) and the groups overlay (-o/--overlay)
                    t['color'] = COLOR_GROUP_OVERLAY_MATCH
                else:
                    # the technique is only present in the overlay and not in the provided groups (-g/--groups)
                    if overlay_file_type == FILE_TYPE_TECHNIQUE_ADMINISTRATION:
                        if overlay_type == OVERLAY_TYPE_VISIBILITY:
                            t['color'] = COLOR_GROUP_OVERLAY_ONLY_VISIBILITY
                        elif overlay_type == OVERLAY_TYPE_DETECTION:
                            t['color'] = COLOR_GROUP_OVERLAY_ONLY_DETECTION
                    else:
                        t['color'] = COLOR_GROUP_OVERLAY_NO_MATCH

                # Add applicable_to to metadata in case of overlay for detection/visibility:
                if overlay_file_type == FILE_TYPE_TECHNIQUE_ADMINISTRATION:
                    metadata_dict['Applicable to'] = set([a for v in all_techniques[tech][overlay_type] for a in v['applicable_to']])
                    metadata_dict['Detection score'] = [str(calculate_score(all_techniques[tech]['detection']))]
                    metadata_dict['Visibility score'] = [str(calculate_score(all_techniques[tech]['visibility']))]

                if 'Overlay' not in metadata_dict:
                    metadata_dict['Overlay'] = set()
                metadata_dict['Overlay'].add(values['group_name'])

                # this will only be effective when loading a YAML files that has a value for the key 'campaign'
                if 'campaign' in values:
                    if 'Campaign' not in metadata_dict:
                        metadata_dict['Campaign'] = set()
                    metadata_dict['Campaign'].add(values['campaign'])

        # change the color and add metadata to make the groups software overlay visible
        for group, values in groups_software.items():  # TODO add support for campaign info in layer metadata
            if tech in values['techniques']:
                if t['score'] > 0:
                    t['color'] = COLOR_GROUP_AND_SOFTWARE
                else:
                    t['color'] = COLOR_SOFTWARE

                if 'Software groups' not in metadata_dict:
                    metadata_dict['Software groups'] = set()
                metadata_dict['Software groups'].add(values['group_name'])

        # create the metadata based on the dict 'metadata_dict'
        for metadata, values in metadata_dict.items():
            tmp_dict = {'name': '-' + metadata, 'value': ', '.join(values)}
            t['metadata'].append(tmp_dict)

        techniques_layer.append(t)

    return techniques_layer


def get_group_list(groups, file_type):
    """
    Make a list of group names for the involved groups.
    :param groups: a dict with data on groups
    :param file_type: the file type of the YAML file as present in the key 'file_type'
    :return: list
    """
    if file_type == FILE_TYPE_GROUP_ADMINISTRATION:
        groups_list = []
        for group, values in groups.items():
            # if YAML file contains campaign key with a legit value
            if 'campaign' in values:
                groups_list.append(values['group_name'] + ' (' + values['campaign'] + ')')
            else:
                groups_list.append(values['group_name'])

        return groups_list
    else:
        return groups


def generate_group_heat_map(groups, overlay, overlay_type, stage, platform, software_groups, filter_applicable_to):
    """
    Calls all functions that are necessary for the generation of the heat map and write a json layer to disk.
    :param groups: threat actor groups
    :param overlay: group(s), visibility or detections to overlay (group ID, group name/alias, YAML file with
    group(s), detections or visibility)
    :param overlay_type: group, visibility or detection
    :param stage: attack or pre-attack
    :param platform: all, Linux, macOS, Windows
    :param software_groups: specify if techniques from related software should be included.
    :param filter_applicable_to: filter techniques based on applicable_to field in techniques administration YAML file
    :return: returns nothing when something's wrong
    """
    overlay_dict = {}
    groups_software_dict = {}

    groups_file_type = None
    if os.path.isfile(groups):
        groups_file_type = check_file(groups, file_type=FILE_TYPE_GROUP_ADMINISTRATION)
        if not groups_file_type:
            return
    else:
        # remove whitespaces (leading and trailing), convert to lower case and put in a list
        groups = groups.split(',')
        groups = list(map(lambda x: x.strip().lower(), groups))

    overlay_file_type = None
    if overlay:
        if os.path.isfile(overlay):
            expected_file_type = FILE_TYPE_GROUP_ADMINISTRATION if overlay_type == OVERLAY_TYPE_GROUP \
                else FILE_TYPE_TECHNIQUE_ADMINISTRATION \
                if overlay_type in [OVERLAY_TYPE_VISIBILITY, OVERLAY_TYPE_DETECTION] else None
            overlay_file_type = check_file(overlay, expected_file_type)
            if not overlay_file_type:
                return
        else:
            overlay = overlay.split(',')
            overlay = list(map(lambda x: x.strip().lower(), overlay))
    else:
        overlay = []

    all_techniques = None
    if overlay_file_type == FILE_TYPE_TECHNIQUE_ADMINISTRATION:
        if overlay_type == OVERLAY_TYPE_VISIBILITY:
            overlay_dict, all_techniques = get_visibility_techniques(overlay, filter_applicable_to)
        elif overlay_type == OVERLAY_TYPE_DETECTION:
            overlay_dict, all_techniques = get_detection_techniques(overlay, filter_applicable_to)
    elif len(overlay) > 0:
        overlay_dict = get_group_techniques(overlay, stage, platform, overlay_file_type)
        if not overlay_dict:
            return

    groups_dict = get_group_techniques(groups, stage, platform, groups_file_type)
    if groups_dict == -1:
        return
    if len(groups_dict) == 0:
        print('[!] Empty layer.')  # the provided groups dit not result in any techniques
        return

    # check if we are doing a software group overlay
    if software_groups and overlay:  # TODO add support for campaign info in layer metadata
        if overlay_type not in [OVERLAY_TYPE_VISIBILITY, OVERLAY_TYPE_DETECTION]:
            # if a group overlay is provided, get the software techniques for the overlay
            groups_software_dict = get_software_techniques(overlay, stage, platform)
    elif software_groups:
        groups_software_dict = get_software_techniques(groups, stage, platform)

    technique_count, max_count = get_technique_count(groups_dict, overlay_dict, groups_software_dict, overlay_type, all_techniques)
    technique_layer = get_technique_layer(technique_count, groups_dict, overlay_dict, groups_software_dict,
                                          overlay_file_type, overlay_type, all_techniques)

    # make a list group names for the involved groups.
    if groups == ['all']:
        groups_list = ['all']
    else:
        groups_list = get_group_list(groups_dict, groups_file_type)
    overlay_list = get_group_list(overlay_dict, overlay_file_type)

    desc = 'stage: ' + stage + ' | platform: ' + platform + ' | group(s): ' + ', '.join(groups_list) + \
           ' | overlay group(s): ' + ', '.join(overlay_list)

    layer = get_layer_template_groups(stage[0].upper() + stage[1:] + ' ' + platform, max_count, desc, stage, platform, overlay_type)
    layer['techniques'] = technique_layer

    json_string = simplejson.dumps(layer).replace('}, ', '},\n')

    if overlay:
        filename = "output/" + stage + '_' + platform.lower() + '_' + '_'.join(groups_list) + '-overlay_' + '_'.join(overlay_list) + '_' + filter_applicable_to.replace(' ', '_')
    else:
        filename = "output/" + stage + '_' + platform.lower() + '_' + '_'.join(groups_list)
    filename = filename[:255] + '.json'
    with open(filename, 'w') as f:  # write layer file to disk
        f.write(json_string)
        print('Written layer: ' + filename)


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


def get_statistics():
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
        data_sources = try_get_key(tech, 'x_mitre_data_sources')
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
    print('-'*50)
    for k, v in data_sources_dict_sorted.items():
        print(str_format.format(str(v['count']), k))
