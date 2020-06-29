from copy import deepcopy
from datetime import datetime
import xlsxwriter
import simplejson
from generic import *


# Imports for pandas and plotly are because of performance reasons in the function that uses these libraries.


def generate_data_sources_layer(filename, output_filename, layer_name):
    """
    Generates a generic layer for data sources.
    :param filename: the filename of the YAML file containing the data sources administration
    :param output_filename: the output filename defined by the user
    :param layer_name: the name of the Navigator layer
    :return:
    """
    my_data_sources, name, platform, exceptions = _load_data_sources(filename)

    # Do the mapping between my data sources and MITRE data sources:
    my_techniques = _map_and_colorize_techniques(my_data_sources, platform, exceptions)

    if not layer_name:
        layer_name = 'Data sources ' + name

    layer = get_layer_template_data_sources(layer_name, 'description', 'attack', platform)
    layer['techniques'] = my_techniques

    json_string = simplejson.dumps(layer).replace('}, ', '},\n')
    if not output_filename:
        output_filename = create_output_filename('data_sources', name)
    write_file(output_filename, json_string)


def plot_data_sources_graph(filename, output_filename):
    """
    Generates a line graph which shows the improvements on numbers of data sources through time.
    :param filename: the filename of the YAML file containing the data sources administration
    :param output_filename: the output filename defined by the user
    :return:
    """
    # pylint: disable=unused-variable
    my_data_sources, name, platform, exceptions = _load_data_sources(filename)

    graph_values = []
    for t in my_data_sources.values():
        if t['date_connected']:
            yyyymm = t['date_connected'].strftime('%Y-%m')
            graph_values.append({'date': yyyymm, 'count': 1})

    import pandas as pd
    df = pd.DataFrame(graph_values).groupby('date', as_index=False)[['count']].sum()
    df['cumcount'] = df['count'].cumsum()

    if not output_filename:
        output_filename = 'graph_data_sources'
    elif output_filename.endswith('.html'):
        output_filename = output_filename.replace('.html', '')
    output_filename = get_non_existing_filename('output/' + output_filename, 'html')

    import plotly
    import plotly.graph_objs as go
    plotly.offline.plot(
        {'data': [go.Scatter(x=df['date'], y=df['cumcount'])],
         'layout': go.Layout(title="# of data sources for " + name)},
        filename=output_filename, auto_open=False
    )
    print("File written:   " + output_filename)


def export_data_source_list_to_excel(filename, output_filename, eql_search=False):
    """
    Makes an overview of all MITRE ATT&CK data sources (via techniques) and lists which data sources are present
    in the YAML administration including all properties and data quality score.
    :param filename: the filename of the YAML file containing the data sources administration
    :param output_filename: the output filename defined by the user
    :param eql_search: specify if an EQL search was performed which may have resulted in missing ATT&CK data sources
    :return:
    """
    # pylint: disable=unused-variable
    my_data_sources, name, platforms, exceptions = _load_data_sources(filename, filter_empty_scores=False)
    if not output_filename:
        output_filename = 'data_sources'
    elif output_filename.endswith('.xlsx'):
        output_filename = output_filename.replace('.xlsx', '')
    excel_filename = get_non_existing_filename('output/' + output_filename, 'xlsx')
    workbook = xlsxwriter.Workbook(excel_filename)
    worksheet = workbook.add_worksheet('Data sources')

    # Formatting:
    format_bold_left = workbook.add_format({'align': 'left', 'bold': True})
    format_title = workbook.add_format({'align': 'left', 'bold': True, 'font_size': '14'})
    format_center_valign_top = workbook.add_format({'align': 'center', 'valign': 'top'})
    wrap_text = workbook.add_format({'text_wrap': True, 'valign': 'top'})
    valign_top = workbook.add_format({'valign': 'top'})
    no_score = workbook.add_format({'valign': 'top', 'align': 'center'})
    dq_score_1 = workbook.add_format({'valign': 'top', 'align': 'center', 'bg_color': COLOR_DS_25p})
    dq_score_2 = workbook.add_format({'valign': 'top', 'align': 'center', 'bg_color': COLOR_DS_50p})
    dq_score_3 = workbook.add_format({'valign': 'top', 'align': 'center', 'bg_color': COLOR_DS_75p, 'font_color': '#ffffff'})
    dq_score_4 = workbook.add_format({'valign': 'top', 'align': 'center', 'bg_color': COLOR_DS_99p, 'font_color': '#ffffff'})
    dq_score_5 = workbook.add_format({'valign': 'top', 'align': 'center', 'bg_color': COLOR_DS_100p, 'font_color': '#ffffff'})

    # Title
    worksheet.write(0, 0, 'Data sources for ' + name, format_title)

    # Header columns
    worksheet.write(2, 0, 'Data source name', format_bold_left)
    worksheet.write(2, 1, 'Date registered', format_bold_left)
    worksheet.write(2, 2, 'Date connected', format_bold_left)
    worksheet.write(2, 3, 'Products', format_bold_left)
    worksheet.write(2, 4, 'Comment', format_bold_left)
    worksheet.write(2, 5, 'Available for data analytics', format_bold_left)
    worksheet.write(2, 6, 'DQ: device completeness', format_bold_left)
    worksheet.write(2, 7, 'DQ: data field completeness', format_bold_left)
    worksheet.write(2, 8, 'DQ: timeliness', format_bold_left)
    worksheet.write(2, 9, 'DQ: consistency', format_bold_left)
    worksheet.write(2, 10, 'DQ: retention', format_bold_left)
    worksheet.write(2, 11, 'DQ: score', format_bold_left)

    worksheet.set_column(0, 0, 35)
    worksheet.set_column(1, 2, 15)
    worksheet.set_column(3, 3, 35)
    worksheet.set_column(4, 4, 50)
    worksheet.set_column(5, 5, 24)
    worksheet.set_column(6, 7, 25)
    worksheet.set_column(8, 10, 15)
    worksheet.set_column(11, 11, 10)

    # Putting the data sources data:
    y = 3

    # check if an ATT&CK data source is missing from the data source YAML administration file
    if eql_search:
        ds_miss_text = 'ATT&CK data source is missing from the YAML file or was excluded by an EQL search'
    else:
        ds_miss_text = 'ATT&CK data source is missing from the YAML file'
    # pylint: disable=consider-iterating-dictionary
    my_ds_list = [ds.lower() for ds in my_data_sources.keys()]
    applicable_data_sources = get_applicable_data_sources_platform(platforms)

    for ds in applicable_data_sources:
        if ds.lower() not in my_ds_list:
            ds_obj = deepcopy(YAML_OBJ_DATA_SOURCE)
            ds_obj['data_source_name'] = ds
            ds_obj['comment'] = ds_miss_text
            my_data_sources[ds] = ds_obj

    for d in sorted(my_data_sources.keys()):
        ds = my_data_sources[d]
        worksheet.write(y, 0, d, valign_top)

        date_registered = ds['date_registered'].strftime('%Y-%m-%d') if isinstance(ds['date_registered'], datetime) else ds['date_registered']
        date_connected = ds['date_connected'].strftime('%Y-%m-%d') if isinstance(ds['date_connected'], datetime) else ds['date_connected']

        worksheet.write(y, 1, str(date_registered).replace('None', ''), valign_top)
        worksheet.write(y, 2, str(date_connected).replace('None', ''), valign_top)
        worksheet.write(y, 3, ', '.join(ds['products']).replace('None', ''), valign_top)
        worksheet.write(y, 4, ds['comment'][:-1] if ds['comment'].endswith('\n') else ds['comment'], wrap_text)
        worksheet.write(y, 5, str(ds['available_for_data_analytics']), valign_top)
        worksheet.write(y, 6, ds['data_quality']['device_completeness'], format_center_valign_top)
        worksheet.write(y, 7, ds['data_quality']['data_field_completeness'], format_center_valign_top)
        worksheet.write(y, 8, ds['data_quality']['timeliness'], format_center_valign_top)
        worksheet.write(y, 9, ds['data_quality']['consistency'], format_center_valign_top)
        worksheet.write(y, 10, ds['data_quality']['retention'], format_center_valign_top)

        score = 0
        score_count = 0
        for k, v in ds['data_quality'].items():
            # the below DQ dimensions are given more weight in the calculation of the DQ score.
            if k in ['device_completeness', 'data_field_completeness', 'retention']:
                score += (v * 2)
                score_count += 2
            else:
                score += v
                score_count += 1
        if score > 0:
            score = score / score_count

        worksheet.write(y, 11, score, dq_score_1 if score < 2 else dq_score_2 if score < 3 else dq_score_3 if score < 4 else dq_score_4 if score < 5 else dq_score_5 if score < 6 else no_score)  # noqa
        y += 1

    worksheet.autofilter(2, 0, 2, 11)
    worksheet.freeze_panes(3, 0)
    try:
        workbook.close()
        print("File written:   " + excel_filename)
    except Exception as e:
        print('[!] Error while writing Excel file: %s' % str(e))


def _load_data_sources(file, filter_empty_scores=True):
    """
    Loads the data sources (including all properties) from the given YAML file.
    :param file: the file location of the YAML file containing the data sources administration or a dict
    :return: dictionary with data sources, name, platform and exceptions list.
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

    for d in yaml_content['data_sources']:
        d['comment'] = d.get('comment', '')
        dq = d['data_quality']
        if not filter_empty_scores:
            my_data_sources[d['data_source_name']] = d
        elif dq['device_completeness'] > 0 or dq['data_field_completeness'] > 0 or dq['timeliness'] > 0 or dq['consistency'] > 0 or dq['retention'] > 0:
            my_data_sources[d['data_source_name']] = d

    name = yaml_content['name']

    platform = get_platform_from_yaml(yaml_content)

    exceptions = []
    if 'exceptions' in yaml_content:
        exceptions = [t['technique_id'] for t in yaml_content['exceptions'] if t['technique_id'] is not None]

    return my_data_sources, name, platform, exceptions


def _count_applicable_data_sources(technique, applicable_data_sources):
    """
    get the count of applicable data sources for the provided technique.
    This takes into account which data sources are applicable for a platform(s)
    :param technique: ATT&CK CTI technique object
    :param applicable_data_sources: a list of applicable ATT&CK data sources
    :return: a count of the applicable data sources for this technique
    """
    applicable_ds_count = 0
    for ds in technique['x_mitre_data_sources']:
        if ds in applicable_data_sources:
            applicable_ds_count += 1
    return applicable_ds_count


def _map_and_colorize_techniques(my_ds, platforms, exceptions):
    """
    Determine the color of the techniques based on how many data sources are available per technique.
    :param my_ds: the configured data sources
    :param platforms: the configured platform(s)
    :param exceptions: the list of ATT&CK technique exception within the data source YAML file
    :return: a dictionary with techniques that can be used in the layer's output file
    """
    techniques = load_attack_data(DATA_TYPE_STIX_ALL_TECH)
    applicable_data_sources = get_applicable_data_sources_platform(platforms)
    technique_colors = {}

    # Color the techniques based on how many data sources are available.
    for t in techniques:
        if 'x_mitre_data_sources' in t:
            total_ds_count = _count_applicable_data_sources(t, applicable_data_sources)
            ds_count = 0
            for ds in t['x_mitre_data_sources']:
                if ds in my_ds.keys() and ds in applicable_data_sources:
                    ds_count += 1
            if total_ds_count > 0:
                result = (float(ds_count) / float(total_ds_count)) * 100
                color = COLOR_DS_25p if result <= 25 else COLOR_DS_50p if result <= 50 else COLOR_DS_75p \
                    if result <= 75 else COLOR_DS_99p if result <= 99 else COLOR_DS_100p
                technique_colors[get_attack_id(t)] = color

    my_techniques = map_techniques_to_data_sources(techniques, my_ds)

    output_techniques = []
    for t, v in my_techniques.items():
        if t not in exceptions and t in technique_colors:
            for tactic in v['tactics']:
                d = dict()
                d['techniqueID'] = t
                d['color'] = technique_colors[t]
                d['comment'] = ''
                d['enabled'] = True
                d['tactic'] = tactic.lower().replace(' ', '-')
                d['metadata'] = [{'name': '-Available data sources', 'value': ', '.join(v['my_data_sources'])},
                                 {'name': '-ATT&CK data sources', 'value': ', '.join(get_applicable_data_sources_technique(v['data_sources'],
                                                                                                                           applicable_data_sources))},
                                 {'name': '-Products', 'value': ', '.join(v['products'])}]
                d['metadata'] = make_layer_metadata_compliant(d['metadata'])
                d['showSubtechniques'] = True

                output_techniques.append(d)

    return output_techniques


def _indent_comment(comment, indent):
    """
    Indent a multiline  general, visibility, detection comment by x spaces
    :param comment: The comment to indent
    :param indent: The number of spaces to use in the indent
    :return: indented comment or the original
    """
    if '\n' in comment:
        new_comment = comment.replace('\n', '\n' + ' ' * indent)
        return new_comment
    else:
        return comment


def _get_technique_yaml_obj(techniques, tech_id):
    """
    Get at technique YAML obj from the provided list of techniques YAML objects which as the provided technique ID
    :param techniques: list of technique YAML objects
    :param tech_id: ATT&CK ID
    :return: technique YAML obj
    """
    for tech in techniques:
        if tech['technique_id'] == tech_id:
            return tech


def update_technique_administration_file(file_data_sources, file_tech_admin):
    """
    Update the visibility scores in the provided technique administration file
    :param file_data_sources: file location of the data source admin. file
    :param file_tech_admin: file location of the tech. admin. file
    :return:
    """
    # first we generate the new visibility scores contained within a temporary tech. admin YAML 'file'
    new_visibility_scores = generate_technique_administration_file(file_data_sources, None, write_file=False)

    # we get the date to remove the single quotes at the end of the code
    today = new_visibility_scores['techniques'][0]['visibility']['score_logbook'][0]['date']

    # next we load the current visibility scores from the tech. admin file
    cur_visibility_scores, _, platform_tech_admin = load_techniques(file_tech_admin)

    # if the platform does not match between the data source and tech. admin file we return
    if set(new_visibility_scores['platform']) != set(platform_tech_admin):
        print('[!] The MITRE ATT&CK platform key-value pair in the data source administration and technique '
              'administration file do not match.\n    Visibility update canceled.')
        return

    # we did not return, so init
    _yaml = init_yaml()
    with open(file_tech_admin) as fd:
        yaml_file_tech_admin = _yaml.load(fd)

    # check if we have tech IDs for which we now have visibility, but which were not yet part of the tech. admin file
    cur_tech_ids = cur_visibility_scores.keys()
    new_tech_ids = list(map(lambda k: k['technique_id'], new_visibility_scores['techniques']))

    tech_ids_new = []
    for tid in new_tech_ids:
        if tid not in cur_tech_ids:
            tech_ids_new.append(tid)

    # Add the new tech. to the ruamel instance: 'yaml_file_tech_admin'
    are_scores_updated = False
    tech_new_print = []
    if len(tech_ids_new) > 0:

        # do we want fill in a comment for all updated visibility scores?
        comment = ''
        if ask_yes_no('\nDo you want to fill in the visibility comment for the updated scores?'):
            comment = input(' >>   Visibility comment for in the new \'score\' object: ')
            print('')

        # add new techniques and set the comment
        x = 0
        for new_tech in new_visibility_scores['techniques']:

            # set the comment for all new visibility scores
            # we will also be needing this later in the code to update the scores of already present techniques
            new_visibility_scores['techniques'][x]['visibility']['score_logbook'][0]['comment'] = comment

            if new_tech['technique_id'] in tech_ids_new:
                are_scores_updated = True
                yaml_file_tech_admin['techniques'].append(new_tech)
                tech_new_print.append(' - ' + new_tech['technique_id'] + '\n')
            x += 1

        print('The following new technique IDs are added to the technique administration file with a visibility '
              'score derived from the nr. of data sources:')
        print(''.join(tech_new_print))
    else:
        print(' - No new techniques, for which we now have visibility, have been added to the techniques administration file.')

    # determine how visibility scores have been assigned in the current YAML file (auto, manually or mixed)
    # also determine if we have any scores that can be updated
    manually_scored = False
    auto_scored = False
    mix_scores = False
    updated_vis_score_cnt = 0
    for cur_tech, cur_values in cur_visibility_scores.items():
        new_tech = _get_technique_yaml_obj(new_visibility_scores['techniques'], cur_tech)
        if new_tech:  # new_tech will be None if technique_id is part of the 'exception' list within the
            # data source administration file
            new_score = new_tech['visibility']['score_logbook'][0]['score']

            for cur_obj in cur_values['visibility']:
                old_score = get_latest_score(cur_obj)

                if get_latest_auto_generated(cur_obj) and old_score != new_score:
                    auto_scored = True
                    updated_vis_score_cnt += 1
                elif old_score != new_score:
                    manually_scored = True
                    updated_vis_score_cnt += 1

            if manually_scored and auto_scored:
                mix_scores = True

    # stop if none of the present visibility scores are eligible for an update
    if not mix_scores and not manually_scored and not auto_scored:
        print(' - None of the already present techniques has a visibility score that is eligible for an update.')
    else:
        print('\nA total of ' + str(updated_vis_score_cnt) + ' visibility scores are eligible for an update.\n')
        # ask how the score should be updated
        answer = 0
        if mix_scores:
            answer = ask_multiple_choice(V_UPDATE_Q_MIXED, [V_UPDATE_ANSWER_3, V_UPDATE_ANSWER_4,
                                                            V_UPDATE_ANSWER_1, V_UPDATE_ANSWER_2, V_UPDATE_ANSWER_CANCEL])
        elif manually_scored:
            answer = ask_multiple_choice(V_UPDATE_Q_ALL_MANUAL, [V_UPDATE_ANSWER_1, V_UPDATE_ANSWER_2, V_UPDATE_ANSWER_CANCEL])
        elif auto_scored:
            answer = ask_multiple_choice(V_UPDATE_Q_ALL_AUTO, [V_UPDATE_ANSWER_1, V_UPDATE_ANSWER_2, V_UPDATE_ANSWER_CANCEL])
        if answer == V_UPDATE_ANSWER_CANCEL:
            return

        # identify which visibility scores have changed and set the action to perform on the score
        # tech_update {tech_id: ..., {obj_idx: { action: 1|2|3, score_obj: {...} } } }
        tech_update = dict()
        for new_tech in new_visibility_scores['techniques']:
            tech_id = new_tech['technique_id']
            new_score_obj = new_tech['visibility']['score_logbook'][0]
            new_score = new_score_obj['score']

            if tech_id in cur_visibility_scores:
                old_visibility_objects = cur_visibility_scores[tech_id]['visibility']
                obj_idx = 0
                for old_vis_obj in old_visibility_objects:
                    old_score = get_latest_score(old_vis_obj)
                    auto_gen = get_latest_auto_generated(old_vis_obj)

                    # continue if score can be updated
                    if old_score != new_score:
                        if tech_id not in tech_update:
                            tech_update[tech_id] = dict()

                        if (answer == V_UPDATE_ANSWER_1) or (answer == V_UPDATE_ANSWER_3 and auto_gen):
                            tech_update[tech_id][obj_idx] = {'action': V_UPDATE_ACTION_AUTO, 'score_obj': new_score_obj}
                        elif answer == V_UPDATE_ANSWER_2:
                            tech_update[tech_id][obj_idx] = {'action': V_UPDATE_ACTION_DIFF, 'score_obj': new_score_obj}
                        elif answer == V_UPDATE_ANSWER_4:
                            if auto_gen:
                                tech_update[tech_id][obj_idx] = {'action': V_UPDATE_ACTION_AUTO, 'score_obj': new_score_obj}
                            else:
                                tech_update[tech_id][obj_idx] = {'action': V_UPDATE_ACTION_DIFF, 'score_obj': new_score_obj}
                    obj_idx += 1

        # perform the above set actions
        score_updates_handled = 0
        for old_tech in yaml_file_tech_admin['techniques']:
            tech_id = old_tech['technique_id']
            tech_name = old_tech['technique_name']
            obj_idx = 0
            if tech_id in tech_update:
                if isinstance(old_tech['visibility'], list):
                    old_vis_obj = old_tech['visibility']
                else:
                    old_vis_obj = [old_tech['visibility']]

                while obj_idx <= len(tech_update[tech_id]):
                    # continue if an action has been set for this visibility object
                    if obj_idx in tech_update[tech_id]:
                        update_action = tech_update[tech_id][obj_idx]['action']
                        new_score_obj = tech_update[tech_id][obj_idx]['score_obj']

                        if update_action == V_UPDATE_ACTION_AUTO:
                            are_scores_updated = True
                            old_vis_obj[obj_idx]['score_logbook'].insert(0, new_score_obj)
                            print(' - Updated a score in technique ID: ' + tech_id +
                                  '   (applicable to: ' + ', '.join(old_vis_obj[obj_idx]['applicable_to']) + ')')
                        elif update_action == V_UPDATE_ACTION_DIFF:
                            print('-' * 80)
                            tmp_txt = '[updates remaining: ' + str(updated_vis_score_cnt - score_updates_handled) + ']'
                            print(' ' * (80 - len(tmp_txt)) + tmp_txt)
                            print('')
                            print('Visibility object:')
                            print(' - ATT&CK ID/name      ' + tech_id + ' / ' + tech_name)
                            print(' - Applicable to:      ' + ', '.join(old_vis_obj[obj_idx]['applicable_to']))
                            print(' - Technique  comment: ' + _indent_comment(old_vis_obj[obj_idx]['comment'], 23))
                            print('')
                            print('OLD score object:')
                            print(' - Date:               ' + get_latest_date(old_vis_obj[obj_idx]).strftime('%Y-%m-%d'))
                            print(' - Score:              ' + str(get_latest_score(old_vis_obj[obj_idx])))
                            print(' - Visibility comment: ' + _indent_comment(get_latest_comment(old_vis_obj[obj_idx]), 23))
                            print(' - Auto generated:     ' + str(get_latest_score_obj(old_vis_obj[obj_idx]).get('auto_generated', 'False')))
                            print('NEW score object:')
                            print(' - Date:               ' + new_score_obj['date'])
                            print(' - Score:              ' + str(new_score_obj['score']))
                            print(' - Visibility comment: ' + _indent_comment(new_score_obj['comment'], 23))
                            print(' - Auto generated:     True')
                            print('')
                            if ask_yes_no('Update the score?'):
                                are_scores_updated = True
                                old_vis_obj[obj_idx]['score_logbook'].insert(0, new_score_obj)
                                print(' - Updated a score in technique ID: ' + tech_id +
                                      '   (applicable to: ' + ', '.join(old_vis_obj[obj_idx]['applicable_to']) + ')')

                        score_updates_handled += 1

                    obj_idx += 1

        # create backup of the current tech. admin YAML file
        if are_scores_updated:
            print('')
            backup_file(file_tech_admin)

            yaml_file_tech_admin = fix_date_and_remove_null(yaml_file_tech_admin, today, input_type='ruamel')

            with open(file_tech_admin, 'w') as fd:
                fd.writelines(yaml_file_tech_admin)
            print('File written:   ' + file_tech_admin)
        else:
            print('No visibility scores have been updated.')

# pylint: disable=redefined-outer-name


def generate_technique_administration_file(filename, output_filename, write_file=True, all_techniques=False):
    """
    Generate a technique administration file based on the data source administration YAML file
    :param filename: the filename of the YAML file containing the data sources administration
    :param output_filename: the output filename defined by the user
    :param write_file: by default the file is written to disk
    :param all_techniques: include all ATT&CK techniques in the generated YAML file that are applicable to the
    platform(s) specified in the data source YAML file
    :return:
    """
    my_data_sources, name, platform, exceptions = _load_data_sources(filename)

    techniques = load_attack_data(DATA_TYPE_STIX_ALL_TECH_ENTERPRISE)
    applicable_data_sources = get_applicable_data_sources_platform(platform)

    yaml_file = dict()
    yaml_file['version'] = FILE_TYPE_TECHNIQUE_ADMINISTRATION_VERSION
    yaml_file['file_type'] = FILE_TYPE_TECHNIQUE_ADMINISTRATION
    yaml_file['name'] = name
    yaml_file['platform'] = platform
    yaml_file['techniques'] = []
    today = dt.now()

    # Score visibility based on the number of available data sources and the exceptions
    for t in techniques:
        platforms = t.get('x_mitre_platforms', None)
        if platform == 'all' or len(set(platforms).intersection(set(platform))) > 0:
            # not every technique has data source listed
            if 'x_mitre_data_sources' in t:
                total_ds_count = _count_applicable_data_sources(t, applicable_data_sources)
                ds_count = 0
                for ds in t['x_mitre_data_sources']:
                    if ds in my_data_sources.keys() and ds in applicable_data_sources:
                        ds_count += 1
                if total_ds_count > 0:
                    result = (float(ds_count) / float(total_ds_count)) * 100

                    score = 0 if result == 0 else 1 if result <= 49 else 2 if result <= 74 else 3 if result <= 99 else 4
                else:
                    score = 0

                # Do not add technique if score == 0 or part of the exception list
                techniques_upper = list(map(lambda x: x.upper(), exceptions))
                tech_id = get_attack_id(t)
                if (score > 0 or all_techniques) and tech_id not in techniques_upper:
                    tech = deepcopy(YAML_OBJ_TECHNIQUE)
                    tech['technique_id'] = tech_id
                    tech['technique_name'] = t['name']
                    tech['visibility']['score_logbook'][0]['score'] = score
                    tech['visibility']['score_logbook'][0]['date'] = today
                    yaml_file['techniques'].append(tech)

    yaml_file['techniques'] = sorted(yaml_file['techniques'], key=lambda k: k['technique_id'])

    if write_file:
        # remove the single quotes around the date key-value pair
        _yaml = init_yaml()
        file = StringIO()

        # create the file lines by writing it to memory
        _yaml.dump(yaml_file, file)
        file.seek(0)
        file_lines = file.readlines()

        # remove the single quotes from the date
        yaml_file_lines = fix_date_and_remove_null(file_lines, today, input_type='list')

        if not output_filename:
            output_filename = 'techniques-administration-' + normalize_name_to_filename(name + '-' + platform_to_name(platform))
        elif output_filename.endswith('.yaml'):
            output_filename = output_filename.replace('.yaml', '')
        output_filename = get_non_existing_filename('output/' + output_filename, 'yaml')
        with open(output_filename, 'w') as f:
            f.writelines(yaml_file_lines)
        print("File written:   " + output_filename)
    else:
        return yaml_file
