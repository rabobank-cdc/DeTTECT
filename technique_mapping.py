import simplejson
import xlsxwriter
from generic import *
from datetime import datetime
# Imports for pandas and plotly are because of performance reasons in the function that uses these libraries.


def generate_detection_layer(filename_techniques, filename_data_sources, overlay, output_filename, layer_name, platform=None):
    """
    Generates layer for detection coverage and optionally an overlaid version with visibility coverage.
    :param filename_techniques: the filename of the YAML file containing the techniques administration
    :param filename_data_sources: the filename of the YAML file containing the data sources administration
    :param overlay: boolean value to specify if an overlay between detection and visibility should be generated
    :param layer_name: the name of the Navigator layer
    :param output_filename: the output filename defined by the user
    :param platform: one or multiple values from PLATFORMS constant
    :return:
    """
    my_techniques, name, platform_yaml = load_techniques(filename_techniques)
    platform = set_platform(platform_yaml, platform)

    if not overlay:
        mapped_techniques_detection = _map_and_colorize_techniques_for_detections(my_techniques)
        if not layer_name:
            layer_name = 'Detections ' + name
        layer_detection = get_layer_template_detections(layer_name, 'description', platform)
        _write_layer(layer_detection, mapped_techniques_detection, 'detection', name, output_filename)
    else:
        my_data_sources = _load_data_sources(filename_data_sources)
        mapped_techniques_both = _map_and_colorize_techniques_for_overlaid(my_techniques, my_data_sources, platform)
        if not layer_name:
            layer_name = 'Visibility and Detection ' + name
        layer_both = get_layer_template_layered(layer_name, 'description', platform)
        _write_layer(layer_both, mapped_techniques_both, 'visibility_and_detection', name, output_filename)


def generate_visibility_layer(filename_techniques, filename_data_sources, overlay, output_filename, layer_name, platform=None):
    """
    Generates layer for visibility coverage and optionally an overlaid version with detection coverage.
    :param filename_techniques: the filename of the YAML file containing the techniques administration
    :param filename_data_sources: the filename of the YAML file containing the data sources administration
    :param overlay: boolean value to specify if an overlay between detection and visibility should be generated
    :param output_filename: the output filename defined by the user
    :param layer_name: the name of the Navigator layer
    :param platform: one or multiple values from PLATFORMS constant
    :return:
    """
    my_data_sources = _load_data_sources(filename_data_sources)
    my_techniques, name, platform_yaml = load_techniques(filename_techniques)
    platform = set_platform(platform_yaml, platform)

    if not overlay:
        mapped_techniques_visibility = _map_and_colorize_techniques_for_visibility(my_techniques, my_data_sources, platform)
        if not layer_name:
            layer_name = 'Visibility ' + name
        layer_visibility = get_layer_template_visibility(layer_name, 'description', platform)
        _write_layer(layer_visibility, mapped_techniques_visibility, 'visibility', name, output_filename)
    else:
        mapped_techniques_both = _map_and_colorize_techniques_for_overlaid(my_techniques, my_data_sources, platform)
        if not layer_name:
            layer_name = 'Visibility and Detection ' + name
        layer_both = get_layer_template_layered(layer_name, 'description', platform)
        _write_layer(layer_both, mapped_techniques_both, 'visibility_and_detection', name, output_filename)


def plot_graph(filename, type_graph, output_filename):
    """
    Generates a line graph which shows the improvements on detections through the time.
    :param filename: the filename of the YAML file containing the techniques administration
    :param type_graph: indicates the type of the graph: detection or visibility
    :param output_filename: the output filename defined by the user
    :return:
    """
    # pylint: disable=unused-variable
    my_techniques, name, platform = load_techniques(filename)

    graph_values = []
    for t in my_techniques.values():
        for item in t[type_graph]:
            date = get_latest_date(item)
            score = get_latest_score(item)
            if date and score > 0:
                yyyymm = date.strftime('%Y-%m')
                graph_values.append({'date': yyyymm, 'count': 1})

    import pandas as pd
    df = pd.DataFrame(graph_values).groupby('date', as_index=False)[['count']].sum()
    df['cumcount'] = df['count'].cumsum()

    if not output_filename:
        output_filename = 'graph_' + type_graph
    elif output_filename.endswith('.html'):
        output_filename = output_filename.replace('.html', '')
    output_filename = get_non_existing_filename('output/' + output_filename, 'html')

    import plotly
    import plotly.graph_objs as go
    plotly.offline.plot(
        {'data': [go.Scatter(x=df['date'], y=df['cumcount'])],
         'layout': go.Layout(title="# of %s items for %s" % (type_graph, name))},
        filename=output_filename, auto_open=False
    )
    print("File written:   " + output_filename)


def _load_data_sources(file):
    """
    Loads the data sources (including all properties) from the given YAML file.
    :param file: the file location of the YAML file containing the data sources administration or a dict
    :return: dictionary with data sources, name, platform and exceptions list.
    """
    my_data_sources = {}

    if isinstance(file, dict):
        # file is a dict instance created due to the use of an EQL query by the user
        yaml_content = file
    else:
        # file is a file location on disk
        _yaml = init_yaml()
        with open(file, 'r') as yaml_file:
            yaml_content = _yaml.load(yaml_file)

    for d in yaml_content['data_sources']:
        d['comment'] = d.get('comment', '')
        dq = d['data_quality']
        if dq['device_completeness'] > 0 and dq['data_field_completeness'] > 0 and dq['timeliness'] > 0 and dq['consistency'] > 0:
            my_data_sources[d['data_source_name']] = d

    return my_data_sources


def _write_layer(layer, mapped_techniques, filename_prefix, name, output_filename):
    """
    Writes the json layer file to disk.
    :param layer: the prepped layer dictionary
    :param mapped_techniques: the techniques section that will be included in the layer
    :param filename_prefix: the prefix for the output filename
    :param name: the name that will be used in the filename together with the prefix
    :param output_filename: the output filename defined by the user
    :return:
    """
    layer['techniques'] = mapped_techniques
    json_string = simplejson.dumps(layer).replace('}, ', '},\n')
    if not output_filename:
        output_filename = create_output_filename(filename_prefix, name)
    else:
        if output_filename.endswith('.json'):
            output_filename = output_filename.replace('.json', '')
        if filename_prefix == 'visibility_and_detection':
            output_filename += '_overlay'
    write_file(output_filename, json_string)


def _map_and_colorize_techniques_for_detections(my_techniques):
    """
    Determine the color of the techniques based on the detection score in the given YAML file.
    :param my_techniques: the configured techniques
    :return: a dictionary with techniques that can be used in the layer's output file
    """
    techniques = load_attack_data(DATA_TYPE_STIX_ALL_TECH)

    # Color the techniques based on how the coverage defined in the detections definition and generate a list with
    # techniques to be used in the layer output file.
    mapped_techniques = []
    technique_id = ""
    try:
        for technique_id, technique_data in my_techniques.items():
            s = calculate_score(technique_data['detection'], zero_value=-1)

            if s != -1:
                color = COLOR_D_0 if s == 0 else COLOR_D_1 if s == 1 else COLOR_D_2 if s == 2 else COLOR_D_3 \
                    if s == 3 else COLOR_D_4 if s == 4 else COLOR_D_5 if s == 5 else ''
                technique = get_technique(techniques, technique_id)

                if technique is not None:
                    x = dict()
                    x['techniqueID'] = technique_id
                    x['color'] = color
                    x['comment'] = ''
                    x['enabled'] = True
                    x['metadata'] = []
                    x['score'] = s
                    cnt = 1
                    tcnt = len([d for d in technique_data['detection'] if get_latest_score(d) >= 0])
                    for detection in technique_data['detection']:
                        d_score = get_latest_score(detection)
                        if d_score >= 0:
                            location = ', '.join(detection['location'])
                            applicable_to = ', '.join(detection['applicable_to'])
                            x['metadata'].append({'name': 'Applicable to', 'value': applicable_to})
                            x['metadata'].append({'name': 'Detection score', 'value': str(d_score)})
                            x['metadata'].append({'name': 'Detection location', 'value': location})
                            x['metadata'].append({'name': 'Technique comment', 'value': detection['comment']})
                            x['metadata'].append({'name': 'Detection comment', 'value': get_latest_comment(detection)})
                            if cnt != tcnt:
                                x['metadata'].append({'name': '------', 'value': ' '})
                            cnt += 1
                    x['metadata'] = make_layer_metadata_compliant(x['metadata'])
                    mapped_techniques.append(x)
                else:
                    print('[!] Technique ' + technique_id + ' is unknown in ATT&CK. Ignoring this technique.')
    except Exception as e:
        print('[!] Possible error in YAML file at: %s. Error: %s' % (technique_id, str(e)))
        quit()

    determine_and_set_show_sub_techniques(mapped_techniques)

    return mapped_techniques


def _map_and_colorize_techniques_for_visibility(my_techniques, my_data_sources, platforms):
    """
    Determine the color of the techniques based on the visibility score in the given YAML file.
    :param my_techniques: the configured techniques
    :param my_data_sources: the configured data sources
    :param platforms: the configured platform(s)
    :return: a dictionary with techniques that can be used in the layer's output file
    """
    techniques = load_attack_data(DATA_TYPE_STIX_ALL_TECH)
    applicable_data_sources = get_applicable_data_sources_platform(platforms)

    technique_ds_mapping = map_techniques_to_data_sources(techniques, my_data_sources)

    # Color the techniques based on how the coverage defined in the detections definition and generate a list with
    # techniques to be used in the layer output file.
    mapped_techniques = []
    for technique_id, technique_data in my_techniques.items():
        s = calculate_score(technique_data['visibility'])
        if s == 0:
            s = None

        my_ds = ', '.join(technique_ds_mapping[technique_id]['my_data_sources']) if technique_id in technique_ds_mapping.keys() and technique_ds_mapping[technique_id]['my_data_sources'] else ''  # noqa
        technique = get_technique(techniques, technique_id)
        color = COLOR_V_1 if s == 1 else COLOR_V_2 if s == 2 else COLOR_V_3 if s == 3 else COLOR_V_4 if s == 4 else ''

        if technique is not None:
            x = dict()
            x['techniqueID'] = technique_id
            x['color'] = color
            x['comment'] = ''
            x['enabled'] = True
            x['metadata'] = []
            x['metadata'].append({'name': 'Available data sources', 'value': my_ds})
            x['metadata'].append({'name': 'ATT&CK data sources', 'value': ', '.join(get_applicable_data_sources_technique(technique['x_mitre_data_sources'],
                                                                                                                          applicable_data_sources))})
            x['metadata'].append({'name': '------', 'value': ' '})
            x['score'] = s

            cnt = 1
            tcnt = len(technique_data['visibility'])
            for visibility in technique_data['visibility']:
                applicable_to = ', '.join(visibility['applicable_to'])
                x['metadata'].append({'name': 'Applicable to', 'value': applicable_to})
                x['metadata'].append({'name': 'Visibility score', 'value': str(get_latest_score(visibility))})
                x['metadata'].append({'name': 'Technique comment', 'value': visibility['comment']})
                x['metadata'].append({'name': 'Visibility comment', 'value': get_latest_comment(visibility)})
                if cnt != tcnt:
                    x['metadata'].append({'name': '------', 'value': ' '})
                cnt += 1

            x['metadata'] = make_layer_metadata_compliant(x['metadata'])
            mapped_techniques.append(x)
        else:
            print('[!] Technique ' + technique_id + ' is unknown in ATT&CK. Ignoring this technique.')

    determine_and_set_show_sub_techniques(mapped_techniques)

    # add metadata with ATT&CK data sources for the ones without visibility:
    for t in techniques:
        tech_id = get_attack_id(t)
        if tech_id not in my_techniques.keys():
            # look if technique already exists in the layer dict (as a result of determine_and_set_show_sub_techniques):
            x = None
            exists = False
            for mapped_tech in mapped_techniques:
                if mapped_tech['techniqueID'] == tech_id:
                    x = mapped_tech
                    exists = True
                    break
            if x is None:
                x = dict()
            x['techniqueID'] = tech_id
            x['comment'] = ''
            x['enabled'] = True
            ds = ', '.join(get_applicable_data_sources_technique(t['x_mitre_data_sources'], applicable_data_sources)) if 'x_mitre_data_sources' in t else ''  # noqa
            x['metadata'] = [{'name': 'ATT&CK data sources', 'value': ds}]
            x['metadata'] = make_layer_metadata_compliant(x['metadata'])

            if not exists:
                mapped_techniques.append(x)

    return mapped_techniques


def _map_and_colorize_techniques_for_overlaid(my_techniques, my_data_sources, platforms):
    """
    Determine the color of the techniques based on both detection and visibility.
    :param my_techniques: the configured techniques
    :param my_data_sources: the configured data sources
    :param platforms: the configured platform(s)
    :return: a dictionary with techniques that can be used in the layer's output file
    """
    techniques = load_attack_data(DATA_TYPE_STIX_ALL_TECH)
    applicable_data_sources = get_applicable_data_sources_platform(platforms)

    technique_ds_mapping = map_techniques_to_data_sources(techniques, my_data_sources)

    # Color the techniques based on how the coverage defined in the detections definition and generate a list with
    # techniques to be used in the layer output file.
    mapped_techniques = []
    for technique_id, technique_data in my_techniques.items():
        detection_score = calculate_score(technique_data['detection'], zero_value=-1)
        visibility_score = calculate_score(technique_data['visibility'])

        detection = True if detection_score > 0 else False
        visibility = True if visibility_score > 0 else False

        if detection and visibility:
            color = COLOR_OVERLAY_BOTH
        elif detection and not visibility:
            s = detection_score
            color = COLOR_D_0 if s == 0 else COLOR_D_1 if s == 1 else COLOR_D_2 if s == 2 else COLOR_D_3 if s == 3 else COLOR_D_4 if s == 4 else COLOR_D_5 if s == 5 else ''
        elif not detection and visibility:
            s = visibility_score
            color = COLOR_V_1 if s == 1 else COLOR_V_2 if s == 2 else COLOR_V_3 if s == 3 else COLOR_V_4 if s == 4 else ''
        elif detection_score == 0:  # forensics/context
            color = COLOR_D_0
        else:
            color = COLOR_WHITE

        my_ds = ', '.join(technique_ds_mapping[technique_id]['my_data_sources']) if technique_id in technique_ds_mapping.keys() and technique_ds_mapping[technique_id]['my_data_sources'] else ''  # noqa

        technique = get_technique(techniques, technique_id)
        x = dict()
        x['techniqueID'] = technique_id
        x['color'] = color
        x['comment'] = ''
        x['enabled'] = True
        x['metadata'] = []
        x['metadata'].append({'name': 'Available data sources', 'value': my_ds})
        x['metadata'].append({'name': 'ATT&CK data sources', 'value': ', '.join(get_applicable_data_sources_technique(technique['x_mitre_data_sources'],
                                                                                                                      applicable_data_sources))})
        # Metadata for detection and visibility:
        for obj_type in ['detection', 'visibility']:
            tcnt = len([obj for obj in technique_data[obj_type] if get_latest_score(obj) >= 0])
            if tcnt > 0:
                x['metadata'] = add_metadata_technique_object(technique_data, obj_type, x['metadata'])

        x['metadata'] = make_layer_metadata_compliant(x['metadata'])
        mapped_techniques.append(x)

    determine_and_set_show_sub_techniques(mapped_techniques)

    return mapped_techniques


def export_techniques_list_to_excel(filename, output_filename):
    """
    Makes an overview of the MITRE ATT&CK techniques from the YAML administration file.
    :param filename: the filename of the YAML file containing the techniques administration
    :param output_filename: the output filename defined by the user
    :return:
    """
    # pylint: disable=unused-variable
    my_techniques, name, platform = load_techniques(filename)
    my_techniques = dict(sorted(my_techniques.items(), key=lambda kv: kv[0], reverse=False))
    mitre_techniques = load_attack_data(DATA_TYPE_STIX_ALL_TECH)

    if not output_filename:
        output_filename = 'techniques'
    elif output_filename.endswith('.xlsx'):
        output_filename = output_filename.replace('.xlsx', '')
    excel_filename = get_non_existing_filename('output/' + output_filename, 'xlsx')
    workbook = xlsxwriter.Workbook(excel_filename)
    worksheet_detections = workbook.add_worksheet('Detections')
    worksheet_visibility = workbook.add_worksheet('Visibility')

    # Formatting:
    format_bold_left = workbook.add_format({'align': 'left', 'bold': True})
    format_title = workbook.add_format({'align': 'left', 'bold': True, 'font_size': '14'})
    format_bold_center_bggrey = workbook.add_format({'align': 'center', 'bold': True, 'bg_color': '#dbdbdb'})
    format_bold_center_bgreen = workbook.add_format({'align': 'center', 'bold': True, 'bg_color': '#8bc34a'})
    format_bold_center_bgblue = workbook.add_format({'align': 'center', 'bold': True, 'bg_color': '#64b5f6'})
    wrap_text = workbook.add_format({'text_wrap': True, 'valign': 'top'})
    valign_top = workbook.add_format({'valign': 'top'})
    no_score = workbook.add_format({'valign': 'top', 'align': 'center'})
    detection_score_0 = workbook.add_format({'valign': 'top', 'align': 'center', 'bg_color': COLOR_D_0})
    detection_score_1 = workbook.add_format({'valign': 'top', 'align': 'center', 'bg_color': COLOR_D_1})
    detection_score_2 = workbook.add_format({'valign': 'top', 'align': 'center', 'bg_color': COLOR_D_2})
    detection_score_3 = workbook.add_format({'valign': 'top', 'align': 'center', 'bg_color': COLOR_D_3})
    detection_score_4 = workbook.add_format({'valign': 'top', 'align': 'center', 'bg_color': COLOR_D_4, 'font_color': '#ffffff'})
    detection_score_5 = workbook.add_format({'valign': 'top', 'align': 'center', 'bg_color': COLOR_D_5, 'font_color': '#ffffff'})
    visibility_score_1 = workbook.add_format({'valign': 'top', 'align': 'center', 'bg_color': COLOR_V_1})
    visibility_score_2 = workbook.add_format({'valign': 'top', 'align': 'center', 'bg_color': COLOR_V_2})
    visibility_score_3 = workbook.add_format({'valign': 'top', 'align': 'center', 'bg_color': COLOR_V_3, 'font_color': '#ffffff'})
    visibility_score_4 = workbook.add_format({'valign': 'top', 'align': 'center', 'bg_color': COLOR_V_4, 'font_color': '#ffffff'})

    # Title
    worksheet_detections.write(0, 0, 'Overview of detections for ' + name, format_title)
    worksheet_visibility.write(0, 0, 'Overview of visibility for ' + name, format_title)

    # Header columns
    worksheet_detections.merge_range(2, 0, 2, 2, 'Technique', format_bold_center_bggrey)
    worksheet_visibility.merge_range(2, 0, 2, 2, 'Technique', format_bold_center_bggrey)
    worksheet_detections.merge_range(2, 3, 2, 8, 'Detection', format_bold_center_bgreen)
    worksheet_visibility.merge_range(2, 3, 2, 7, 'Visibility', format_bold_center_bgblue)

    # Writing the detections:
    y = 3
    worksheet_detections.write(y, 0, 'ID', format_bold_left)
    worksheet_detections.write(y, 1, 'Description', format_bold_left)
    worksheet_detections.write(y, 2, 'Tactic', format_bold_left)
    worksheet_detections.write(y, 3, 'Applicable to', format_bold_left)
    worksheet_detections.write(y, 4, 'Date', format_bold_left)
    worksheet_detections.write(y, 5, 'Score', format_bold_left)
    worksheet_detections.write(y, 6, 'Location', format_bold_left)
    worksheet_detections.write(y, 7, 'Technique comment', format_bold_left)
    worksheet_detections.write(y, 8, 'Detection comment', format_bold_left)
    worksheet_detections.set_column(0, 0, 8)
    worksheet_detections.set_column(1, 1, 40)
    worksheet_detections.set_column(2, 2, 40)
    worksheet_detections.set_column(3, 3, 18)
    worksheet_detections.set_column(4, 4, 11)
    worksheet_detections.set_column(5, 5, 8)
    worksheet_detections.set_column(6, 8, 50)
    y = 4
    for technique_id, technique_data in my_techniques.items():
        # Add row for every detection that is defined:
        for detection in technique_data['detection']:
            worksheet_detections.write(y, 0, technique_id, valign_top)
            worksheet_detections.write(y, 1, get_technique(mitre_techniques, technique_id)['name'], valign_top)
            worksheet_detections.write(y, 2, ', '.join(t.capitalize() for t in
                                                       get_tactics(get_technique(mitre_techniques, technique_id))),
                                       valign_top)
            worksheet_detections.write(y, 3, ', '.join(detection['applicable_to']), wrap_text)
            # make sure the date format is '%Y-%m-%d'. When we've done a EQL query this will become '%Y-%m-%d %H %M $%S'
            tmp_date = get_latest_date(detection)
            if isinstance(tmp_date, datetime):
                tmp_date = tmp_date.strftime('%Y-%m-%d')
            worksheet_detections.write(y, 4, str(tmp_date).replace('None', ''), valign_top)
            ds = get_latest_score(detection)
            worksheet_detections.write(y, 5, ds, detection_score_0 if ds == 0 else detection_score_1 if ds == 1 else detection_score_2 if ds == 2 else detection_score_3 if ds == 3 else detection_score_4 if ds == 4 else detection_score_5 if ds == 5 else no_score)  # noqa
            worksheet_detections.write(y, 6, '\n'.join(detection['location']), wrap_text)
            worksheet_detections.write(y, 7, detection['comment'][:-1] if detection['comment'].endswith('\n') else detection['comment'], wrap_text)
            d_comment = get_latest_comment(detection)
            worksheet_detections.write(y, 8, d_comment[:-1] if d_comment.endswith('\n') else d_comment, wrap_text)
            y += 1
    worksheet_detections.autofilter(3, 0, 3, 8)
    worksheet_detections.freeze_panes(4, 0)

    # Writing the visibility items:
    y = 3
    worksheet_visibility.write(y, 0, 'ID', format_bold_left)
    worksheet_visibility.write(y, 1, 'Description', format_bold_left)
    worksheet_visibility.write(y, 2, 'Tactic', format_bold_left)
    worksheet_visibility.write(y, 3, 'Applicable to', format_bold_left)
    worksheet_visibility.write(y, 4, 'Date', format_bold_left)
    worksheet_visibility.write(y, 5, 'Score', format_bold_left)
    worksheet_visibility.write(y, 6, 'Technique comment', format_bold_left)
    worksheet_visibility.write(y, 7, 'Visibility comment', format_bold_left)
    worksheet_visibility.set_column(0, 0, 8)
    worksheet_visibility.set_column(1, 1, 40)
    worksheet_visibility.set_column(2, 2, 40)
    worksheet_visibility.set_column(3, 3, 18)
    worksheet_visibility.set_column(4, 4, 11)
    worksheet_visibility.set_column(5, 5, 8)
    worksheet_visibility.set_column(6, 7, 50)
    y = 4
    for technique_id, technique_data in my_techniques.items():
        # Add row for every visibility that is defined:
        for visibility in technique_data['visibility']:
            worksheet_visibility.write(y, 0, technique_id, valign_top)
            worksheet_visibility.write(y, 1, get_technique(mitre_techniques, technique_id)['name'], valign_top)
            worksheet_visibility.write(y, 2, ', '.join(t.capitalize() for t in
                                                       get_tactics(get_technique(mitre_techniques, technique_id))), valign_top)
            worksheet_visibility.write(y, 3, ', '.join(visibility['applicable_to']), wrap_text)
            # make sure the date format is '%Y-%m-%d'. When we've done a EQL query this will become '%Y-%m-%d %H %M $%S'
            tmp_date = get_latest_date(visibility)
            if isinstance(tmp_date, datetime):
                tmp_date = tmp_date.strftime('%Y-%m-%d')
            worksheet_visibility.write(y, 4, str(tmp_date).replace('None', ''), valign_top)
            vs = get_latest_score(visibility)
            worksheet_visibility.write(y, 5, vs, visibility_score_1 if vs == 1 else visibility_score_2 if vs == 2 else visibility_score_3 if vs == 3 else visibility_score_4 if vs == 4 else no_score)  # noqa
            v_comment = get_latest_comment(visibility)
            worksheet_visibility.write(y, 6, visibility['comment'][:-1] if visibility['comment'].endswith('\n') else visibility['comment'], wrap_text)
            worksheet_visibility.write(y, 7, v_comment[:-1] if v_comment.endswith('\n') else v_comment, wrap_text)
            y += 1
    worksheet_visibility.autofilter(3, 0, 3, 7)
    worksheet_visibility.freeze_panes(4, 0)

    try:
        workbook.close()
        print("File written:   " + excel_filename)
    except Exception as e:
        print('[!] Error while writing Excel file: %s' % str(e))
