import simplejson
from generic import *
import xlsxwriter
# Imports for pandas and plotly are because of performance reasons in the function that uses these libraries.


def generate_detection_layer(filename_techniques, filename_data_sources, overlay, filter_applicable_to):
    """
    Generates layer for detection coverage and optionally an overlaid version with visibility coverage.
    :param filename_techniques: the filename of the yaml file containing the techniques administration
    :param filename_data_sources: the filename of the yaml file containing the data sources administration
    :param overlay: boolean value to specify if an overlay between detection and visibility should be generated
    :param filter_applicable_to: filter techniques based on applicable_to field in techniques administration YAML file
    :return:
    """
    if not overlay:
        my_techniques, name, platform = load_techniques(filename_techniques, 'detection', filter_applicable_to)
        mapped_techniques_detection = _map_and_colorize_techniques_for_detections(my_techniques)
        layer_detection = get_layer_template_detections('Detections ' + name + ' ' + filter_applicable_to, 'description', 'attack', platform)
        _write_layer(layer_detection, mapped_techniques_detection, 'detection', filter_applicable_to, name)
    else:
        my_techniques, name, platform = load_techniques(filename_techniques, 'all', filter_applicable_to)
        my_data_sources = _load_data_sources(filename_data_sources)
        mapped_techniques_both = _map_and_colorize_techniques_for_overlaid(my_techniques, my_data_sources, filter_applicable_to)
        layer_both = get_layer_template_layered('Visibility and Detection ' + name + ' ' + filter_applicable_to, 'description', 'attack', platform)
        _write_layer(layer_both, mapped_techniques_both, 'visibility_and_detection', filter_applicable_to, name)


def generate_visibility_layer(filename_techniques, filename_data_sources, overlay, filter_applicable_to):
    """
    Generates layer for visibility coverage and optionally an overlaid version with detection coverage.
    :param filename_techniques: the filename of the yaml file containing the techniques administration
    :param filename_data_sources: the filename of the yaml file containing the data sources administration
    :param overlay: boolean value to specify if an overlay between detection and visibility should be generated
    :param filter_applicable_to: filter techniques based on applicable_to field in techniques administration YAML file
    :return:
    """
    my_data_sources = _load_data_sources(filename_data_sources)

    if not overlay:
        my_techniques, name, platform = load_techniques(filename_techniques, 'visibility', filter_applicable_to)
        mapped_techniques_visibility = _map_and_colorize_techniques_for_visibility(my_techniques, my_data_sources)
        layer_visibility = get_layer_template_visibility('Visibility ' + name + ' ' + filter_applicable_to, 'description', 'attack', platform)
        _write_layer(layer_visibility, mapped_techniques_visibility, 'visibility', filter_applicable_to, name)
    else:
        my_techniques, name, platform = load_techniques(filename_techniques, 'all', filter_applicable_to)
        mapped_techniques_both = _map_and_colorize_techniques_for_overlaid(my_techniques, my_data_sources, filter_applicable_to)
        layer_both = get_layer_template_layered('Visibility and Detection ' + name + ' ' + filter_applicable_to, 'description', 'attack', platform)
        _write_layer(layer_both, mapped_techniques_both, 'visibility_and_detection', filter_applicable_to, name)


def plot_detection_graph(filename, filter_applicable_to):
    """
    Generates a line graph which shows the improvements on detections through the time.
    :param filename: the filename of the yaml file containing the techniques administration
    :param filter_applicable_to: filter techniques based on applicable_to field in techniques administration YAML file
    :return:
    """
    my_techniques, name, platform = load_techniques(filename, 'detection', filter_applicable_to)

    graph_values = []
    for t in my_techniques.values():
        for detection in t['detection']:
            if detection['date_implemented']:
                yyyymm = detection['date_implemented'].strftime('%Y-%m')
                graph_values.append({'date': yyyymm, 'count': 1})

    import pandas as pd
    df = pd.DataFrame(graph_values).groupby('date', as_index=False)[['count']].sum()
    df['cumcount'] = df.ix[::1, 'count'].cumsum()[::1]

    output_filename = 'output/graph_detection_%s.html' % filter_applicable_to
    import plotly
    import plotly.graph_objs as go
    plotly.offline.plot(
        {'data': [go.Scatter(x=df['date'], y=df['cumcount'])],
         'layout': go.Layout(title="# of detections for %s %s" % (name, filter_applicable_to))},
        filename=output_filename, auto_open=False
    )
    print("File written: " + output_filename)


def _load_data_sources(filename):
    """
    Loads the data sources (including all properties) from the given yaml file.
    :param filename: the filename of the yaml file containing the data sources administration
    :return: dictionary with data sources (including properties)
    """
    my_data_sources = {}
    with open(filename, 'r') as yaml_file:
        yaml_content = yaml.load(yaml_file, Loader=yaml.FullLoader)
        for d in yaml_content['data_sources']:
            dq = d['data_quality']
            if dq['device_completeness'] > 0 and dq['data_field_completeness'] > 0 and dq['timeliness'] > 0 and dq['consistency'] > 0:
                my_data_sources[d['data_source_name']] = d
    return my_data_sources


def _write_layer(layer, mapped_techniques, filename_prefix, filename_suffix, name):
    """
    Writes the json layer file to disk.
    :param layer: the prepped layer dictionary
    :param mapped_techniques: the techniques section that will be included in the layer
    :param filename_prefix: the prefix for the output filename
    :param filename_suffix: the suffix for the output filename
    :param name: the name that will be used in the filename together with the prefix
    :return:
    """

    layer['techniques'] = mapped_techniques
    json_string = simplejson.dumps(layer).replace('}, ', '},\n')
    filename_suffix = '_' + filename_suffix if filename_suffix != '' else ''
    output_filename = normalize_name_to_filename('output/%s_%s%s.json' % (filename_prefix, name, filename_suffix))
    with open(output_filename, 'w') as f:
        f.write(json_string)
    print("File written: " + output_filename)


def _map_and_colorize_techniques_for_detections(my_techniques):
    """
    Determine the color of the techniques based on the detection score in the given yaml file.
    :param my_techniques: the configured techniques
    :return: a dictionary with techniques that can be used in the layer's output file
    """
    techniques = load_attack_data(DATA_TYPE_STIX_ALL_TECH)

    # Color the techniques based on how the coverage defined in the detections definition and generate a list with
    # techniques to be used in the layer output file.
    mapped_techniques = []
    try:
        for technique_id, technique_data in my_techniques.items():
            s = calculate_score(technique_data['detection'], zero_value=-1)

            if s != -1:
                color = COLOR_D_0 if s == 0 else COLOR_D_1 if s == 1 else COLOR_D_2 if s == 2 else COLOR_D_3 \
                                  if s == 3 else COLOR_D_4 if s == 4 else COLOR_D_5 if s == 5 else ''
                technique = get_technique(techniques, technique_id)

                for tactic in get_tactics(technique):
                    x = {}
                    x['techniqueID'] = technique_id
                    x['color'] = color
                    x['comment'] = ''
                    x['enabled'] = True
                    x['tactic'] = tactic.lower().replace(' ', '-')
                    x['metadata'] = []
                    x['score'] = s
                    cnt = 1
                    tcnt = len([d for d in technique_data['detection'] if d['score'] >= 0])
                    for detection in technique_data['detection']:
                        if detection['score'] >= 0:
                            location = ', '.join(detection['location'])
                            location = location if location != '' else '-'
                            applicable_to = ', '.join(detection['applicable_to'])
                            comment = str(detection['comment']) if str(detection['comment']) != '' else '-'
                            x['metadata'].append({'name': '-Applicable to', 'value': applicable_to})
                            x['metadata'].append({'name': '-Detection score', 'value': str(detection['score'])})
                            x['metadata'].append({'name': '-Detection location', 'value': location})
                            x['metadata'].append({'name': '-Comment', 'value': comment})
                            if cnt != tcnt:
                                x['metadata'].append({'name': '---', 'value': '---'})
                            cnt += 1
                    mapped_techniques.append(x)
    except Exception as e:
        print('[!] Possible error in YAML file at: %s. Error: %s' % (technique_id, str(e)))
        quit()

    return mapped_techniques


def _map_and_colorize_techniques_for_visibility(my_techniques, my_data_sources):
    """
    Determine the color of the techniques based on the visibility score in the given yaml file.
    :param my_techniques: the configured techniques
    :param my_data_sources: the configured data sources
    :return: a dictionary with techniques that can be used in the layer's output file
    """
    techniques = load_attack_data(DATA_TYPE_STIX_ALL_TECH)

    technique_ds_mapping = map_techniques_to_data_sources(techniques, my_data_sources)

    # Color the techniques based on how the coverage defined in the detections definition and generate a list with
    # techniques to be used in the layer output file.
    mapped_techniques = []
    for technique_id, technique_data in my_techniques.items():
        s = calculate_score(technique_data['visibility'])
        if s == 0:
            s = None

        my_ds = ', '.join(technique_ds_mapping[technique_id]['my_data_sources']) if technique_id in technique_ds_mapping.keys() and technique_ds_mapping[technique_id]['my_data_sources'] else '-'
        technique = get_technique(techniques, technique_id)
        color = COLOR_V_1 if s == 1 else COLOR_V_2 if s == 2 else COLOR_V_3 if s == 3 else COLOR_V_4 if s == 4 else ''

        for tactic in get_tactics(technique):
            x = {}
            x['techniqueID'] = technique_id
            x['color'] = color
            x['comment'] = ''
            x['enabled'] = True
            x['tactic'] = tactic.lower().replace(' ', '-')
            x['metadata'] = []
            x['metadata'].append({'name': '-Available data sources', 'value': my_ds})
            x['metadata'].append({'name': '-ATT&CK data sources', 'value': ', '.join(technique['x_mitre_data_sources'])})
            x['metadata'].append({'name': '---', 'value': '---'})
            x['score'] = s

            cnt = 1
            tcnt = len(technique_data['visibility'])
            for visibility in technique_data['visibility']:
                comment = str(visibility['comment']) if str(visibility['comment']) != '' else '-'
                applicable_to = ', '.join(visibility['applicable_to'])
                x['metadata'].append({'name': '-Applicable to', 'value': applicable_to})
                x['metadata'].append({'name': '-Visibility score', 'value': str(visibility['score'])})
                x['metadata'].append({'name': '-Comment', 'value': comment})
                if cnt != tcnt:
                    x['metadata'].append({'name': '---', 'value': '---'})
                cnt += 1

            mapped_techniques.append(x)

    for t in techniques:
        tech_id = get_attack_id(t)
        if tech_id not in my_techniques.keys():
            tactics = get_tactics(t)
            if tactics:
                for tactic in tactics:
                    x = {}
                    x['techniqueID'] = tech_id
                    x['comment'] = ''
                    x['enabled'] = True
                    x['tactic'] = tactic.lower().replace(' ', '-')
                    ds = ', '.join(t['x_mitre_data_sources']) if 'x_mitre_data_sources' in t else '-'
                    x['metadata'] = [{'name': '-ATT&CK data sources', 'value': ds}]

                    mapped_techniques.append(x)

    return mapped_techniques


def _map_and_colorize_techniques_for_overlaid(my_techniques, my_data_sources, filter_applicable_to):
    """
    Determine the color of the techniques based on both detection and visibility.
    :param my_techniques: the configured techniques
    :param my_data_sources: the configured data sources
    :param filter_applicable_to: filter techniques based on applicable_to field in techniques administration YAML file
    :return: a dictionary with techniques that can be used in the layer's output file
    """
    techniques = load_attack_data(DATA_TYPE_STIX_ALL_TECH)

    technique_ds_mapping = map_techniques_to_data_sources(techniques, my_data_sources)

    # Color the techniques based on how the coverage defined in the detections definition and generate a list with
    # techniques to be used in the layer output file.
    mapped_techniques = []
    for technique_id, technique_data in my_techniques.items():
        detection_score = calculate_score(technique_data['detection'], zero_value=-1)
        visibility_score = calculate_score(technique_data['visibility'])

        detection = True if detection_score > 0 else False
        visibility = True if visibility_score > 0 else False

        # Additional filtering based on applicable_to field. Overrules the score.
        a2_d = set([a for d in technique_data['detection'] for a in d['applicable_to']])
        a2_v = set([a for v in technique_data['detection'] for a in v['applicable_to']])

        if filter_applicable_to != 'all' and filter_applicable_to not in a2_d and 'all' not in a2_d:
            detection = False
        if filter_applicable_to != 'all' and filter_applicable_to not in a2_v and 'all' not in a2_v:
            visibility = False

        if detection and visibility:
            color = COLOR_OVERLAY_BOTH
        elif detection and not visibility:
            color = COLOR_OVERLAY_DETECTION
        elif not detection and visibility:
            color = COLOR_OVERLAY_VISIBILITY

        my_ds = ', '.join(technique_ds_mapping[technique_id]['my_data_sources']) if technique_id in technique_ds_mapping.keys() and technique_ds_mapping[technique_id]['my_data_sources'] else '-'

        technique = get_technique(techniques, technique_id)
        for tactic in get_tactics(technique):
            x = {}
            x['techniqueID'] = technique_id
            x['color'] = color
            x['comment'] = ''
            x['enabled'] = True
            x['tactic'] = tactic.lower().replace(' ', '-')
            x['metadata'] = []
            x['metadata'].append({'name': '-Available data sources', 'value': my_ds})
            x['metadata'].append({'name': '-ATT&CK data sources', 'value': ', '.join(technique['x_mitre_data_sources'])})
            x['metadata'].append({'name': '---', 'value': '---'})

            # Metadata for detection:
            cnt = 1
            tcnt = len([d for d in technique_data['detection'] if d['score'] >= 0 and (filter_applicable_to == 'all' or filter_applicable_to in d['applicable_to'] or 'all' in d['applicable_to'])])
            for detection in technique_data['detection']:
                if detection['score'] >= 0 and (filter_applicable_to == 'all' or filter_applicable_to in detection['applicable_to'] or 'all' in detection['applicable_to']):
                    location = ', '.join(detection['location'])
                    location = location if location != '' else '-'
                    applicable_to = ', '.join(detection['applicable_to'])
                    comment = str(detection['comment']) if str(detection['comment']) != '' else '-'
                    x['metadata'].append({'name': '-Applicable to', 'value': applicable_to})
                    x['metadata'].append({'name': '-Detection score', 'value': str(detection['score'])})
                    x['metadata'].append({'name': '-Detection location', 'value': location})
                    x['metadata'].append({'name': '-Comment', 'value': comment})
                    if cnt != tcnt:
                        x['metadata'].append({'name': '---', 'value': '---'})
                    cnt += 1

            # Metadata for visibility:
            if tcnt > 0:
                x['metadata'].append({'name': '---', 'value': '---'})
            cnt = 1
            tcnt = len([v for v in technique_data['visibility'] if filter_applicable_to == 'all' or filter_applicable_to in v['applicable_to'] or 'all' in v['applicable_to']])
            for visibility in technique_data['visibility']:
                if filter_applicable_to == 'all' or filter_applicable_to in visibility['applicable_to'] or 'all' in visibility['applicable_to']:
                    comment = str(visibility['comment']) if str(visibility['comment']) != '' else '-'
                    applicable_to = ', '.join(visibility['applicable_to'])
                    x['metadata'].append({'name': '-Applicable to', 'value': applicable_to})
                    x['metadata'].append({'name': '-Visibility score', 'value': str(visibility['score'])})
                    x['metadata'].append({'name': '-Comment', 'value': comment})
                    if cnt != tcnt:
                        x['metadata'].append({'name': '---', 'value': '---'})
                    cnt += 1

            mapped_techniques.append(x)

    return mapped_techniques


def export_techniques_list_to_excel(filename):
    """
    Makes an overview of the MITRE ATT&CK techniques from the YAML administration file.
    :param filename: the filename of the yaml file containing the techniques administration
    :return:
    """
    my_techniques, name, platform = load_techniques(filename, 'all')
    my_techniques = dict(sorted(my_techniques.items(), key=lambda kv: kv[0], reverse=False))
    mitre_techniques = load_attack_data(DATA_TYPE_STIX_ALL_TECH)

    excel_filename = 'output/techniques.xlsx'
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
    worksheet_visibility.merge_range(2, 3, 2, 5, 'Visibility', format_bold_center_bgblue)

    # Writing the detections:
    y = 3
    worksheet_detections.write(y, 0, 'ID', format_bold_left)
    worksheet_detections.write(y, 1, 'Description', format_bold_left)
    worksheet_detections.write(y, 2, 'Tactic', format_bold_left)
    worksheet_detections.write(y, 3, 'Applicable to', format_bold_left)
    worksheet_detections.write(y, 4, 'Date registered', format_bold_left)
    worksheet_detections.write(y, 5, 'Date implemented', format_bold_left)
    worksheet_detections.write(y, 6, 'Score', format_bold_left)
    worksheet_detections.write(y, 7, 'Location', format_bold_left)
    worksheet_detections.write(y, 8, 'Comment', format_bold_left)
    worksheet_detections.set_column(0, 0, 14)
    worksheet_detections.set_column(1, 1, 40)
    worksheet_detections.set_column(2, 2, 50)
    worksheet_detections.set_column(3, 3, 18)
    worksheet_detections.set_column(4, 4, 15)
    worksheet_detections.set_column(5, 5, 18)
    worksheet_detections.set_column(6, 6, 8)
    worksheet_detections.set_column(7, 7, 25)
    worksheet_detections.set_column(8, 8, 40)
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
            worksheet_detections.write(y, 4, str(detection['date_registered']).replace('None', ''), valign_top)
            worksheet_detections.write(y, 5, str(detection['date_implemented']).replace('None', ''), valign_top)
            ds = detection['score']
            worksheet_detections.write(y, 6, ds, detection_score_0 if ds == 0 else detection_score_1 if ds == 1 else detection_score_2 if ds == 2 else detection_score_3 if ds == 3 else detection_score_4 if ds == 4 else detection_score_5 if ds == 5 else no_score)
            worksheet_detections.write(y, 7, '\n'.join(detection['location']), wrap_text)
            worksheet_detections.write(y, 8, detection['comment'][:-1] if detection['comment'].endswith('\n') else detection['comment'], wrap_text)
            y += 1
    worksheet_detections.autofilter(3, 0, 3, 8)
    worksheet_detections.freeze_panes(4, 0)

    # Writing the visibility items:
    y = 3
    worksheet_visibility.write(y, 0, 'ID', format_bold_left)
    worksheet_visibility.write(y, 1, 'Description', format_bold_left)
    worksheet_visibility.write(y, 2, 'Tactic', format_bold_left)
    worksheet_visibility.write(y, 3, 'Applicable to', format_bold_left)
    worksheet_visibility.write(y, 4, 'Score', format_bold_left)
    worksheet_visibility.write(y, 5, 'Comment', format_bold_left)
    worksheet_visibility.set_column(0, 0, 14)
    worksheet_visibility.set_column(1, 1, 40)
    worksheet_visibility.set_column(2, 2, 50)
    worksheet_visibility.set_column(3, 9, 18)
    worksheet_visibility.set_column(4, 10, 8)
    worksheet_visibility.set_column(5, 11, 40)
    y = 4
    for technique_id, technique_data in my_techniques.items():
        # Add row for every visibility that is defined:
        for visibility in technique_data['visibility']:
            worksheet_visibility.write(y, 0, technique_id, valign_top)
            worksheet_visibility.write(y, 1, get_technique(mitre_techniques, technique_id)['name'], valign_top)
            worksheet_visibility.write(y, 2, ', '.join(t.capitalize() for t in
                                                       get_tactics(get_technique(mitre_techniques, technique_id))),
                                       valign_top)
            worksheet_visibility.write(y, 3, ', '.join(visibility['applicable_to']), wrap_text)
            vs = visibility['score']
            worksheet_visibility.write(y, 4, vs, visibility_score_1 if vs == 1 else visibility_score_2 if vs == 2 else visibility_score_3 if vs == 3 else visibility_score_4 if vs == 4 else no_score)
            worksheet_visibility.write(y, 5, visibility['comment'][:-1] if visibility['comment'].endswith('\n') else visibility['comment'], wrap_text)
            y += 1
    worksheet_visibility.autofilter(3, 0, 3, 5)
    worksheet_visibility.freeze_panes(4, 0)

    try:
        workbook.close()
        print("File written: " + excel_filename)
    except Exception as e:
        print('[!] Error while writing Excel file: %s' % str(e))
