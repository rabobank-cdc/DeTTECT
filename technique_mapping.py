import simplejson
from generic import *
import xlsxwriter
# Imports for pandas and plotly are because of performance reasons in the function that uses these libraries.


def generate_detection_layer(filename_techniques, filename_data_sources, overlay):
    """
    Generates layer for detection coverage and optionally an overlayed version with visibility coverage.
    :param filename_techniques: the filename of the yaml file containing the techniques administration
    :param filename_data_sources: the filename of the yaml file containing the data sources administration
    :param overlay: boolean value to specify if an overlay between detection and visibility should be generated
    :return:
    """
    my_techniques, name, platform = _load_detections(filename_techniques)

    if not overlay:
        mapped_techniques_detection = _map_and_colorize_techniques_for_detections(my_techniques)
        layer_detection = get_layer_template_detections('Detections ' + name, 'description', 'attack', platform)
        _write_layer(layer_detection, mapped_techniques_detection, 'detection', name)
    else:
        my_data_sources = _load_data_sources(filename_data_sources)
        mapped_techniques_both = _map_and_colorize_techniques_for_overlayed(my_techniques, my_data_sources)
        layer_both = get_layer_template_layered('Visibility and Detection ' + name, 'description', 'attack', platform)
        _write_layer(layer_both, mapped_techniques_both, 'visibility_and_detection', name)


def generate_visibility_layer(filename_techniques, filename_data_sources, overlay):
    """
    Generates layer for visibility coverage and optionally an overlayed version with detection coverage.
    :param filename_techniques: the filename of the yaml file containing the techniques administration
    :param filename_data_sources: the filename of the yaml file containing the data sources administration
    :param overlay: boolean value to specify if an overlay between detection and visibility should be generated
    :return:
    """
    my_techniques, name, platform = _load_detections(filename_techniques)
    my_data_sources = _load_data_sources(filename_data_sources)

    if not overlay:
        mapped_techniques_visibility = _map_and_colorize_techniques_for_visibility(my_techniques, my_data_sources)
        layer_visibility = get_layer_template_visibility('Visibility ' + name, 'description', 'attack', platform)
        _write_layer(layer_visibility, mapped_techniques_visibility, 'visibility', name)
    else:
        mapped_techniques_both = _map_and_colorize_techniques_for_overlayed(my_techniques, my_data_sources)
        layer_both = get_layer_template_layered('Visibility and Detection ' + name, 'description', 'attack', platform)
        _write_layer(layer_both, mapped_techniques_both, 'visibility_and_detection', name)


def plot_detection_graph(filename):
    """
    Generates a line graph which shows the improvements on detections through the time.
    :param filename: the filename of the yaml file containing the techniques administration
    :return:
    """
    my_techniques, name, platform = _load_detections(filename)

    graph_values = []
    for t in my_techniques.values():
        if 'detection' in t.keys() and t['detection']['date_implemented']:
            yyyymm = t['detection']['date_implemented'].strftime('%Y-%m')
            graph_values.append({'date': yyyymm, 'count': 1})

    import pandas as pd
    df = pd.DataFrame(graph_values).groupby('date', as_index=False)[['count']].sum()
    df['cumcount'] = df.ix[::1, 'count'].cumsum()[::1]

    output_filename = 'output/graph_detection.html'
    import plotly
    import plotly.graph_objs as go
    plotly.offline.plot(
        {'data': [go.Scatter(x=df['date'], y=df['cumcount'])],
         'layout': go.Layout(title="# of detections for " + name)},
        filename=output_filename, auto_open=False
    )
    print("File written: " + output_filename)


def _load_detections(filename):
    """
    Loads the techniques (including detection and visibility properties) from the given yaml file.
    :param filename: the filename of the yaml file containing the techniques administration
    :return: dictionary with techniques (incl. properties), name and platform
    """
    my_techniques = {}
    with open(filename, 'r') as yaml_file:
        yaml_content = yaml.load(yaml_file, Loader=yaml.FullLoader)
        for d in yaml_content['techniques']:
            my_techniques[d['technique_id']] = d
        name = yaml_content['name']
        platform = yaml_content['platform']
    return my_techniques, name, platform


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


def _write_layer(layer, mapped_techniques, filename_prefix, name):
    """
    Writes the json layer file to disk.
    :param layer: the prepped layer dictionary
    :param mapped_techniques: the techniques section that will be included in the layer
    :param filename_prefix: the prefix for the output filename
    :param name: the name that will be used in the filename together with the prefix
    :return:
    """

    layer['techniques'] = mapped_techniques
    json_string = simplejson.dumps(layer).replace('}, ', '},\n')
    output_filename = 'output/%s_%s.json' % (filename_prefix, normalize_name_to_filename(name))
    with open(output_filename, 'w') as f:
        f.write(json_string)
    print("File written: " + output_filename)


def _map_and_colorize_techniques_for_detections(my_techniques):
    """
    Determine the color of the techniques based on the detection score in the given yaml file.
    :param my_techniques: the configured techniques
    :return: a dictionary with techniques that can be used in the layer's output file
    """
    techniques = load_attack_data(DATATYPE_ALL_TECH)

    # Color the techniques based on how the coverage defined in the detections definition and generate a list with
    # techniques to be used in the layer output file.
    mapped_techniques = []
    try:
        for d, c in my_techniques.items():
            s = -1 if 'detection' not in c.keys() else c['detection']['score']
            color = COLOR_D_0 if s == 0 else COLOR_D_1 if s == 1 else COLOR_D_2 if s == 2 else COLOR_D_3 \
                if s == 3 else COLOR_D_4 if s == 4 else COLOR_D_5 if s == 5 else ''
            technique = get_technique(techniques, d)
            for tactic in technique['tactic']:
                location = ', '.join(c['detection']['location']) if 'detection' in c.keys() else '-'
                location = location if location != '' else '-'
                x = {}
                x['techniqueID'] = d
                x['color'] = color
                x['comment'] = ''
                x['enabled'] = True
                x['tactic'] = tactic.lower().replace(' ', '-')
                x['metadata'] = [{'name': '-Detection score', 'value': str(s)},
                                 {'name': '-Detection location', 'value': location}]

                mapped_techniques.append(x)
    except Exception:
        print('[!] Possible error in YAML file at: ' + d)
        quit()

    return mapped_techniques


def _map_and_colorize_techniques_for_visibility(my_techniques, my_data_sources):
    """
    Determine the color of the techniques based on the visibility score in the given yaml file.
    :param my_techniques: the configured techniques
    :param my_data_sources: the configured data sources
    :return: a dictionary with techniques that can be used in the layer's output file
    """
    techniques = load_attack_data(DATATYPE_ALL_TECH)

    technique_ds_mapping = map_techniques_to_data_sources(techniques, my_data_sources)

    # Color the techniques based on how the coverage defined in the detections definition and generate a list with
    # techniques to be used in the layer output file.
    mapped_techniques = []
    for d, c in my_techniques.items():
        s = 0 if 'visibility' not in c.keys() else c['visibility']['score']
        if 'visibility' in c.keys():
            comment = str(c['visibility']['comment']) if str(c['visibility']['comment']) != '' else '-'
        else:
            comment = '-'
        my_ds = ', '.join(technique_ds_mapping[d]['my_data_sources']) if d in technique_ds_mapping.keys() and technique_ds_mapping[d]['my_data_sources'] else '-'
        color = COLOR_V_1 if s == 1 else COLOR_V_2 if s == 2 else COLOR_V_3 if s == 3 else COLOR_V_4 if s == 4 else ''
        technique = get_technique(techniques, d)
        for tactic in technique['tactic']:
            x = {}
            x['techniqueID'] = d
            x['color'] = color
            x['comment'] = ''
            x['enabled'] = True
            x['tactic'] = tactic.lower().replace(' ', '-')
            x['metadata'] = [{'name': '-Visibility score', 'value': str(s)},
                             {'name': '-Comment', 'value': comment},
                             {'name': '-Available data sources', 'value': my_ds},
                             {'name': '-ATT&CK data sources', 'value': ', '.join(technique['data_sources'])}]

            mapped_techniques.append(x)

    for t in techniques:
        if t['technique_id'] not in my_techniques.keys():
            if t['tactic']:
                for tactic in t['tactic']:
                    x = {}
                    x['techniqueID'] = t['technique_id']
                    x['comment'] = ''
                    x['enabled'] = True
                    x['tactic'] = tactic.lower().replace(' ', '-')
                    ds = ', '.join(t['data_sources']) if t['data_sources'] else '-'
                    x['metadata'] = [{'name': '-ATT&CK data sources', 'value': ds}]

                    mapped_techniques.append(x)

    return mapped_techniques


def _map_and_colorize_techniques_for_overlayed(my_techniques, my_data_sources):
    """
    Determine the color of the techniques based on both detection and visibility.
    :param my_techniques: the configured techniques
    :param my_data_sources: the configured data sources
    :return: a dictionary with techniques that can be used in the layer's output file
    """
    techniques = load_attack_data(DATATYPE_ALL_TECH)

    technique_ds_mapping = map_techniques_to_data_sources(techniques, my_data_sources)

    # Color the techniques based on how the coverage defined in the detections definition and generate a list with
    # techniques to be used in the layer output file.
    mapped_techniques = []
    for d, c in my_techniques.items():
        detection_score = 0 if 'detection' not in c.keys() else c['detection']['score']
        visibility_score = 0 if 'visibility' not in c.keys() else c['visibility']['score']

        detection = True if detection_score > 0 else False
        visibility = True if visibility_score > 0 else False

        if detection and visibility:
            color = COLOR_OVERLAY_BOTH
        elif detection and not visibility:
            color = COLOR_OVERLAY_DETECTION
        elif not detection and visibility:
            color = COLOR_OVERLAY_VISIBILITY

        location = ', '.join(c['detection']['location']) if 'detection' in c.keys() else '-'
        location = location if location != '' else '-'

        if 'visibility' in c.keys():
            comment = str(c['visibility']['comment']) if str(c['visibility']['comment']) != '' else '-'
        else:
            comment = '-'

        my_ds = ', '.join(technique_ds_mapping[d]['my_data_sources']) if d in technique_ds_mapping.keys() and technique_ds_mapping[d]['my_data_sources'] else '-'

        technique = get_technique(techniques, d)
        for tactic in technique['tactic']:
            x = {}
            x['techniqueID'] = d
            x['color'] = color
            x['comment'] = ''
            x['enabled'] = True
            x['tactic'] = tactic.lower().replace(' ', '-')
            x['metadata'] = [{'name': '-Visibility score', 'value': str(visibility_score)},
                             {'name': '-Comment', 'value': comment},
                             {'name': '-Available data sources', 'value': my_ds},
                             {'name': '-ATT&CK data sources', 'value': ', '.join(technique['data_sources'])},
                             {'name': '-Detection score', 'value': str(detection_score)},
                             {'name': '-Detection location', 'value': location}]

            mapped_techniques.append(x)

    return mapped_techniques


def export_techniques_list_to_excel(filename):
    """
    Makes an overview of the MITRE ATT&CK techniques from the YAML administration file.
    :param filename: the filename of the yaml file containing the techniques administration
    :return:
    """
    my_techniques, name, platform = _load_detections(filename)
    my_techniques = dict(sorted(my_techniques.items(), key=lambda kv: kv[0], reverse=False))
    mitre_techniques = load_attack_data(DATATYPE_ALL_TECH)

    excel_filename = 'output/techniques.xlsx'
    workbook = xlsxwriter.Workbook(excel_filename)
    worksheet = workbook.add_worksheet('Data sources')

    # Formatting:
    format_bold_left = workbook.add_format({'align': 'left', 'bold': True})
    format_title = workbook.add_format({'align': 'left', 'bold': True, 'font_size': '14'})
    format_left = workbook.add_format({'align': 'left'})
    format_bold_center_bggrey = workbook.add_format({'align': 'center', 'bold': True, 'bg_color': '#dbdbdb'})
    format_bold_center_bgreen = workbook.add_format({'align': 'center', 'bold': True, 'bg_color': '#8bc34a'})
    format_bold_center_bgblue = workbook.add_format({'align': 'center', 'bold': True, 'bg_color': '#64b5f6'})

    # Title
    worksheet.write(0, 0, 'Overview of techniques for ' + name, format_title)

    # Header columns
    worksheet.merge_range(2, 0, 2, 2, 'Technique', format_bold_center_bggrey)
    worksheet.merge_range(2, 3, 2, 7, 'Detection', format_bold_center_bgreen)
    worksheet.merge_range(2, 8, 2, 9, 'Visibility', format_bold_center_bgblue)
    y = 3
    worksheet.write(y, 0, 'ID', format_bold_left)
    worksheet.write(y, 1, 'Tactic', format_bold_left)
    worksheet.write(y, 2, 'Description', format_bold_left)
    worksheet.write(y, 3, 'Date registered', format_bold_left)
    worksheet.write(y, 4, 'Date implemented', format_bold_left)
    worksheet.write(y, 5, 'Score', format_bold_left)
    worksheet.write(y, 6, 'Location', format_bold_left)
    worksheet.write(y, 7, 'Comment', format_bold_left)
    worksheet.write(y, 8, 'Score', format_bold_left)
    worksheet.write(y, 9, 'Comment', format_bold_left)

    worksheet.set_column(0, 0, 14)
    worksheet.set_column(1, 1, 50)
    worksheet.set_column(2, 2, 40)
    worksheet.set_column(3, 3, 15)
    worksheet.set_column(4, 4, 18)
    worksheet.set_column(5, 5, 8)
    worksheet.set_column(6, 6, 25)
    worksheet.set_column(7, 7, 40)
    worksheet.set_column(8, 8, 8)
    worksheet.set_column(9, 9, 40)

    # Putting the techniques:
    y = 4
    for d, c in my_techniques.items():
        worksheet.write(y, 0, d)
        worksheet.write(y, 1, ', '.join(t.capitalize() for t in get_technique(mitre_techniques, d)['tactic']))
        worksheet.write(y, 2, get_technique(mitre_techniques, d)['technique'])
        worksheet.write(y, 3, str(c['detection']['date_registered']).replace('None', ''))
        worksheet.write(y, 4, str(c['detection']['date_implemented']).replace('None', ''))
        worksheet.write(y, 5, c['detection']['score'], format_left)
        worksheet.write(y, 6, ','.join(c['detection']['location']))
        worksheet.write(y, 7, c['detection']['comment'])
        worksheet.write(y, 8, c['visibility']['score'], format_left)
        worksheet.write(y, 9, c['visibility']['comment'])
        y += 1

    worksheet.autofilter(3, 0, 3, 9)
    worksheet.freeze_panes(4, 0)
    try:
        workbook.close()
        print("File written: " + excel_filename)
    except Exception as e:
        print('[!] Error while writing Excel file: %s' % str(e))
