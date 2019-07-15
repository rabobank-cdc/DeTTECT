import simplejson
from generic import *
import xlsxwriter
import copy
# Imports for pandas and plotly are because of performance reasons in the function that uses these libraries.


def generate_data_sources_layer(filename):
    """
    Generates a generic layer for data sources.
    :param filename: the filename of the yaml file containing the data sources administration
    :return:
    """
    my_data_sources, name, platform, exceptions = _load_data_sources(filename)

    # Do the mapping between my data sources and MITRE data sources:
    my_techniques = _map_and_colorize_techniques(my_data_sources, exceptions)

    layer = get_layer_template_data_sources("Data sources " + name, 'description', 'attack', platform)
    layer['techniques'] = my_techniques

    json_string = simplejson.dumps(layer).replace('}, ', '},\n')
    output_filename = 'output/data_sources_' + normalize_name_to_filename(name) + '.json'
    with open(output_filename, 'w') as f:
        f.write(json_string)
    print("File written: " + output_filename)


def plot_data_sources_graph(filename):
    """
    Generates a line graph which shows the improvements on numbers of data sources through time.
    :param filename: the filename of the yaml file containing the data sources administration
    :return:
    """
    my_data_sources, name, platform, exceptions = _load_data_sources(filename)

    graph_values = []
    for t in my_data_sources.values():
        if t['date_connected']:
            yyyymm = t['date_connected'].strftime('%Y-%m')
            graph_values.append({'date': yyyymm, 'count': 1})

    import pandas as pd
    df = pd.DataFrame(graph_values).groupby('date', as_index=False)[['count']].sum()
    df['cumcount'] = df.ix[::1, 'count'].cumsum()[::1]

    output_filename = 'output/graph_data_sources.html'

    import plotly
    import plotly.graph_objs as go
    plotly.offline.plot(
        {'data': [go.Scatter(x=df['date'], y=df['cumcount'])],
         'layout': go.Layout(title="# of data sources for " + name)},
        filename=output_filename, auto_open=False
    )
    print("File written: " + output_filename)


def export_data_source_list_to_excel(filename):
    """
    Makes an overview of all MITRE ATT&CK data sources (via techniques) and lists which data sources are present
    in the yaml administration including all properties and data quality score.
    :param filename: the filename of the yaml file containing the data sources administration
    :return:
    """
    my_data_sources, name, platform, exceptions = _load_data_sources(filename, filter_empty_scores=False)

    excel_filename = 'output/data_sources.xlsx'
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
    worksheet.set_column(3, 4, 35)
    worksheet.set_column(5, 5, 24)
    worksheet.set_column(6, 7, 25)
    worksheet.set_column(8, 10, 15)
    worksheet.set_column(11, 11, 10)

    # Putting the data sources data:
    y = 3
    for d in get_all_mitre_data_sources():
        worksheet.write(y, 0, d, valign_top)
        if d in my_data_sources.keys():
            ds = my_data_sources[d]
            worksheet.write(y, 1, str(ds['date_registered']).replace('None', ''), valign_top)
            worksheet.write(y, 2, str(ds['date_connected']).replace('None', ''), valign_top)
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
            for s in ds['data_quality'].values():
                if s != 0:
                    score_count += 1
                    score += s
            if score > 0:
                score = score/score_count

            worksheet.write(y, 11, score, dq_score_1 if score < 2 else dq_score_2 if score < 3 else dq_score_3 if score < 4 else dq_score_4 if score < 5 else dq_score_5 if score < 6 else no_score)
        y += 1

    worksheet.autofilter(2, 0, 2, 11)
    worksheet.freeze_panes(3, 0)
    try:
        workbook.close()
        print("File written: " + excel_filename)
    except Exception as e:
        print('[!] Error while writing Excel file: %s' % str(e))


def _load_data_sources(filename, filter_empty_scores=True):
    """
    Loads the data sources (including all properties) from the given yaml file.
    :param filename: the filename of the yaml file containing the data sources administration
    :return: dictionaty with data sources, name, platform and exceptions list.
    """
    my_data_sources = {}
    with open(filename, 'r') as yaml_file:
        yaml_content = yaml.load(yaml_file, Loader=yaml.FullLoader)
        for d in yaml_content['data_sources']:
            dq = d['data_quality']
            if not filter_empty_scores:
                my_data_sources[d['data_source_name']] = d
            elif dq['device_completeness'] > 0 and dq['data_field_completeness'] > 0 and dq['timeliness'] > 0 and dq['consistency'] > 0:
                my_data_sources[d['data_source_name']] = d
        name = yaml_content['name']
        platform = yaml_content['platform']
        exceptions = [t['technique_id'] for t in yaml_content['exceptions']]
    return my_data_sources, name, platform, exceptions


def _map_and_colorize_techniques(my_ds, exceptions):
    """
    Determine the color of the techniques based on how many data sources are available per technique.
    :param my_ds: the configured data sources
    :return: a dictionary with techniques that can be used in the layer's output file
    """
    techniques = load_attack_data(DATA_TYPE_STIX_ALL_TECH)
    technique_colors = {}

    # Color the techniques based on how many data sources are available.
    for t in techniques:
        if 'x_mitre_data_sources' in t:
            total_ds_count = len(t['x_mitre_data_sources'])
            ds_count = 0
            for ds in t['x_mitre_data_sources']:
                if ds in my_ds.keys():
                    ds_count += 1
            if total_ds_count > 0:
                result = (float(ds_count) / float(total_ds_count)) * 100
                color = COLOR_DS_25p if result <= 25 else COLOR_DS_50p if result <= 50 else COLOR_DS_75p \
                    if result <= 75 else COLOR_DS_99p if result <= 99 else COLOR_DS_100p
                technique_colors[get_attack_id(t)] = color

    my_techniques = map_techniques_to_data_sources(techniques, my_ds)

    output_techniques = []
    for t, v in my_techniques.items():
        if t not in exceptions:
            for tactic in v['tactics']:
                d = {}
                d['techniqueID'] = t
                # d['score'] = 50
                d['color'] = technique_colors[t]
                d['comment'] = ''
                d['enabled'] = True
                d['tactic'] = tactic.lower().replace(' ', '-')
                d['metadata'] = [{'name': '-Available data sources', 'value': ', '.join(v['my_data_sources'])},
                                 {'name': '-ATT&CK data sources', 'value': ', '.join(v['data_sources'])},
                                 {'name': '-Products', 'value': ', '.join(v['products'])}]

                output_techniques.append(d)

    return output_techniques


def generate_technique_administration_file(filename):
    """
    Generate a technique administration file based on the data source administration yaml file
    :param filename: the filename of the yaml file containing the data sources administration
    :return:
    """
    my_data_sources, name, platform, exceptions = _load_data_sources(filename)

    techniques = load_attack_data(DATA_TYPE_STIX_ALL_TECH_ENTERPRISE)

    # This is part of the techniques administration YAML file and is used as a template
    dict_tech = {'technique_id': '', 'technique_name': '', 'detection': {'applicable_to': ['all'],
                                                                         'date_registered': None,
                                                                         'date_implemented': None,
                                                                         'score': -1, 'location': [''], 'comment': ''},
                 'visibility': {'applicable_to': ['all'], 'score': 0, 'comment': ''}}

    yaml_file = {}
    yaml_file['version'] = FILE_TYPE_TECHNIQUE_ADMINISTRATION_VERSION
    yaml_file['file_type'] = FILE_TYPE_TECHNIQUE_ADMINISTRATION
    yaml_file['name'] = name
    yaml_file['platform'] = platform
    yaml_file['techniques'] = []

    # Score visibility based on the number of available data sources and the exceptions
    for t in techniques:
        platforms_lower = list(map(lambda x: x.lower(), try_get_key(t, 'x_mitre_platforms')))
        if platform in platforms_lower:
            # not every technique has data source listed
            if 'x_mitre_data_sources' in t:
                total_ds_count = len(t['x_mitre_data_sources'])
                ds_count = 0
                for ds in t['x_mitre_data_sources']:
                    if ds in my_data_sources.keys():
                        ds_count += 1
                if total_ds_count > 0:
                    result = (float(ds_count) / float(total_ds_count)) * 100

                    score = 0 if result == 0 else 1 if result <= 49 else 2 if result <= 74 else 3 if result <= 99 else 4
                else:
                    score = 0

                # Do not add technique if score == 0 or part of the exception list
                techniques_upper = list(map(lambda x: x.upper(), exceptions))
                tech_id = get_attack_id(t)
                if score > 0 and tech_id not in techniques_upper:
                    tech = copy.deepcopy(dict_tech)
                    tech['technique_id'] = tech_id
                    tech['technique_name'] = t['name']
                    tech['visibility']['score'] = score
                    yaml_file['techniques'].append(tech)

    yaml_string = '%YAML 1.2\n---\n' + yaml.dump(yaml_file, sort_keys=False).replace('null', '')
    output_filename = 'output/techniques-administration-' + normalize_name_to_filename(name+'-'+platform) + '.yaml'
    suffix = 1
    while os.path.exists(output_filename):
        output_filename = 'output/techniques-administration-' + normalize_name_to_filename(name + '-' + platform) + \
                          '_' + str(suffix) + '.yaml'
        suffix += 1

    with open(output_filename, 'w') as f:
        f.write(yaml_string)
    print("File written: " + output_filename)
