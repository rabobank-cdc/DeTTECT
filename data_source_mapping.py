import xlsxwriter
import simplejson
from copy import deepcopy
from datetime import datetime
from itertools import chain
from generic import *
from file_output import *
from navigator_layer import *
# Imports for pandas and plotly are because of performance reasons in the function that uses these libraries.


def _count_applicable_data_sources(technique, applicable_data_sources, applicable_dettect_data_sources):
    """
    get the count of applicable (DeTT&CT) data sources for the provided technique.
    This takes into account which data sources are applicable for a platform(s).
    :param technique: ATT&CK CTI technique object
    :param applicable_data_sources: a list of applicable ATT&CK data sources
    :param applicable_dettect_data_sources: a list of applicable DeTT&CT data sources
    :return: a count of the applicable data sources for this technique
    """
    applicable_ds_count = 0

    for ds in technique['data_components']:
        if ds in applicable_data_sources:
            applicable_ds_count += 1

    for ds in technique['dettect_data_sources']:
        if ds in applicable_dettect_data_sources:
            applicable_ds_count += 1

    return applicable_ds_count


def _system_in_data_source_details_object(data_source, system):
    """
    Checks if the provided system is present within the provided YAML global data source object
    :param data_source: YAML data source object
    :param system: YAML system object
    :return: True if present otherwise False
    """
    for ds in data_source['data_source']:
        if system['applicable_to'].lower() in (app_to.lower() for app_to in ds['applicable_to']):
            return True
    return False


def _map_and_colorize_techniques(my_ds, systems, exceptions, domain, layer_settings):
    """
    Determine the color of the technique based on how many data sources are available per technique. Also, it will
    create much of the content for the Navigator layer.
    :param my_ds: the configured data sources
    :param systems: the systems YAML object from the data source file
    :param exceptions: the list of ATT&CK technique exception within the data source YAML file
    :param domain: the specified domain
    :param layer_settings: settings for the Navigator layer
    :return: a dictionary with techniques that can be used in the layer's output file
    """
    techniques = load_attack_data(DATA_TYPE_STIX_ALL_TECH_ENTERPRISE if domain ==
                                  'enterprise-attack' else DATA_TYPE_STIX_ALL_TECH_ICS if domain == 'ics-attack' else DATA_TYPE_STIX_ALL_TECH_MOBILE)
    output_techniques = []

    for t in techniques:
        tech_id = t['technique_id']
        
        tactics = []
        if 'includeTactic' in layer_settings.keys() and layer_settings['includeTactic'] == 'True':
            for kill_chain_phase in t['kill_chain_phases']:
                if kill_chain_phase['kill_chain_name'] == 'mitre-attack':
                    tactics.append(kill_chain_phase['phase_name'])
        else:
            tactics.append(None)
        
        if tech_id not in list(map(lambda x: x.upper(), exceptions)):
            scores_idx = 0
            ds_scores = []
            system_available_data_sources = {}

            # calculate visibility score per system
            for system in systems:
                # the system is relevant for this technique due to a match in ATT&CK platform
                if len(set(system['platform']).intersection(set(t['x_mitre_platforms']))) > 0:
                    applicable_data_sources = get_applicable_data_sources_platform(system['platform'], domain)
                    applicable_dettect_data_sources = get_applicable_dettect_data_sources_platform(system['platform'], domain)
                    total_ds_count = _count_applicable_data_sources(t, applicable_data_sources, applicable_dettect_data_sources)

                    if total_ds_count > 0:  # the system's platform has a data source applicable to this technique
                        ds_count = 0
                        for ds in t['data_components']:
                            # the ATT&CK data source is applicable to this system and available
                            if ds in applicable_data_sources and ds in my_ds.keys() and _system_in_data_source_details_object(my_ds[ds], system):
                                if ds_count == 0:
                                    system_available_data_sources[scores_idx] = [ds]
                                else:
                                    system_available_data_sources[scores_idx].append(ds)
                                ds_count += 1

                        for cdc in t['dettect_data_sources']:
                            if cdc in applicable_dettect_data_sources and cdc in my_ds.keys() and _system_in_data_source_details_object(my_ds[cdc], system):
                                if ds_count == 0:
                                    system_available_data_sources[scores_idx] = [cdc]
                                else:
                                    system_available_data_sources[scores_idx].append(cdc)
                                ds_count += 1

                        if ds_count > 0:
                            ds_scores.append((float(ds_count) / float(total_ds_count)) * 100)
                        else:
                            ds_scores.append(0)  # none of the applicable data sources are available for this system
                    else:
                        # the technique is applicable to this system (and thus its platform(s)),
                        # but none of the technique's listed data source are applicable for its platform(s)
                        ds_scores.append(0)
                    scores_idx += 1

            # Populate the metadata.
            avg_ds_score = 0
            if not all(s == 0 for s in ds_scores):
                avg_ds_score = float(sum(ds_scores)) / float(len(ds_scores))

            color = COLOR_DS_25p if avg_ds_score <= 25 else COLOR_DS_50p if avg_ds_score <= 50 else COLOR_DS_75p \
                if avg_ds_score <= 75 else COLOR_DS_99p if avg_ds_score <= 99 else COLOR_DS_100p

            d = dict()
            d['techniqueID'] = tech_id
            if avg_ds_score > 0:
                d['color'] = color
            d['comment'] = ''
            d['enabled'] = True
            d['metadata'] = []

            if 'showMetadata' not in layer_settings.keys() or ('showMetadata' in layer_settings.keys() and str(layer_settings['showMetadata']) == 'True'):
                scores_idx = 0
                divider = 0
                for system in systems:
                    # the system is relevant for this technique due to a match in ATT&CK platform
                    if len(set(system['platform']).intersection(set(t['x_mitre_platforms']))) > 0:
                        score = ds_scores[scores_idx]

                        if divider != 0:
                            d['metadata'].append({'divider': True})
                        divider += 1

                        d['metadata'].append({'name': 'Applicable to', 'value': system['applicable_to']})

                        app_data_sources = sorted(get_applicable_data_sources_technique(
                            t['data_components'], get_applicable_data_sources_platform(system['platform'], domain)))
                        app_dettect_data_sources = sorted(get_applicable_dettect_data_sources_technique(
                            t['dettect_data_sources'], get_applicable_dettect_data_sources_platform(system['platform'], domain)))

                        if score > 0:
                            d['metadata'].append({'name': 'Available data sources', 'value': ', '.join(
                                system_available_data_sources[scores_idx])})
                        else:
                            d['metadata'].append({'name': 'Available data sources', 'value': ''})

                        d['metadata'].append({'name': 'ATT&CK data sources', 'value': ', '.join(app_data_sources)})
                        d['metadata'].append({'name': 'DeTT&CT data sources', 'value': ', '.join(app_dettect_data_sources)})
                        d['metadata'].append({'name': 'Score', 'value': str(int(score)) + '%'})
                        scores_idx += 1

                d['metadata'] = make_layer_metadata_compliant(d['metadata'])

            for tactic in tactics:
                if tactic is not None:
                    d['tactic'] = tactic
                output_techniques.append(deepcopy(d))

    determine_and_set_show_sub_techniques(output_techniques, techniques, layer_settings)

    return output_techniques


def _indent_comment(comment, indent):
    """
    Indent a multiline general, visibility, detection comment by x spaces
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


def generate_data_sources_layer(filename, output_filename, output_overwrite, layer_name, layer_settings):
    """
    Generates a generic layer for data sources.
    :param filename: the filename of the YAML file containing the data sources administration
    :param output_filename: the output filename defined by the user
    :param output_overwrite: boolean flag indicating whether we're in overwrite mode
    :param layer_name: the name of the Navigator layer
    :param layer_settings: settings for the Navigator layer
    :return:
    """
    my_data_sources, name, systems, exceptions, domain = load_data_sources(filename)

    # Do the mapping between my data sources and MITRE data sources:
    my_techniques = _map_and_colorize_techniques(my_data_sources, systems, exceptions, domain, layer_settings)

    if not layer_name:
        layer_name = 'Data sources ' + name

    platforms = list(set(chain.from_iterable(map(lambda k: k['platform'], systems))))
    layer = get_layer_template_data_sources(layer_name, 'description', platforms, domain, layer_settings)
    layer['techniques'] = my_techniques

    json_string = simplejson.dumps(layer).replace('}, ', '},\n')
    if not output_filename:
        output_filename = create_output_filename('data_sources', name)
    write_file(output_filename, output_overwrite, json_string)


def plot_data_sources_graph(filename, output_filename, output_overwrite):
    """
    Generates a line graph which shows the improvements on numbers of data sources through time.
    :param filename: the filename of the YAML file containing the data sources administration
    :param output_filename: the output filename defined by the user
    :param output_overwrite: boolean flag indicating whether we're in overwrite mode
    :return:
    """
    my_data_sources, name, _, _, _ = load_data_sources(filename)

    graph_values = []
    for ds_global, ds_detail in my_data_sources.items():
        for ds in ds_detail['data_source']:
            if ds['date_connected']:
                yyyymmdd = ds['date_connected'].strftime('%Y-%m-%d')
                graph_values.append({'date': yyyymmdd, 'count': 1})

    import pandas as pd
    df = pd.DataFrame(graph_values).groupby('date', as_index=False)[['count']].sum()
    df['cumcount'] = df['count'].cumsum()

    if not output_filename:
        output_filename = 'graph_data_sources'
    elif output_filename.endswith('.html'):
        output_filename = output_filename.replace('.html', '')
    
    if os.sep not in output_filename:
        output_filename = 'output/%s' % output_filename

    if not output_overwrite:
        output_filename = get_non_existing_filename(output_filename, 'html')
    else:
        output_filename = use_existing_filename(output_filename, 'html')

    try:
        import plotly.graph_objs as go
        import plotly.offline as offline
        offline.plot(
            {'data': [go.Scatter(x=df['date'], y=df['cumcount'])],
            'layout': go.Layout(title="# of data sources for " + name)},
            filename=output_filename, auto_open=False
        )
        print("File written:   " + output_filename)
    except Exception as e:
        print('[!] Error while writing graph file: %s' % str(e))


def export_data_source_list_to_excel(filename, output_filename, output_overwrite, eql_search=False):
    """
    Makes an overview of all MITRE ATT&CK data sources (via techniques) and lists which data sources are present
    in the YAML administration including all properties and data quality score.
    :param filename: the filename of the YAML file containing the data sources administration
    :param output_filename: the output filename defined by the user
    :param output_overwrite: boolean flag indicating whether we're in overwrite mode
    :param eql_search: specify if an EQL search was performed which may have resulted in missing ATT&CK data sources
    :return:
    """
    # pylint: disable=unused-variable
    my_data_sources, name, systems, _, domain = load_data_sources(filename, filter_empty_scores=False)
    my_data_sources = dict(sorted(my_data_sources.items(), key=lambda kv: kv[0], reverse=False))

    if not output_filename:
        output_filename = 'data_sources'
    elif output_filename.endswith('.xlsx'):
        output_filename = output_filename.replace('.xlsx', '')
    
    if os.sep not in output_filename:
        output_filename = 'output/%s' % output_filename

    if not output_overwrite:
        excel_filename = get_non_existing_filename(output_filename, 'xlsx')
    else:
        excel_filename = use_existing_filename(output_filename, 'xlsx')

    workbook = xlsxwriter.Workbook(excel_filename)
    worksheet = workbook.add_worksheet('Data sources')

    # Formatting:
    format_bold_left = workbook.add_format({'align': 'left', 'bold': True})
    format_title = workbook.add_format({'align': 'left', 'bold': True, 'font_size': '14'})
    format_center_valign_top = workbook.add_format({'align': 'center', 'valign': 'top'})
    wrap_text = workbook.add_format({'text_wrap': True, 'valign': 'top'})
    valign_top = workbook.add_format({'valign': 'top'})
    no_score = workbook.add_format({'valign': 'top', 'align': 'center'})
    dq_score_0 = workbook.add_format({'valign': 'top', 'align': 'center'})
    dq_score_1 = workbook.add_format({'valign': 'top', 'align': 'center', 'bg_color': COLOR_DS_25p})
    dq_score_2 = workbook.add_format({'valign': 'top', 'align': 'center', 'bg_color': COLOR_DS_50p})
    dq_score_3 = workbook.add_format({'valign': 'top', 'align': 'center', 'bg_color': COLOR_DS_75p, 'font_color': '#ffffff'})
    dq_score_4 = workbook.add_format({'valign': 'top', 'align': 'center', 'bg_color': COLOR_DS_99p, 'font_color': '#ffffff'})
    dq_score_5 = workbook.add_format({'valign': 'top', 'align': 'center', 'bg_color': COLOR_DS_100p, 'font_color': '#ffffff'})

    # Title
    worksheet.write(0, 0, 'Data sources for: ' + name, format_title)
    worksheet.write(1, 0, 'Domain: ' + domain)
    worksheet.write(2, 0, 'Systems: ')
    y = 3
    for system in systems:
        worksheet.write(y, 0, '- %s: %s' % (system['applicable_to'], ', '.join(system['platform'])))
        y += 1

    # Header columns
    y += 1
    worksheet.write(y, 0, 'Data source name', format_bold_left)
    worksheet.write(y, 1, 'Applicable to', format_bold_left)
    worksheet.write(y, 2, 'Date registered', format_bold_left)
    worksheet.write(y, 3, 'Date connected', format_bold_left)
    worksheet.write(y, 4, 'Products', format_bold_left)
    worksheet.write(y, 5, 'Comment', format_bold_left)
    worksheet.write(y, 6, 'Available for data analytics', format_bold_left)
    worksheet.write(y, 7, 'DQ: device completeness', format_bold_left)
    worksheet.write(y, 8, 'DQ: data field completeness', format_bold_left)
    worksheet.write(y, 9, 'DQ: timeliness', format_bold_left)
    worksheet.write(y, 10, 'DQ: consistency', format_bold_left)
    worksheet.write(y, 11, 'DQ: retention', format_bold_left)
    worksheet.write(y, 12, 'DQ: score', format_bold_left)

    worksheet.autofilter(y, 0, y, 12)
    worksheet.freeze_panes(y + 1, 0)

    worksheet.set_column(0, 0, 35)
    worksheet.set_column(1, 1, 18)
    worksheet.set_column(2, 3, 15)
    worksheet.set_column(4, 4, 35)
    worksheet.set_column(5, 5, 50)
    worksheet.set_column(6, 6, 24)
    worksheet.set_column(7, 8, 25)
    worksheet.set_column(9, 11, 15)
    worksheet.set_column(12, 12, 10)

    # Putting the data sources data:
    y += 1

    for ds_global, ds_detail in my_data_sources.items():

        for ds in ds_detail['data_source']:
            worksheet.write(y, 0, ds_global, valign_top)

            date_registered = ds['date_registered'].strftime('%Y-%m-%d') if isinstance(ds['date_registered'], datetime) else ds['date_registered']
            date_connected = ds['date_connected'].strftime('%Y-%m-%d') if isinstance(ds['date_connected'], datetime) else ds['date_connected']

            worksheet.write(y, 1, ', '.join(ds['applicable_to']), wrap_text)
            worksheet.write(y, 2, str(date_registered).replace('None', ''), valign_top)
            worksheet.write(y, 3, str(date_connected).replace('None', ''), valign_top)
            worksheet.write(y, 4, ', '.join(ds['products']).replace('None', ''), valign_top)
            worksheet.write(y, 5, ds['comment'][:-1] if ds['comment'].endswith('\n') else ds['comment'], wrap_text)
            worksheet.write(y, 6, str(ds['available_for_data_analytics']), valign_top)
            worksheet.write(y, 7, ds['data_quality']['device_completeness'], format_center_valign_top)
            worksheet.write(y, 8, ds['data_quality']['data_field_completeness'], format_center_valign_top)
            worksheet.write(y, 9, ds['data_quality']['timeliness'], format_center_valign_top)
            worksheet.write(y, 10, ds['data_quality']['consistency'], format_center_valign_top)
            worksheet.write(y, 11, ds['data_quality']['retention'], format_center_valign_top)

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

            worksheet.write(y, 12, score, dq_score_0 if score == 0 else dq_score_1 if score < 2 else dq_score_2 if score < 3 else dq_score_3 if score < 4 else dq_score_4 if score < 5 else dq_score_5 if score < 6 else no_score)  # noqa
            y += 1

    try:
        workbook.close()
        print("File written:   " + excel_filename)
    except Exception as e:
        print('[!] Error while writing Excel file: %s' % str(e))


def _print_ds_systems(systems):
    """
    Print the data source systems key-value pair to stdout
    :param systems: systems key value pair
    :return:
    """
    print(' ' * 4 + 'Data source administration \'systems\' key-value pair:')
    for s in systems:
        print(' ' * 4 + '  * applicable_to: ' + s['applicable_to'])
        for p in s['platform']:
            print(' ' * 4 + '     - ' + p)


def _print_tech_visibility_object_diff(old_tech, new_tech, tech_id, tech_name):
    """
    Print the 'diff' of the old and and the new visibility object(s) as part of a technique
    :param old_vis_obj: old technique object
    :param new_vis_obj: new technique object
    :param tech_id: technique ID of the visibility object
    :param tech_name: technique name
    :return:
    """
    print('\n')
    print('Technique: ' + tech_id + ' / ' + tech_name)
    print('')
    print('OLD visibility object(s):')
    for old_vis_obj in old_tech['visibility']:
        old_score_date = get_latest_date(old_vis_obj)
        old_score_date = old_score_date.strftime('%Y-%m-%d') if old_score_date is not None else ''
        print(' - Applicable to: ' + ', '.join(old_vis_obj['applicable_to']))
        print('   * Date:                     ' + old_score_date)
        print('   * Score:                    ' + str(get_latest_score(old_vis_obj)))
        print('   * Visibility score comment: ' + _indent_comment(get_latest_comment(old_vis_obj), 31))
        print('   * Auto generated:           ' + str(get_latest_score_obj(old_vis_obj).get('auto_generated', 'False')))
    print('NEW visibility object(s):')
    for new_vis_obj in new_tech['visibility']:
        new_score_date = new_vis_obj['score_logbook'][0]['date'].strftime('%Y-%m-%d')
        print(' - Applicable to: ' + ', '.join(new_vis_obj['applicable_to']))
        print('   * Date:                     ' + new_score_date)
        print('   * Score:                    ' + str(new_vis_obj['score_logbook'][0]['score']))
        print('   * Visibility score comment: ' + _indent_comment(new_vis_obj['score_logbook'][0]['comment'], 31))
        print('   * Auto generated:           True')
    print('\n')


def _print_visibility_object_diff(old_vis_obj, new_vis_obj, tech_id, tech_name):
    """
    Print the 'diff' of the old and and the new visibility object
    :param old_vis_obj: old visibility object
    :param new_vis_obj: new visibility object
    :param tech_id: technique ID of the visibility object
    :param tech_name: technique name
    :return:
    """
    print('\n')
    print('Visibility object:')
    print(' - ATT&CK ID/name            ' + tech_id + ' / ' + tech_name)
    print(' - Applicable to:            ' + ', '.join(old_vis_obj['applicable_to']))
    print(' - Visibility comment:       ' + _indent_comment(old_vis_obj['comment'], 29))
    print('')
    print('OLD score object:')
    old_score_date = get_latest_date(old_vis_obj)
    old_score_date = old_score_date.strftime('%Y-%m-%d') if old_score_date is not None else ''
    new_score_date = new_vis_obj['score_logbook'][0]['date'].strftime('%Y-%m-%d')
    print(' - Date:                     ' + old_score_date)
    print(' - Score:                    ' + str(get_latest_score(old_vis_obj)))
    print(' - Visibility score comment: ' + _indent_comment(get_latest_comment(old_vis_obj), 29))
    print(' - Auto generated:           ' + str(get_latest_score_obj(old_vis_obj).get('auto_generated', 'False')))
    print('NEW score object:')
    print(' - Date:                     ' + new_score_date)
    print(' - Score:                    ' + str(new_vis_obj['score_logbook'][0]['score']))
    print(' - Visibility score comment: ' + _indent_comment(new_vis_obj['score_logbook'][0]['comment'], 29))
    print(' - Auto generated:           True')
    print('\n')


def _print_progress_visibility_update(count, total):
    """
    Print the progress of the visibility update to stdout
    :parm count: counter / how far are we in the progress?
    :param total: total techniques to process
    :return:
    """
    print(' \n' + '-' * 80)
    percentage = round((100 * count) / total, 0)
    tmp_txt1 = 'Progress: ' + str(percentage) + '% '
    tmp_txt2 = '[techniques remaining to be checked ' + str(total - count) + ']'
    print(tmp_txt1 + ' ' * (80 - len(tmp_txt1 + tmp_txt2)) + tmp_txt2)


def _add_visibility_object_to_dict(dict_vis_objects, tech_id, vis_obj):
    """
    Add visibility object(s) to a dict with the structure {tech_id: [visibility_obj]}
    :param dict_vis_objects: the dictionary to add the visibility object(s) to
    :param tech_id: the technique ID to which the visibility object(s) needs to be added
    :param vis_obj: the visibility object(s) to add to the dictionary
    return: updated dict_vis_objects
    """
    if tech_id not in dict_vis_objects:
        dict_vis_objects[tech_id] = []

    if isinstance(vis_obj, list):
        dict_vis_objects[tech_id].extend(deepcopy(vis_obj))
    else:
        dict_vis_objects[tech_id].append(deepcopy(vis_obj))

    return dict_vis_objects


def update_technique_administration_file(file_data_sources, file_tech_admin):
    """
    Update the visibility scores in the provided technique administration file
    :param file_data_sources: file location of the data source admin. file
    :param file_tech_admin: file location of the tech. admin. file
    :return:
    """
    file_updated = False

    # first we generate the new visibility scores contained within a temporary tech. admin YAML 'file'
    new_visibility_scores = generate_technique_administration_file(file_data_sources, None, write_file=False, all_techniques=True)

    # we get the date to remove the single quotes from the date at the end of of this function's code
    today = new_visibility_scores['techniques'][0]['visibility'][0]['score_logbook'][0]['date']

    # next, we load the current visibility scores from the tech. admin file
    cur_visibility_scores, _, platform_tech_admin, domain_tech_admin = load_techniques(file_tech_admin)

    # last, we get the systems kv-pair from the data source file
    _, _, systems, _, domain = load_data_sources(file_data_sources)

    # if the tech admin. file has a platform not present in the DS admin. file we return
    if len(set(platform_tech_admin).difference(set(new_visibility_scores['platform']))) > 0:
        print('[!] The technique administration file\'s key-value pair \'platform\' has ATT&CK platform(s) that are not '
              'part of the data source administration \'systems\' key-value pair. This should be fixed before the '
              'visibility update can continue.')
        print('\n    Technique administration \'platform\' key-value pair:')
        for p in platform_tech_admin:
            print('      - ' + p)
        print('')
        _print_ds_systems(systems)
        print('\nVisibility update canceled.')

        return

    # if the tech admin. file has an applicable_to value not present in the DS admin. file we return
    app_ds = set([s['applicable_to'].lower() for s in systems])
    app_tech = {}  # applicable_to: {app_to: ..., tech_ids: ...} - we have app_to in here to preserve the casing when printing
    for tech_id, v in cur_visibility_scores.items():
        for vis in v['visibility']:
            for a in vis['applicable_to']:
                a_low = a.lower()
                if a_low != 'all':
                    if a_low not in app_tech:
                        app_tech[a_low] = {}
                        app_tech[a_low]['app_to'] = a
                        app_tech[a_low]['tech_id'] = []
                    app_tech[a_low]['tech_id'].append(tech_id)

    # if the tech admin. file has another domain than the DS admin file has we return
    if domain != domain_tech_admin:
        print('[!] The technique administration file has another value for \'domain\' than the value for \'domain\' in '
              'the data source administration file. This should be fixed before the visibility update can continue.')
        print('\nVisibility update canceled.')

        return

    if len(set(app_tech).difference(app_ds)) > 0:
        print('[!] The technique administration file has visibility objects with \'applicable_to\' values that are not '
              'present in the data source administration \'systems\' key-value pair. This should be fixed before the '
              'visibility update can continue.')
        print('\n    Technique administration \'applicable_to\' values used within visibility objects:')
        for k, v in app_tech.items():
            print('      * applicable_to: ' + v['app_to'])
            print('        Used in technique(s): ' + ', '.join(v['tech_id']) + '\n')
        print('')
        _print_ds_systems(systems)
        print('\nVisibility update canceled.')

        return

    # we did not return, so init and start the upgrade :-)
    _yaml = init_yaml()
    with open(file_tech_admin) as fd:
        yaml_file_tech_admin_updated = _yaml.load(fd)

    # set the comment
    comment = ''
    if ask_yes_no('\nDo you want to fill in the visibility comment for the added and/or updated scores?'):
        comment = input(' >>   Comment: ')
        print('')

    # Set the comment for all new visibility scores. We will also be needing this later in the code to update
    # the scores of already present techniques. Therefore, we will add the comment already to every visibility object
    if comment != '':
        x = 0
        for new_tech in new_visibility_scores['techniques']:
            for visibility_obj in new_tech['visibility']:
                visibility_obj['score_logbook'][0]['comment'] = comment
        x += 1

    # check if the DS admin. file has an ATT&CK platform (part of systems) not part of the tech admin. file.
    # If yes, add this platform the the tech admin. file's 'platform' kv pair
    ds_platforms_not_in_tech = set(new_visibility_scores['platform']).difference(set(platform_tech_admin))
    if len(ds_platforms_not_in_tech) > 0:
        print('As part of the \'systems\' key-value pair, the data source administration file has ATT&CK platform(s) '
              'that are not part of the technique administration file. Therefore, the following platform(s) will be added '
              'to the \'platform\' key-value par as part of the technique administration file:')
        for p in ds_platforms_not_in_tech:
            print(' - ' + p)

        yaml_file_tech_admin_updated['platform'].extend(ds_platforms_not_in_tech)
        file_updated = True
        input('\n' + TXT_ANY_KEY_TO_CONTINUE)
        print('\n')

    # check if we have tech IDs for which we now have visibility, but which were not yet part of the tech. admin file
    cur_tech_ids = set(cur_visibility_scores.keys())
    new_tech_ids = set()

    del_unnecesary_all_tech_ids = set()  # resulted from 'all_techniques=True)', which we do need to call in this way
    # because we also want to update visibilty scores for which the score has become 0 (e.g. due to a removal of a data source)
    tech_idx = 0
    for tech in new_visibility_scores['techniques']:
        tech_id = tech['technique_id']
        score = False

        for vis_obj in tech['visibility']:
            if vis_obj['score_logbook'][0]['score'] > 0:
                score = True
                break
            elif tech_id not in cur_tech_ids:
                del_unnecesary_all_tech_ids.add(tech_idx)
        if score:
            new_tech_ids.add(tech_id)

        tech_idx += 1
    tech_ids_new = new_tech_ids.difference(cur_tech_ids)

    # remove techniques which came from 'all_techniques=True)', but that are not present as a technqiue in the current/outdated tech file
    for idx in sorted(del_unnecesary_all_tech_ids, reverse=True):
        del new_visibility_scores['techniques'][idx]

    # Add the new tech. to the ruamel instance: 'yaml_file_tech_admin'
    if len(tech_ids_new) > 0:
        file_updated = True
        x = 0
        for new_tech in new_visibility_scores['techniques']:
            if new_tech['technique_id'] in tech_ids_new:
                yaml_file_tech_admin_updated['techniques'].append(new_tech)
            x += 1

        print('The following new technique IDs will be added to the technique administration file with a visibility '
              'score derived from the nr. of available data sources:')
        print_tech_ids_list = [' ']
        x = 0
        for tech_id in sorted(tech_ids_new):
            if not len(print_tech_ids_list[x]) + len(tech_id) + 2 <= 80:
                x += 1
                print_tech_ids_list.append(' ')
            print_tech_ids_list[x] += tech_id + ", "
        print_tech_ids_list[x] = print_tech_ids_list[x][:-2]
        print('\n'.join(print_tech_ids_list))

    input('\n' + TXT_ANY_KEY_TO_CONTINUE)
    print('\n')

    # Remove techniques which we no longer need
    new_visibility_scores['techniques'] = [tech for tech in new_visibility_scores['techniques']
                                           if tech['technique_id'] not in tech_ids_new]

    # Update visibility objects for which we have
    #  - A match on the applicable_to value(s) between the old and new visibility object
    #  - A different visibility score (otherwise there is no need to update)
    #    (update = adding a new score logbook entry)
    print('We will now start with updating techniques\' visibility scores for which we have an EXACT match on \'applicable_to\' values.')
    input('\n' + TXT_ANY_KEY_TO_CONTINUE)
    print('\n')

    new_vis_objects = {}  # {tech_id: [visibility_obj]}

    new_visibility_scores_updated = deepcopy(new_visibility_scores)
    cur_visibility_scores_updated = deepcopy(cur_visibility_scores)

    answer_yes_to_all_auto_gen_false = False
    answer_yes_to_all_auto_gen_true = False
    answer_no_to_all_auto_gen_false = False
    answer_no_to_all_auto_gen_true = False
    we_have_updated_scores = False

    total_tech_ids = len(new_visibility_scores['techniques'])
    tech_ids_to_delete = set()
    tech_idxs_to_delete = set()
    idx_tech_id = 0
    for new_tech in new_visibility_scores['techniques']:
        tech_id = new_tech['technique_id']
        tech_name = new_tech['technique_name']

        if tech_id in cur_visibility_scores:
            idx_new_vis_obj = 0
            set_new_vis_obj_del = set()
            set_old_vis_obj_del = set()

            for new_vis_obj in new_tech['visibility']:
                idx_old_vis_obj = 0

                for old_vis_obj in cur_visibility_scores[tech_id]['visibility']:
                    # we have a MATCH on the applicable_to value between the old and new visibility object
                    if set(new_vis_obj['applicable_to']) == set(old_vis_obj['applicable_to']):

                        # we can ignore the update if the score stays the same
                        if new_vis_obj['score_logbook'][0]['score'] != get_latest_score(old_vis_obj):
                            answer = -1
                            old_score_auto_generated = get_latest_auto_generated(old_vis_obj)

                            # based on the answer provided by the user we can skip asking for user input, and hence printing the diff
                            if (not (old_score_auto_generated) and not (answer_yes_to_all_auto_gen_false) and not (answer_no_to_all_auto_gen_false)) \
                                    or (not (answer_yes_to_all_auto_gen_true) and not (answer_no_to_all_auto_gen_true)):
                                _print_progress_visibility_update(idx_tech_id + 1, total_tech_ids)
                                _print_visibility_object_diff(old_vis_obj, new_vis_obj, tech_id, tech_name)

                            if not (old_score_auto_generated) and not (answer_yes_to_all_auto_gen_false) and not (answer_no_to_all_auto_gen_false):
                                print('[!] The OLD score was set manually (auto_generated = false). But, The NEW score '
                                      'is derived from the nr. of available data sources.\n')
                                answer = ask_multiple_choice('Update the score?', ['Yes', 'No',
                                                                                   'Yes to ALL (where OLD score has auto_generated = false)',
                                                                                   'No to ALL (where OLD score has auto_generated = false)'])
                                answer_yes_to_all_auto_gen_false = True if answer == 3 else False
                                answer_no_to_all_auto_gen_false = True if answer == 4 else False
                            elif not (answer_yes_to_all_auto_gen_true) and not (answer_no_to_all_auto_gen_true):
                                print('Both the OLD and NEW scores were derived from the nr. of available data sources '
                                      '(auto_generated = true).\n')
                                answer = ask_multiple_choice('Update the score?', ['Yes', 'No',
                                                                                   'Yes to ALL (where OLD score has auto_generated = true)',
                                                                                   'No to ALL (where OLD score has auto_generated = true)'])
                                answer_yes_to_all_auto_gen_true = True if answer == 3 else False
                                answer_no_to_all_auto_gen_true = True if answer == 4 else False

                            # update the score / add a new score logbook entry
                            if (old_score_auto_generated and answer_yes_to_all_auto_gen_true) or \
                                    (not (old_score_auto_generated) and answer_yes_to_all_auto_gen_false) or answer == 1:
                                file_updated = True
                                we_have_updated_scores = True

                                old_vis_obj['score_logbook'].insert(0, new_vis_obj['score_logbook'][0])

                                upd_str = ' - Updated a visibility score in technique: {0:<10} (applicable to: {1})'
                                print(upd_str.format(tech_id, ', '.join(old_vis_obj['applicable_to'])))
                            else:
                                not_upd_str = ' - A visibility score in this technique was NOT updated: {0:<10} (applicable to: {1})'
                                print(not_upd_str.format(tech_id, ', '.join(old_vis_obj['applicable_to'])))

                        # add the updated score, or keep the old score
                        new_vis_objects = _add_visibility_object_to_dict(new_vis_objects, tech_id, old_vis_obj)

                        set_new_vis_obj_del.add(idx_new_vis_obj)
                        set_old_vis_obj_del.add(idx_old_vis_obj)

                    idx_old_vis_obj += 1
                idx_new_vis_obj += 1

            # delete visibility objects (old and new) which we processed (possibly including the technique itself)
            for idx in sorted(set_new_vis_obj_del, reverse=True):
                del new_visibility_scores_updated['techniques'][idx_tech_id]['visibility'][idx]

            if len(new_visibility_scores_updated['techniques'][idx_tech_id]['visibility']) == 0:
                tech_idxs_to_delete.add(idx_tech_id)

            for idx in sorted(set_old_vis_obj_del, reverse=True):
                del cur_visibility_scores_updated[tech_id]['visibility'][idx]

            if len(cur_visibility_scores_updated[tech_id]['visibility']) == 0:
                tech_ids_to_delete.add(tech_id)

        idx_tech_id += 1

    # delete techniques which no longer have any visibility objects
    for idx in sorted(tech_idxs_to_delete, reverse=True):
        del new_visibility_scores_updated['techniques'][idx]
    for tech_id in tech_ids_to_delete:
        del cur_visibility_scores_updated[tech_id]

    if not (we_have_updated_scores):
        print(' - No visibility scores were found eligible for an update, or you rejected all eligible updates.')

    # Update visibility objects for which we have
    #  - NO match on the applicable_to value(s) between the old and new visibility object
    #    (update = adding new or replacing existing objects)
    print('\nWe will now start with updating techniques\' visibility scores for which we have NO match on \'applicable_to\' values.')
    input('\n' + TXT_ANY_KEY_TO_CONTINUE)
    print('\n')

    answer_yes_to_all_auto_gen_false = False
    answer_yes_to_all_auto_gen_true = False
    answer_no_to_all_auto_gen_false = False
    answer_no_to_all_auto_gen_true = False
    we_have_updated_scores = False

    total_tech_ids = len(new_visibility_scores_updated['techniques'])
    idx_tech_id = 0

    for new_tech in new_visibility_scores_updated['techniques']:
        tech_id = new_tech['technique_id']
        tech_name = new_tech['technique_name']

        if tech_id not in cur_visibility_scores_updated:
            # We can add this visibility object without asking the user, because it (and thus its applicable_to value)
            # was never part of the cur/old technique administration file. We are sure of that because visibility objects
            # for which we had an EXACT match were removed. In this particular case that resulted in the deletion of the
            # techniques itself (as it had zero visibility objects remaining)
            file_updated = True
            we_have_updated_scores = True

            new_vis_objects = _add_visibility_object_to_dict(new_vis_objects, tech_id, new_tech['visibility'])
            applicable_to = list(set(chain.from_iterable(map(lambda k: k['applicable_to'], new_tech['visibility']))))

            not_upd_str = ' - A new visibility object was added to technique: {0:<10} (applicable to: {1})'
            print(not_upd_str.format(tech_id, ', '.join(applicable_to)))
        else:
            answer = -1
            list_old_score_auto_generated = [get_latest_auto_generated(old_vis_obj)
                                             for old_vis_obj in cur_visibility_scores_updated[tech_id]['visibility']]
            old_score_auto_generated = True if True in list_old_score_auto_generated else False

            # based on the answer provided by the user we can skip asking for user input, and hence printing the diff
            if (not (old_score_auto_generated) and not (answer_yes_to_all_auto_gen_false) and not (answer_no_to_all_auto_gen_false)) \
                    or (not (answer_yes_to_all_auto_gen_true) and not (answer_no_to_all_auto_gen_true)):
                _print_progress_visibility_update(idx_tech_id + 1, total_tech_ids)
                _print_tech_visibility_object_diff(cur_visibility_scores_updated[tech_id], new_tech, tech_id, tech_name)

            if not (old_score_auto_generated) and not (answer_yes_to_all_auto_gen_false) and not (answer_no_to_all_auto_gen_false):
                print('[!] At least one OLD score was set manually (auto_generated = false). '
                      'But, The NEW score(s) are derived from the nr. of available data sources.\n')
                answer = ask_multiple_choice('Replace the OLD the visibility objects(s)?', ['Yes', 'No',
                                                                                            'Yes to ALL (where at least one OLD score has auto_generated = false)',
                                                                                            'No to ALL (where at least one OLD score has auto_generated = false)'])
                answer_yes_to_all_auto_gen_false = True if answer == 3 else False
                answer_no_to_all_auto_gen_false = True if answer == 4 else False
            elif not (answer_yes_to_all_auto_gen_true) and not (answer_no_to_all_auto_gen_true):
                print('Both the OLD and NEW scores were derived from the nr. of available data sources '
                      '(auto_generated = true).\n')
                answer = ask_multiple_choice('Replace the OLD visibility object(s)?', ['Yes', 'No',
                                                                                       'Yes to ALL (where OLD score has auto_generated = true)',
                                                                                       'No to ALL (where OLD score has auto_generated = true)'])
                answer_yes_to_all_auto_gen_true = True if answer == 3 else False
                answer_no_to_all_auto_gen_true = True if answer == 4 else False

            # replace the visibility objects or keep the existing ones
            if (old_score_auto_generated and answer_yes_to_all_auto_gen_true) or \
                    (not (old_score_auto_generated) and answer_yes_to_all_auto_gen_false) or answer == 1:
                file_updated = True
                we_have_updated_scores = True

                new_vis_objects = _add_visibility_object_to_dict(new_vis_objects, tech_id, new_tech['visibility'])
                applicable_to = list(set(chain.from_iterable(map(lambda k: k['applicable_to'], new_tech['visibility']))))

                upd_str = ' - Replaced a visibility score in technique: {0:<10} (applicable to: {1})'
                print(upd_str.format(tech_id, ', '.join(applicable_to)))
            else:
                new_vis_objects = _add_visibility_object_to_dict(new_vis_objects, tech_id, cur_visibility_scores_updated[tech_id]['visibility'])
                applicable_to = list(set(chain.from_iterable(
                    map(lambda k: k['applicable_to'], cur_visibility_scores_updated[tech_id]['visibility']))))

                not_upd_str = ' - A visibility score in this technique was NOT updated: {0:<10} (applicable to: {1})'
                print(not_upd_str.format(tech_id, ', '.join(applicable_to)))

        idx_tech_id += 1

    # Update visibility objects in the technique administration file that will be written to disk
    idx_tech = 0
    for tech in yaml_file_tech_admin_updated['techniques']:
        tech_id = tech['technique_id']
        if tech_id not in tech_ids_new and tech_id in new_vis_objects:
            yaml_file_tech_admin_updated['techniques'][idx_tech]['visibility'] = new_vis_objects[tech_id]
        idx_tech += 1

    # create backup of the current tech. admin YAML file
    if file_updated:
        print('')
        backup_file(file_tech_admin)

        yaml_file_tech_admin_updated = fix_date_and_remove_null(yaml_file_tech_admin_updated, today, input_type='ruamel')

        with open(file_tech_admin, 'w') as fd:
            fd.writelines(yaml_file_tech_admin_updated)
        print('File written:   ' + file_tech_admin)
    else:
        print('No visibility scores have been updated.')

# pylint: disable=redefined-outer-name


def generate_technique_administration_file(filename, output_filename, output_overwrite, write_file=True, all_techniques=False):
    """
    Generate a technique administration file based on the data source administration YAML file
    :param filename: the filename of the YAML file containing the data sources administration
    :param output_filename: the output filename defined by the user
    :param output_overwrite: boolean flag indicating whether we're in overwrite mode
    :param write_file: by default the file is written to disk
    :param all_techniques: include all ATT&CK techniques in the generated YAML file that are applicable to the
    platform(s) specified in the data source YAML file
    :return:
    """
    my_ds, name, systems, exceptions, domain = load_data_sources(filename)

    techniques = load_attack_data(DATA_TYPE_STIX_ALL_TECH_ENTERPRISE if domain ==
                                  'enterprise-attack' else DATA_TYPE_STIX_ALL_TECH_ICS if domain == 'ics-attack' else DATA_TYPE_STIX_ALL_TECH_MOBILE)
    yaml_platform = list(set(chain.from_iterable(map(lambda k: k['platform'], systems))))
    all_applicable_to_values = set([s['applicable_to'] for s in systems])

    yaml_file = dict()
    yaml_file['version'] = FILE_TYPE_TECHNIQUE_ADMINISTRATION_VERSION
    yaml_file['file_type'] = FILE_TYPE_TECHNIQUE_ADMINISTRATION
    yaml_file['name'] = name
    yaml_file['domain'] = domain
    yaml_file['platform'] = yaml_platform
    yaml_file['techniques'] = []
    today = dt.now()

    # Score visibility based on the number of available data sources and the exceptions
    for t in techniques:
        mitre_platforms = t.get('x_mitre_platforms', [])
        tech_id = t['technique_id']
        tech = None
        visibility_obj_count = 0

        if tech_id not in list(map(lambda x: x.upper(), exceptions)):
            # calculate visibility score per system
            for system in systems:
                ds_score = -1
                platform_match = False
                # the system is relevant for this technique due to a match in ATT&CK platform
                if len(set(system['platform']).intersection(set(mitre_platforms))) > 0:
                    platform_match = True
                    applicable_data_sources = get_applicable_data_sources_platform(system['platform'], domain)
                    applicable_dettect_data_sources = get_applicable_dettect_data_sources_platform(system['platform'], domain)
                    total_ds_count = _count_applicable_data_sources(t, applicable_data_sources, applicable_dettect_data_sources)

                    if total_ds_count > 0:  # the system's platform has data source applicable to this technique
                        ds_count = 0
                        for ds in t['data_components']:
                            # the ATT&CK data source is applicable to this system and available
                            if ds in applicable_data_sources and ds in my_ds.keys() and _system_in_data_source_details_object(my_ds[ds], system):
                                ds_count += 1

                        for cdc in t['dettect_data_sources']:
                            if cdc in applicable_dettect_data_sources and cdc in my_ds.keys() and _system_in_data_source_details_object(my_ds[cdc], system):
                                ds_count += 1

                        if ds_count > 0:
                            result = (float(ds_count) / float(total_ds_count)) * 100
                            ds_score = 1 if result <= 49 else 2 if result <= 74 else 3 if result <= 99 else 4
                        else:
                            ds_score = 0  # none of the applicable data sources are available for this system
                    else:
                        # the technique is applicable to this system (and thus its platform(s)),
                        # but none of the technique's listed data source are applicable for its platform(s), or the technique has not data sources
                        ds_score = -1

                # Do not add technique if score == 0 or the user want every technique to be added
                if ds_score > 0 or (all_techniques and platform_match):
                    # the ATT&CK technique is not yet part of the YAML file
                    if visibility_obj_count == 0:
                        tech = deepcopy(YAML_OBJ_TECHNIQUE)
                        tech['technique_id'] = tech_id
                        tech['technique_name'] = t['name']

                    # score can be -1 due to all_techniques
                    ds_score = 0 if ds_score == -1 else ds_score

                    # check if we have already have a visibility object with this exact same score
                    same_score = False
                    if visibility_obj_count > 0:
                        for vis_obj in tech['visibility']:
                            if vis_obj['score_logbook'][0]['score'] == ds_score:
                                vis_obj['applicable_to'].append(system['applicable_to'])
                                same_score = True
                                break
                    if not same_score:
                        tech['visibility'].append(deepcopy(YAML_OBJ_VISIBILITY))
                        tech['visibility'][visibility_obj_count]['score_logbook'][0]['score'] = ds_score
                        tech['visibility'][visibility_obj_count]['score_logbook'][0]['date'] = today
                        tech['visibility'][visibility_obj_count]['applicable_to'] = [system['applicable_to']]
                        visibility_obj_count += 1
            if tech:
                # check if we have an applicable to value that can be replaced by the value 'all'
                for vis_obj in tech['visibility']:
                    if all_applicable_to_values == set(vis_obj['applicable_to']) and not len(all_applicable_to_values) == 1:
                        vis_obj['applicable_to'] = ['all']
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
            output_filename = 'techniques-administration-' + normalize_name_to_filename(name)
        elif output_filename.endswith('.yaml'):
            output_filename = output_filename.replace('.yaml', '')
        
        if os.sep not in output_filename:
            output_filename = 'output/%s' % output_filename

        if not output_overwrite:
            output_filename = get_non_existing_filename(output_filename, 'yaml')
        else:
            output_filename = use_existing_filename(output_filename, 'yaml')

        try:
            with open(output_filename, 'w') as f:
                f.writelines(yaml_file_lines)
            print("File written:   " + output_filename)
        except Exception as e:
            print('[!] Error while writing yaml file: %s' % str(e))
    else:
        return yaml_file
