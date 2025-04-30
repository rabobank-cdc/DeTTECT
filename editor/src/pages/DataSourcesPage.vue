<template>
    <div>
        <div v-if="doc != null" class="back-to-top">
            <label @click="navigateToTop" class="cursor-pointer" title="Back to top">
                <icons icon="arrow-up"></icons>
            </label>
        </div>
        <div class="row" id="pageTop">
            <div class="col">
                <div class="card card-card">
                    <div class="row cursor-pointer" @click="hideFileDetails(!file_details_visible)">
                        <div class="col-md-7">
                            <div class="card-header">
                                <h2 class="card-title"><i class="tim-icons icon-coins"></i> Data Sources{{ showFileName }}</h2>
                            </div>
                        </div>
                        <div class="col mt-3 mb-2 text-right">
                            <label v-if="fileChanged" class="pl-2">
                                <icons icon="text-balloon"></icons>
                                You have unsaved changes. You may want to save the file to preserve your changes.</label
                            >
                        </div>
                        <div v-if="doc != null && !file_details_visible" class="top-save-button">
                            <button
                                type="button"
                                class="btn"
                                @click="
                                    downloadYaml('data_sources', 'data_source_name');
                                    $event.stopPropagation();
                                "
                            >
                                <icons icon="save"></icons>
                                &nbsp;Save
                            </button>
                        </div>
                        <div class="col-md-0 mt-3 mr-4 text-right" :title="file_details_visible ? 'Collapse File Details' : 'Expand File Details'">
                            <icons :icon="file_details_visible ? 'collapse' : 'expand'"></icons>
                        </div>
                    </div>
                    <b-collapse id="collapse-ds" v-model="file_details_visible">
                        <div class="card-body">
                            <div class="row">
                                <div class="col">
                                    <button type="button" class="btn mr-md-3" @click="askNewFile">
                                        <icons icon="file-empty"></icons>
                                        &nbsp;New file
                                    </button>
                                    <label class="custom-file-upload">
                                        <icons icon="file"></icons>
                                        &nbsp;Select YAML file
                                        <file-reader @load="readFile($event)" :setFileNameFn="setFileName" :id="'dsFileReader'"></file-reader>
                                    </label>
                                </div>
                            </div>
                            <div v-if="doc != null" class="row pt-md-2">
                                <div class="col">
                                    <file-details
                                        :filename="filename"
                                        :doc="doc"
                                        :platforms="getPlatforms(doc.domain)"
                                        :platformConversion="getPlatformConversion(doc.domain)"
                                        systemsOrPlatforms="systems"
                                        fileType="datasources"
                                    ></file-details>
                                </div>
                            </div>
                            <div v-if="doc != null" class="row pt-md-2">
                                <div class="col card-text">
                                    <button type="button" class="btn" @click="downloadYaml('data_sources', 'data_source_name')">
                                        <icons icon="save"></icons>
                                        &nbsp;Save YAML file
                                    </button>
                                </div>
                            </div>
                        </div>
                    </b-collapse>
                </div>
            </div>
        </div>
        <div v-if="doc != null" class="row">
            <div class="col">
                <card type="card">
                    <div class="row">
                        <div class="col">
                            <p>
                                <button
                                    type="button"
                                    class="btn btn-secondary"
                                    @click="addItem('data_sources', 'data_source_name', emptyDataSourceObject)"
                                >
                                    <icons icon="plus"></icons>
                                    &nbsp;Add data source
                                </button>
                                &nbsp;
                                <button type="button" class="btn btn-secondary" @click="addAllDataSources()">
                                    <icons icon="plus-filled"></icons>
                                    &nbsp;Add all data sources
                                </button>
                            </p>
                        </div>
                    </div>
                    <div class="row mt-md-2">
                        <div class="col">
                            <base-input
                                v-model="filters.filter.value"
                                placeholder="filter"
                                @keyup="countDataSources()"
                                @change="countDataSources()"
                            />
                            <div class="search-summary">Showing {{ data_sources_count }} of {{ doc.data_sources.length }} data sources</div>
                            <v-table
                                :data="doc.data_sources"
                                @selectionChanged="selectDataSource($event)"
                                selectedClass="table-selected-custom"
                                :filters="filters"
                                class="table-custom"
                                ref="data_table"
                            >
                                <thead slot="head">
                                    <v-th sortKey="data_source_name" defaultSort="asc" width="350">Name</v-th>
                                    <v-th :sortKey="joinedApplicableTo" width="500">Applicable to</v-th>
                                    <th></th>
                                </thead>
                                <tbody slot="body" slot-scope="{ displayData }">
                                    <v-tr v-for="(row, i) in displayData" :key="row.data_source_name" :row="row" ref="data_table_rows">
                                        <td>{{ row.data_source_name }}</td>
                                        <td>
                                            {{ joinedApplicableTo(row) }}
                                        </td>
                                        <td>
                                            <i
                                                class="tim-icons icon-trash-simple cursor-pointer"
                                                :idx="i"
                                                :data_source_name="row.data_source_name"
                                                @click="deleteDataSource($event)"
                                            />
                                        </td>
                                    </v-tr>
                                </tbody>
                            </v-table>
                        </div>
                    </div>
                </card>
            </div>
            <div class="col">
                <card type="card">
                    <data-source-detail
                        v-if="getSelectedItem() != null"
                        :dataSource="getSelectedItem()"
                        :allDataSources="doc.data_sources"
                        :allSystems="doc.systems"
                        :dqHelpText="dqHelpText"
                        :dsHelpText="dsHelpText"
                        :prevDataSourceQuality="prevDataSourceQuality"
                        :navigateItem="navigateItem"
                        ref="detailComponent"
                        :domain="doc.domain"
                    ></data-source-detail>
                </card>
            </div>
        </div>
    </div>
</template>
<script>
import DataSourceDetail from './DataSourceDetail';
import Icons from '@/components/Icons';
import jsyaml from 'js-yaml';
import moment from 'moment';
import constants from '@/constants';
import { pageMixin } from '../mixins/PageMixins.js';
import { navigateMixins } from '../mixins/NavigateMixins.js';
import { notificationMixin } from '../mixins/NotificationMixins.js';
import dataSources from '@/data/data_sources';
import customDataSources from '@/data/dettect_data_sources';
import dataSourcePlatforms from '@/data/data_source_platforms';
import _ from 'lodash';

export default {
    name: 'data-sources-page',
    data() {
        return {
            filters: {
                filter: {
                    value: '',
                    keys: ['data_source_name']
                }
            },
            prevDataSourceQuality: {},
            data_columns: ['data_source_name', 'date_registered', 'products'],
            dqFileToRender: 'https://raw.githubusercontent.com/wiki/rabobank-cdc/DeTTECT/Data-quality-scoring.md',
            dqHelpText: null,
            dsFileToRender: 'https://raw.githubusercontent.com/wiki/rabobank-cdc/DeTTECT/YAML-administration-data-sources.md',
            dsHelpText: null,
            emptyDataSourceObject: constants.YAML_OBJ_DATA_SOURCES,
            selectedPlatforms: Array,
            data_sources_count: 0
        };
    },
    computed: {
        getDataSources() {
            return dataSources[this.dataSourcePlatformsSelectorATTACK];
        },
        dataSourcePlatformsSelectorATTACK() {
            return this.doc.domain == 'enterprise-attack' ? 'ATT&CK-Enterprise' : this.doc.domain == 'ics-attack' ? 'ATT&CK-ICS' : 'ATT&CK-Mobile';
        },
        dataSourcePlatformsSelectorDETTECT() {
            return this.doc.domain == 'enterprise-attack' ? 'DeTT&CT-Enterprise' : this.doc.domain == 'ics-attack' ? 'DeTT&CT-ICS' : 'DeTT&CT-Mobile';
        }
    },
    mixins: [pageMixin, navigateMixins, notificationMixin],
    components: {
        DataSourceDetail,
        Icons
    },
    created: function () {
        this.preloadMarkDown();
    },
    methods: {
        readFile(event) {
            // Loads and checks the file content
            try {
                let yaml_input = jsyaml.load(event.result);

                if (yaml_input['file_type'] == 'data-source-administration') {
                    if (yaml_input['version'] != constants.YAML_DATASOURCES_VERSION) {
                        this.notifyDanger('Invalid file version', 'The version of the YAML file is not supported by this version of the Editor.');
                    } else {
                        ///////////////////////////////////////////////
                        // Health checks before assignment to this.doc:
                        ///////////////////////////////////////////////

                        // Check domain is filled, default enterprise-attack:
                        if (yaml_input.domain == undefined || yaml_input.domain == null) {
                            yaml_input.domain = 'enterprise-attack';
                        }

                        // Check domain is valid:
                        if (!constants.DETTECT_DOMAIN_SUPPORT.includes(yaml_input.domain)) {
                            this.notifyDanger(
                                'Invalid domain',
                                'Invalid value for the domain was found in the YAML file and therefore set to enterprise-attack.'
                            );
                            yaml_input.domain = 'enterprise-attack';
                        }

                        // Fix missing or empty systems field:
                        if (yaml_input.systems == undefined || yaml_input.systems == null) {
                            yaml_input.systems = _.cloneDeep(constants.YAML_OBJ_NEW_DATA_SOURCES_FILE['systems']);
                        } else {
                            // Fix missing or empty applicable_to and platform fields:
                            for (let i = 0; i < yaml_input.systems.length; i++) {
                                if (yaml_input.systems[i].applicable_to == undefined || yaml_input.systems[i].applicable_to == null) {
                                    yaml_input.systems[i].applicable_to = 'empty' + i;
                                }
                                if (yaml_input.systems[i].platform == undefined || yaml_input.systems[i].platform == null) {
                                    yaml_input.systems[i].platform = [];
                                }

                                // Fix a single platform string to list
                                if (typeof yaml_input.systems[i].platform == 'string') {
                                    yaml_input.systems[i].platform = [yaml_input.systems[i].platform];
                                }

                                let valid_platforms = [];
                                for (let j = 0; j < yaml_input.systems[i].platform.length; j++) {
                                    // Only use valid platform values (in right casing):
                                    if (this.getPlatforms(yaml_input.domain).indexOf(yaml_input.systems[i].platform[j]) < 0) {
                                        let p = yaml_input.systems[i].platform[j].toLowerCase();
                                        if (Object.keys(this.getPlatformConversion(yaml_input.domain)).indexOf(p) >= 0) {
                                            valid_platforms.push(this.getPlatformConversion(yaml_input.domain)[p]);
                                        } else {
                                            this.notifyDanger(
                                                'Invalid value',
                                                'Invalid value for platform was found in the YAML file and was removed: ' +
                                                    yaml_input.systems[i].platform[j]
                                            );
                                        }
                                    } else {
                                        valid_platforms.push(yaml_input.systems[i].platform[j]);
                                    }
                                }
                                yaml_input.systems[i].platform = valid_platforms;
                            }
                        }

                        // Check for duplicate data sources:
                        let data_sources_in_file = new Array();
                        for (let i = 0; i < yaml_input.data_sources.length; i++) {
                            data_sources_in_file.push(yaml_input.data_sources[i].data_source_name);
                        }
                        let findDuplicates = (arr) => arr.filter((item, index) => arr.indexOf(item) != index);
                        let duplicates = findDuplicates(data_sources_in_file);
                        if (duplicates.length > 0) {
                            this.notifyDanger('Duplicates', 'Duplicate data sources are present in the file: ' + duplicates.join(', '));
                            return;
                        }

                        // Fix missing/invalid fields for data_source items: products, available_for_data_analytics, data_quality
                        for (let i = 0; i < yaml_input.data_sources.length; i++) {
                            for (let j = 0; j < yaml_input.data_sources[i].data_source.length; j++) {
                                if (yaml_input.data_sources[i].data_source[j].products == undefined) {
                                    yaml_input.data_sources[i].data_source[j].products = [];
                                }

                                if (yaml_input.data_sources[i].data_source[j].available_for_data_analytics == undefined) {
                                    yaml_input.data_sources[i].data_source[j].available_for_data_analytics = false;
                                }

                                if (typeof yaml_input.data_sources[i].data_source[j].available_for_data_analytics != 'boolean') {
                                    yaml_input.data_sources[i].data_source[j].available_for_data_analytics = false;
                                }

                                if (yaml_input.data_sources[i].data_source[j].data_quality == undefined) {
                                    yaml_input.data_sources[i].data_source[j].data_quality = {
                                        device_completeness: 0,
                                        data_field_completeness: 0,
                                        timeliness: 0,
                                        consistency: 0,
                                        retention: 0
                                    };
                                }

                                yaml_input.data_sources[i].data_source[j].data_quality.device_completeness = this.fixSDataQualityScore(
                                    yaml_input.data_sources[i].data_source[j].data_quality.device_completeness
                                );
                                yaml_input.data_sources[i].data_source[j].data_quality.data_field_completeness = this.fixSDataQualityScore(
                                    yaml_input.data_sources[i].data_source[j].data_quality.data_field_completeness
                                );
                                yaml_input.data_sources[i].data_source[j].data_quality.timeliness = this.fixSDataQualityScore(
                                    yaml_input.data_sources[i].data_source[j].data_quality.timeliness
                                );
                                yaml_input.data_sources[i].data_source[j].data_quality.consistency = this.fixSDataQualityScore(
                                    yaml_input.data_sources[i].data_source[j].data_quality.consistency
                                );
                                yaml_input.data_sources[i].data_source[j].data_quality.retention = this.fixSDataQualityScore(
                                    yaml_input.data_sources[i].data_source[j].data_quality.retention
                                );
                            }
                        }

                        // For the following fields it's not a problem is they are missing because the GUI solves/handles this properly:
                        // - date_registered. Also invalid values are handled correctly.
                        // - date_connected. Also invalid values are handled correctly.
                        // - comment

                        this.doc = yaml_input;
                        this.filename = this.selected_filename;
                        this.filters.filter.value = '';
                        while (this.selectedRow != null && this.selectedRow.length > 0) {
                            this.selectedRow.pop();
                        }

                        // Fix the date to be in the correct date format (YYYY-MM-DD):
                        for (let i = 0; i < this.doc.data_sources.length; i++) {
                            for (let j = 0; j < this.doc.data_sources[i].data_source.length; j++) {
                                let dr = this.doc.data_sources[i].data_source[j]['date_registered'];
                                let dv = this.doc.data_sources[i].data_source[j]['date_connected'];
                                if (dr != null) {
                                    this.doc.data_sources[i].data_source[j]['date_registered'] = moment(dr, 'DD/MM/YYYY').format('YYYY-MM-DD');
                                }
                                if (dv != null) {
                                    this.doc.data_sources[i].data_source[j]['date_connected'] = moment(dv, 'DD/MM/YYYY').format('YYYY-MM-DD');
                                }
                            }
                        }

                        this.prevDataSourceQuality = {};
                        this.fileChanged = false;
                        this.setWatch();

                        // Reset the file reader for Chrome, so that it will be possible to load the same file again:
                        document.getElementById('dsFileReader').value = null;
                    }
                } else {
                    this.notifyInvalidFileType(this.selected_filename);
                }
            } catch (e) {
                this.notifyInvalidFileType(this.selected_filename);
            }
        },
        newFile() {
            this.filename = 'data-sources-new.yaml';
            this.selected_filename = 'data-sources-new.yaml';
            this.doc = _.cloneDeep(constants.YAML_OBJ_NEW_DATA_SOURCES_FILE);
            this.selectedRow.pop();
            this.deletedRows = [];
            this.fileChanged = false;
            this.setWatch();
        },
        fixSDataQualityScore(v) {
            if (v == undefined) {
                return 0;
            } else if (v < 0) {
                return 0;
            } else if (v > 5) {
                return 5;
            } else if (typeof v == 'number') {
                return v;
            } else {
                return 0;
            }
        },
        cleanupBeforeDownload() {
            // empty function. must be here to make downloadYaml() work for every page
        },
        convertBeforeDownload(newDoc) {
            // Convert the date (which is a string in the GUI) to a real Date object in the YAML file
            for (let i = 0; i < newDoc.data_sources.length; i++) {
                for (let j = 0; j < newDoc.data_sources[i].data_source.length; j++) {
                    if (newDoc.data_sources[i].data_source[j]['date_registered'] != null) {
                        newDoc.data_sources[i].data_source[j]['date_registered'] = new Date(newDoc.data_sources[i].data_source[j]['date_registered']);
                    }
                    if (newDoc.data_sources[i].data_source[j]['date_connected'] != null) {
                        newDoc.data_sources[i].data_source[j]['date_connected'] = new Date(newDoc.data_sources[i].data_source[j]['date_connected']);
                    }
                }
            }
        },
        deleteDataSource(event) {
            this.deleteItem(event, 'data_sources', ['data_source_name'], 'Data source', this.recoverDeletedDataSource);
            this.countDataSources();
        },
        getSelectedPlatforms() {
            let selectedPlatforms = new Set();
            for (let i = 0; i < this.doc.systems.length; i++) {
                for (let j = 0; j < this.doc.systems[i].platform.length; j++) {
                    selectedPlatforms.add(this.doc.systems[i].platform[j]);
                }
            }
            this.selectedPlatforms = Array.from(selectedPlatforms);
        },
        addAllDataSources() {
            this.getSelectedPlatforms();
            // Add all data sources based on both data sources and DeTT&CT data sources and check if the platform of these
            // (DeTT&CT) data sources corresponds to the selected platforms within the systems key-value pair.
            let current_ds_in_file = [];
            for (let i = 0; i < this.doc.data_sources.length; i++) {
                current_ds_in_file.push(this.doc.data_sources[i].data_source_name);
            }

            for (let i = 0; i < this.selectedPlatforms.length; i++) {
                for (let j = 0; j < this.getDataSources.length; j++) {
                    if (
                        this.selectedPlatforms[i] == 'all' ||
                        dataSourcePlatforms[this.dataSourcePlatformsSelectorATTACK][this.selectedPlatforms[i]].includes(this.getDataSources[j])
                    ) {
                        if (!current_ds_in_file.includes(this.getDataSources[j])) {
                            let newrow = _.cloneDeep(this.emptyDataSourceObject);
                            newrow.data_source_name = this.getDataSources[j];
                            this.doc.data_sources.push(newrow);
                            current_ds_in_file.push(this.getDataSources[j]);
                        }
                    }
                }

                // DeTT&CT (custom) data sources are currently only for Enterprise ATT&CK:
                if (this.doc.domain == 'enterprise-attack') {
                    for (let j = 0; j < customDataSources.length; j++) {
                        if (
                            this.selectedPlatforms[i] == 'all' ||
                            dataSourcePlatforms[this.dataSourcePlatformsSelectorDETTECT][this.selectedPlatforms[i]].includes(customDataSources[j])
                        ) {
                            if (!current_ds_in_file.includes(customDataSources[j])) {
                                let newrow = _.cloneDeep(this.emptyDataSourceObject);
                                newrow.data_source_name = customDataSources[j];
                                this.doc.data_sources.push(newrow);
                                current_ds_in_file.push(customDataSources[j]);
                            }
                        }
                    }
                }
            }
            this.countDataSources();
        },
        recoverDeletedDataSource(data_source_name) {
            this.recoverDeletedItem('data_sources', data_source_name, this.doc.data_sources, ['data_source_name']);
        },
        preloadMarkDown() {
            // Preload the data quality help text from Github
            this.dqHelpText = 'Loading the help content...';
            this.$http.get(this.dqFileToRender).then(
                (response) => {
                    // remove links to other wiki pages
                    this.dqHelpText = response.body.replace(/\[(.+)\](\([#\w-]+\))/gm, '$1');
                },
                // eslint-disable-next-line no-unused-vars
                (response) => {
                    this.dqHelpText = 'An error occurred while loading the help content.';
                }
            );

            this.dsHelpText = 'Loading the help content...';
            this.$http.get(this.dsFileToRender).then(
                (response) => {
                    try {
                        this.dsHelpText = response.body.replace(/\[(.+)\](\([#\w-]+\))/gm, '$1'); // remove links to other wiki pages
                        this.dsHelpText = this.dsHelpText.match(/## Data source details object((.*|\n)*)/gim, '$1')[0];
                        this.dsHelpText = this.dsHelpText.replace(/^## Data source details object/gim, '');
                        this.dsHelpText = this.dsHelpText.replace(/^## .+((.*|\n)*)/gim, '');
                    } catch (e) {
                        this.dsHelpText = 'An error occurred while loading the help content.';
                    }
                },
                // eslint-disable-next-line no-unused-vars
                (response) => {
                    this.dsHelpText = 'An error occurred while loading the help content.';
                }
            );
        },
        notifyInvalidFileType(filename) {
            this.notifyDanger('Invalid YAML file type', "The file '" + filename + "' is not a valid data source administration file.");
        },
        hideFileDetails(state) {
            if (this.doc != null && this.$route.name == 'datasources' && !this.file_details_lock) {
                this.file_details_visible = state;
                this.changePageTitle();
            }
        },
        selectDataSource(event) {
            if (this.$refs.detailComponent != undefined) {
                this.$refs.detailComponent.closeAllCollapses();
            }
            this.selectItem(event);
            this.countDataSources();
        },
        joinedApplicableTo(row) {
            return row.data_source
                .map(function (row) {
                    return row.applicable_to;
                })
                .join(', ');
        },
        countDataSources() {
            if (this.$refs.data_table != undefined) {
                setTimeout(() => {
                    this.data_sources_count = this.$refs.data_table.$el.rows.length;
                }, 100);
            } else {
                this.data_sources_count = 0;
            }
        }
    },
    filters: {
        listToString: function (value) {
            if (Array.isArray(value)) {
                return value.join(', ');
            } else {
                return value;
            }
        }
    }
};
</script>

<style></style>
