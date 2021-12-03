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
                                <h2 class="card-title"><i class="tim-icons icon-zoom-split"></i> Techniques{{ showFileName }}</h2>
                            </div>
                        </div>
                        <div class="col mt-3 text-right">
                            <label v-if="fileChanged" class="pl-2">
                                <icons icon="text-balloon"></icons>
                                You have unsaved changes. You may want to save the file to preserve your changes.</label
                            >
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
                                        <file-reader @load="readFile($event)" :setFileNameFn="setFileName" :id="'techniqueFileReader'"></file-reader>
                                    </label>
                                </div>
                            </div>
                            <div v-if="doc != null" class="row pt-md-2">
                                <div class="col">
                                    <file-details
                                        :filename="filename"
                                        :doc="doc"
                                        :platforms="platforms"
                                        systemsOrPlatforms="platforms"
                                    ></file-details>
                                </div>
                            </div>
                            <div v-if="doc != null" class="row pt-md-2">
                                <div class="col card-text">
                                    <button type="button" class="btn" @click="downloadYaml('techniques', 'technique_id')">
                                        <icons icon="save"></icons>
                                        &nbsp;Save YAML file
                                    </button>
                                </div>
                                <div
                                    class="col-md-0 mt-3 mr-4 text-right cursor-pointer"
                                    @click="file_details_lock = !file_details_lock"
                                    :title="file_details_lock ? 'File Details: locked' : 'File Details: auto hide'"
                                >
                                    <icons :icon="file_details_lock ? 'lock' : 'unlock'"></icons>
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
                                <button type="button" class="btn btn-secondary" @click="addItem('techniques', 'technique_id', emptyTechObject)">
                                    <icons icon="plus"></icons>
                                    &nbsp;Add technique
                                </button>
                            </p>
                        </div>
                    </div>
                    <div class="row mt-md-2">
                        <div class="col">
                            <base-input v-model="filters.filter.value" placeholder="filter" />
                            <v-table
                                :data="doc.techniques"
                                @selectionChanged="selectTechnique($event)"
                                selectedClass="table-selected-custom"
                                :filters="filters"
                                class="table-custom"
                                ref="data_table"
                            >
                                <thead slot="head">
                                    <v-th sortKey="technique_id" defaultSort="asc" width="200">Technique ID</v-th>
                                    <v-th sortKey="technique_name" width="400">Name</v-th>
                                    <th></th>
                                </thead>
                                <tbody slot="body" slot-scope="{ displayData }">
                                    <v-tr v-for="(row, i) in displayData" :key="row.technique_id" :row="row" ref="data_table_rows">
                                        <td>{{ row.technique_id }}</td>
                                        <td>{{ row.technique_name }}</td>
                                        <td>
                                            <i
                                                class="tim-icons icon-trash-simple cursor-pointer"
                                                :idx="i"
                                                :technique_id="row.technique_id"
                                                @click="deleteTechnique($event)"
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
                    <techniques-detail
                        v-if="getSelectedItem() != null"
                        :technique="getSelectedItem()"
                        :allTechniques="doc.techniques"
                        :selectedPlatforms="doc.platform"
                        ref="detailComponent"
                        :navigateItem="navigateItem"
                    ></techniques-detail>
                </card>
            </div>
        </div>
    </div>
</template>

<script>
import TechniquesDetail from './TechniquesDetail';
import Icons from '@/components/Icons';
import jsyaml from 'js-yaml';
import moment from 'moment';
import constants from '@/constants';
import { pageMixin } from '../mixins/PageMixins.js';
import { navigateMixins } from '../mixins/NavigateMixins.js';
import { notificationMixin } from '../mixins/NotificationMixins.js';
import _ from 'lodash';

export default {
    name: 'techniques-page',
    data() {
        return {
            filters: {
                filter: {
                    value: '',
                    keys: ['technique_id', 'technique_name']
                }
            },
            data_columns: ['technique_id', 'technique_name'],
            emptyTechObject: constants.YAML_OBJ_TECHNIQUE
        };
    },
    mixins: [pageMixin, navigateMixins, notificationMixin],
    components: {
        TechniquesDetail,
        Icons
    },
    methods: {
        readFile(event) {
            // Loads and checks the file content
            try {
                let yaml_input = jsyaml.load(event.result);

                if (yaml_input['file_type'] == 'technique-administration') {
                    if (yaml_input['version'] != constants.YAML_TECHNIQUES_VERSION) {
                        this.notifyDanger('Invalid file version', 'The version of the YAML file is not supported by this version of the Editor.');
                    } else {
                        ///////////////////////////////////////////////
                        // Health checks before assignment to this.doc:
                        ///////////////////////////////////////////////

                        // Fix missing or empty platform:
                        if (yaml_input.platform == undefined || yaml_input.platform == null) {
                            yaml_input.platform = [];
                        }

                        // Fix a single platform string to list
                        if (typeof yaml_input.platform == 'string') {
                            yaml_input.platform = [yaml_input.platform];
                        }

                        // Only use valid platform values (in right casing):
                        let valid_platforms = [];
                        for (let i = 0; i < yaml_input.platform.length; i++) {
                            if (this.platforms.indexOf(yaml_input.platform[i]) < 0) {
                                let p = yaml_input.platform[i].toLowerCase();
                                if (Object.keys(constants.PLATFORM_CONVERSION).indexOf(p) >= 0) {
                                    valid_platforms.push(constants.PLATFORM_CONVERSION[p]);
                                } else {
                                    this.notifyDanger('Invalid value', 'Invalid value for platform was found in the YAML file and was removed.');
                                }
                            } else {
                                valid_platforms.push(yaml_input.platform[i]);
                            }
                        }
                        yaml_input.platform = valid_platforms;

                        // Fix missing/invalid fields:
                        for (let i = 0; i < yaml_input.techniques.length; i++) {
                            // Fix no detection node:
                            if (yaml_input.techniques[i].detection == undefined) {
                                yaml_input.techniques[i].detection = new Array(_.cloneDeep(constants.YAML_OBJ_TECHNIQUE_DETECTION));
                            } else if (!Array.isArray(yaml_input.techniques[i].detection)) {
                                // Put single detection item in list:
                                yaml_input.techniques[i].detection = new Array(yaml_input.techniques[i].detection);
                            }

                            // Fix no visibility node:
                            if (yaml_input.techniques[i].visibility == undefined) {
                                yaml_input.techniques[i].visibility = new Array(_.cloneDeep(constants.YAML_OBJ_TECHNIQUE_VISIBILITY));
                            } else if (!Array.isArray(yaml_input.techniques[i].visibility)) {
                                // Put single visibility item in list:
                                yaml_input.techniques[i].visibility = new Array(yaml_input.techniques[i].visibility);
                            }

                            // Check detection fields:
                            for (let x = 0; x < yaml_input.techniques[i].detection.length; x++) {
                                if (yaml_input.techniques[i].detection[x].applicable_to == undefined) {
                                    yaml_input.techniques[i].detection[x].applicable_to = ['all'];
                                }
                                if (yaml_input.techniques[i].detection[x].location == undefined) {
                                    yaml_input.techniques[i].detection[x].location = [];
                                }
                                let length_location = yaml_input.techniques[i].detection[x].location.length;
                                while (length_location--) {
                                    if (yaml_input.techniques[i].detection[x].location[length_location] == '') {
                                        yaml_input.techniques[i].detection[x].location.splice(length_location, 1);
                                    }
                                }
                                if (yaml_input.techniques[i].detection[x].comment == undefined) {
                                    yaml_input.techniques[i].detection[x].comment = '';
                                }
                                if (
                                    yaml_input.techniques[i].detection[x].score_logbook == undefined ||
                                    yaml_input.techniques[i].detection[x].score_logbook.length == 0
                                ) {
                                    yaml_input.techniques[i].detection[x].score_logbook = new Array(
                                        _.cloneDeep(constants.YAML_OBJ_SCORE_DETECTION_LOGBOOK)
                                    );
                                }

                                // Check score log book variables:
                                for (let j = 0; j < yaml_input.techniques[i].detection[x].score_logbook.length; j++) {
                                    if (yaml_input.techniques[i].detection[x].score_logbook[j].date == undefined) {
                                        yaml_input.techniques[i].detection[x].score_logbook[j].date = null;
                                    }
                                    if (yaml_input.techniques[i].detection[x].score_logbook[j].score == undefined) {
                                        yaml_input.techniques[i].detection[x].score_logbook[j].score = -1;
                                    } else {
                                        yaml_input.techniques[i].detection[x].score_logbook[j].score = this.fixSDetectionScore(
                                            yaml_input.techniques[i].detection[x].score_logbook[j].score
                                        );
                                    }
                                    if (yaml_input.techniques[i].detection[x].score_logbook[j].comment == undefined) {
                                        yaml_input.techniques[i].detection[x].score_logbook[j].comment = '';
                                    }
                                    if (yaml_input.techniques[i].detection[x].score_logbook[j].date != null) {
                                        yaml_input.techniques[i].detection[x].score_logbook[j].date = moment(
                                            yaml_input.techniques[i].detection[x].score_logbook[j].date,
                                            'DD/MM/YYYY'
                                        ).format('YYYY-MM-DD');
                                    }
                                }
                            }

                            // Check visibility fields:
                            for (let x = 0; x < yaml_input.techniques[i].visibility.length; x++) {
                                if (yaml_input.techniques[i].visibility[x].applicable_to == undefined) {
                                    yaml_input.techniques[i].visibility[x].applicable_to = ['all'];
                                }
                                if (yaml_input.techniques[i].visibility[x].comment == undefined) {
                                    yaml_input.techniques[i].visibility[x].comment = '';
                                }
                                if (
                                    yaml_input.techniques[i].visibility[x].score_logbook == undefined ||
                                    yaml_input.techniques[i].visibility[x].score_logbook.length == 0
                                ) {
                                    yaml_input.techniques[i].visibility[x].score_logbook = new Array(
                                        _.cloneDeep(constants.YAML_OBJ_SCORE_VISIBILITY_LOGBOOK)
                                    );
                                }

                                // Check score log book variables:
                                for (let j = 0; j < yaml_input.techniques[i].visibility[x].score_logbook.length; j++) {
                                    if (yaml_input.techniques[i].visibility[x].score_logbook[j].date == undefined) {
                                        yaml_input.techniques[i].visibility[x].score_logbook[j].date = null;
                                    }
                                    if (yaml_input.techniques[i].visibility[x].score_logbook[j].score == undefined) {
                                        yaml_input.techniques[i].visibility[x].score_logbook[j].score = 0;
                                    } else {
                                        yaml_input.techniques[i].visibility[x].score_logbook[j].score = this.fixVisibilityScore(
                                            yaml_input.techniques[i].visibility[x].score_logbook[j].score
                                        );
                                    }
                                    if (yaml_input.techniques[i].visibility[x].score_logbook[j].comment == undefined) {
                                        yaml_input.techniques[i].visibility[x].score_logbook[j].comment = '';
                                    }
                                    if (yaml_input.techniques[i].visibility[x].score_logbook[j].date != null) {
                                        yaml_input.techniques[i].visibility[x].score_logbook[j].date = moment(
                                            yaml_input.techniques[i].visibility[x].score_logbook[j].date,
                                            'DD/MM/YYYY'
                                        ).format('YYYY-MM-DD');
                                    }
                                    if (yaml_input.techniques[i].visibility[x].score_logbook[j].auto_generated == undefined) {
                                        yaml_input.techniques[i].visibility[x].score_logbook[j].auto_generated = false;
                                    }
                                    if (typeof yaml_input.techniques[i].visibility[x].score_logbook[j].auto_generated != 'boolean') {
                                        yaml_input.techniques[i].visibility[x].score_logbook[j].auto_generated = false;
                                    }
                                }
                            }

                            // Check overlapping applicable_to values for detection:
                            let applicable_to_list_detection = [];
                            let notifiedList_detection = [];
                            for (let x = 0; x < yaml_input.techniques[i].detection.length; x++) {
                                for (let j = 0; j < yaml_input.techniques[i].detection[x].applicable_to.length; j++) {
                                    applicable_to_list_detection.push(yaml_input.techniques[i].detection[x].applicable_to[j]);
                                }
                            }
                            for (let x = 0; x < applicable_to_list_detection.length; x++) {
                                let c = 0;
                                for (let j = 0; j < applicable_to_list_detection.length; j++) {
                                    if (applicable_to_list_detection[x] == applicable_to_list_detection[j]) {
                                        c++;
                                    }
                                }
                                if (c > 1 && !notifiedList_detection.includes(applicable_to_list_detection[x])) {
                                    notifiedList_detection.push(applicable_to_list_detection[x]);
                                    this.notifyOverlappingApplicableTo(
                                        'detection',
                                        yaml_input.techniques[i].technique_id,
                                        applicable_to_list_detection[x]
                                    );
                                }
                            }

                            // Check overlapping applicable_to values for visibility:
                            let applicable_to_list_visibility = [];
                            let notifiedList_visibility = [];
                            for (let x = 0; x < yaml_input.techniques[i].visibility.length; x++) {
                                for (let j = 0; j < yaml_input.techniques[i].visibility[x].applicable_to.length; j++) {
                                    applicable_to_list_visibility.push(yaml_input.techniques[i].visibility[x].applicable_to[j]);
                                }
                            }
                            for (let x = 0; x < applicable_to_list_visibility.length; x++) {
                                let c = 0;
                                for (let j = 0; j < applicable_to_list_visibility.length; j++) {
                                    if (applicable_to_list_visibility[x] == applicable_to_list_visibility[j]) {
                                        c++;
                                    }
                                }
                                if (c > 1 && !notifiedList_visibility.includes(applicable_to_list_visibility[x])) {
                                    notifiedList_visibility.push(applicable_to_list_visibility[x]);
                                    this.notifyOverlappingApplicableTo(
                                        'visibility',
                                        yaml_input.techniques[i].technique_id,
                                        applicable_to_list_visibility[x]
                                    );
                                }
                            }
                        }

                        this.doc = yaml_input;
                        this.filename = this.selected_filename;
                        this.filters.filter.value = '';
                        while (this.selectedRow != null && this.selectedRow.length > 0) {
                            this.selectedRow.pop();
                        }

                        this.fileChanged = false;
                        if (this.unwatchFunction != null) {
                            this.unwatchFunction();
                        }
                        this.unwatchFunction = this.$watch(
                            'doc',
                            // eslint-disable-next-line no-unused-vars
                            function(after, before) {
                                this.fileChanged = true;
                            },
                            { deep: true }
                        );

                        // Reset the file reader for Chrome, so that it will be possible to load the same file again:
                        document.getElementById('techniqueFileReader').value = null;
                    }
                } else {
                    this.notifyInvalidFileType(this.selected_filename);
                }
            } catch (e) {
                alert(e);
                this.notifyInvalidFileType(this.selected_filename);
            }
        },
        newFile() {
            this.filename = 'techniques-administration-new.yaml';
            this.selected_filename = 'techniques-administration-new.yaml';
            this.doc = _.cloneDeep(constants.YAML_OBJ_NEW_TECHNIQUES_FILE);
            this.selectedRow.pop();
            this.deletedRows = [];
            this.fileChanged = false;
            this.setWatch();
        },
        fixSDetectionScore(d) {
            if (d == undefined) {
                return -1;
            } else if (d < -1) {
                return -1;
            } else if (d > 5) {
                return 5;
            } else if (typeof d == 'number') {
                return d;
            } else {
                return -1;
            }
        },
        fixVisibilityScore(v) {
            if (v == undefined) {
                return 0;
            } else if (v < 0) {
                return 0;
            } else if (v > 4) {
                return 4;
            } else if (typeof v == 'number') {
                return v;
            } else {
                return 0;
            }
        },
        cleanupBeforeDownload() {
            // Check platform:
            if (this.doc.platform.length == 0) {
                this.notifyDanger('Missing value', 'No value for platform selected. Please select one or more platforms.');
                return;
            }

            // Remove empty score logbook rows in detection:
            for (let i = 0; i < this.doc.techniques.length; i++) {
                for (let x = 0; x < this.doc.techniques[i].detection.length; x++) {
                    let indexEmptyScoreLogbook = -1;
                    for (let j = 0; j < this.doc.techniques[i].detection[x].score_logbook.length; j++) {
                        if (this.doc.techniques[i].detection[x].score_logbook.length == 1) {
                            break;
                        }
                        let d = this.doc.techniques[i].detection[x].score_logbook[j].date;
                        if (d == null || d == '') {
                            indexEmptyScoreLogbook = j;
                        }
                    }
                    if (indexEmptyScoreLogbook >= 0) {
                        this.doc.techniques[i].detection[x].score_logbook.splice(indexEmptyScoreLogbook, 1);
                    }
                }
            }

            // Remove empty score logbook rows in visibility:
            for (let i = 0; i < this.doc.techniques.length; i++) {
                for (let x = 0; x < this.doc.techniques[i].visibility.length; x++) {
                    let indexEmptyScoreLogbook = -1;
                    for (let j = 0; j < this.doc.techniques[i].visibility[x].score_logbook.length; j++) {
                        if (this.doc.techniques[i].visibility[x].score_logbook.length == 1) {
                            break;
                        }
                        let d = this.doc.techniques[i].visibility[x].score_logbook[j].date;
                        if (d == null || d == '') {
                            indexEmptyScoreLogbook = j;
                        }
                    }
                    if (indexEmptyScoreLogbook >= 0) {
                        this.doc.techniques[i].visibility[x].score_logbook.splice(indexEmptyScoreLogbook, 1);
                    }
                }
            }
        },
        convertBeforeDownload(newDoc) {
            // Convert the date (which is a string in the GUI) to a real Date object in the YAML file
            for (let i = 0; i < newDoc.techniques.length; i++) {
                for (let x = 0; x < newDoc.techniques[i].detection.length; x++) {
                    for (let j = 0; j < newDoc.techniques[i].detection[x].score_logbook.length; j++) {
                        if (newDoc.techniques[i].detection[x].score_logbook[j]['date'] != null) {
                            newDoc.techniques[i].detection[x].score_logbook[j]['date'] = new Date(
                                newDoc.techniques[i].detection[x].score_logbook[j]['date']
                            );
                        }
                    }
                }
            }
            for (let i = 0; i < newDoc.techniques.length; i++) {
                for (let x = 0; x < newDoc.techniques[i].visibility.length; x++) {
                    for (let j = 0; j < newDoc.techniques[i].visibility[x].score_logbook.length; j++) {
                        if (newDoc.techniques[i].visibility[x].score_logbook[j]['date'] != null) {
                            newDoc.techniques[i].visibility[x].score_logbook[j]['date'] = new Date(
                                newDoc.techniques[i].visibility[x].score_logbook[j]['date']
                            );
                        }
                    }
                }
            }
        },
        selectTechnique(event) {
            if (this.$refs.detailComponent != undefined) {
                this.$refs.detailComponent.closeAllCollapses();
            }
            this.selectItem(event);
        },
        selectTechniqueId(technique_id) {
            let row = null;
            for (let i = 0; i < this.doc.techniques.length; i++) {
                if (this.doc.techniques[i].technique_id == technique_id) {
                    row = this.doc.techniques[i];
                }
            }
            if (row != null) {
                this.selectedRow.pop();
                this.selectedRow.push(row);
            }
        },
        deleteTechnique(event) {
            this.deleteItem(event, 'techniques', 'technique_id', 'Technique', this.recoverDeletedTechnique);
        },
        recoverDeletedTechnique(technique_id) {
            this.recoverDeletedItem('techniques', technique_id);
        },
        notifyInvalidFileType(filename) {
            this.notifyDanger('Invalid YAML file type', "The file '" + filename + "' is not a valid technique administration file.");
        },
        notifyOverlappingApplicableTo(type, technique_id, value) {
            this.notifyDangerWithCallback(
                "Overlapping value in 'applicable_to'",
                "A duplicate value for 'applicable_to' was found within the " + type + ' section of technique ' + technique_id + ": '" + value + "'",
                this.selectTechniqueId,
                'Go to technique ' + technique_id,
                technique_id,
                true
            );
        },
        hideFileDetails(state) {
            if (this.doc != null && this.$route.name == 'techniques' && !this.file_details_lock) {
                this.file_details_visible = state;
                this.changePageTitle();
            }
        }
    }
};
</script>

<style></style>
