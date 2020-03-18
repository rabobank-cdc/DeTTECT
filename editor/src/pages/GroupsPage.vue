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
                    <div class="card-header">
                        <h2 class="card-title"><i class="tim-icons icon-single-02"></i> Groups</h2>
                    </div>
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
                                    <file-reader @load="readFile($event)" :setFileNameFn="setFileName" :id="'groupFileReader'"></file-reader>
                                </label>
                                <label v-if="fileChanged" class="pl-2">
                                    <icons icon="text-balloon"></icons>
                                    You have unsaved changes. You may want to save the file to preserve your changes.</label
                                >
                            </div>
                        </div>
                        <div v-if="doc != null" class="row pt-md-2">
                            <div class="col">
                                <file-details :filename="filename" :doc="doc" :platforms="platforms" :showName="false"></file-details>
                            </div>
                        </div>
                        <div v-if="doc != null" class="row pt-md-2">
                            <div class="col card-text">
                                <button type="button" class="btn" @click="downloadYaml('groups', 'group_name')">
                                    <icons icon="save"></icons>
                                    &nbsp;Save YAML file
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <div v-if="doc != null" class="row">
            <div class="col">
                <card type="card">
                    <div class="row">
                        <div class="col">
                            <p>
                                <button type="button" class="btn btn-secondary" @click="addItem('groups', 'group_name', emptyGroupObject)">
                                    <icons icon="plus"></icons>
                                    &nbsp;Add group
                                </button>
                            </p>
                        </div>
                    </div>
                    <div class="row mt-md-2">
                        <div class="col">
                            <base-input v-model="filters.filter.value" placeholder="filter" />
                            <v-table
                                :data="doc.groups"
                                @selectionChanged="selectItem($event)"
                                selectedClass="table-selected-custom"
                                :filters="filters"
                                class="table-custom"
                            >
                                <thead slot="head">
                                    <v-th sortKey="group_name" defaultSort="asc" width="400">Group name</v-th>
                                    <v-th sortKey="campaign" width="400">Campaign</v-th>
                                    <v-th sortKey="enabled" width="150">Enabled</v-th>
                                    <th></th>
                                </thead>
                                <tbody slot="body" slot-scope="{ displayData }">
                                    <v-tr v-for="(row, i) in displayData" :key="i" :row="row">
                                        <td>{{ row.group_name }}</td>
                                        <td>{{ row.campaign }}</td>
                                        <td>{{ row.enabled | listToString }}</td>
                                        <td>
                                            <i
                                                class="tim-icons icon-trash-simple cursor-pointer"
                                                :idx="i"
                                                :group_name="row.group_name"
                                                @click="deleteGroup($event)"
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
                    <groups-detail
                        v-if="getSelectedItem() != null"
                        :group="getSelectedItem()"
                        :allGroups="doc.groups"
                        :selectedPlatforms="doc.platform"
                        :groupHelpText="groupHelpText"
                    ></groups-detail>
                </card>
            </div>
        </div>
    </div>
</template>

<script>
import GroupsDetail from './GroupsDetail';
import Icons from '@/components/Icons';
import jsyaml from 'js-yaml';
import constants from '@/constants';
import { pageMixin } from '../mixins/PageMixins.js';
import { notificationMixin } from '../mixins/NotificationMixins.js';
import _ from 'lodash';

export default {
    name: 'groups-page',
    data() {
        return {
            filters: {
                filter: {
                    value: '',
                    keys: ['group_name', 'campaign', 'enabled']
                }
            },
            data_columns: ['group_name', 'campaign', 'enabled'],
            groupFileToRender: 'https://raw.githubusercontent.com/wiki/rabobank-cdc/DeTTECT/YAML-administration-groups.md',
            groupHelpText: null,
            emptyGroupObject: constants.YAML_OBJ_GROUP
        };
    },
    mixins: [pageMixin, notificationMixin],
    components: {
        GroupsDetail,
        Icons
    },
    created: function() {
        this.preloadMarkDown();
    },
    methods: {
        readFile(event) {
            // Loads and checks the file content
            try {
                let yaml_input = jsyaml.safeLoad(event.result);

                if (yaml_input['file_type'] == 'group-administration') {
                    if (yaml_input['version'] != constants.YAML_DATASOURCES_VERSION) {
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

                        // Fix missing/invalid fields: group_name, campaign, enabled, technique_id, software_id
                        for (let i = 0; i < yaml_input.groups.length; i++) {
                            if (yaml_input.groups[i].group_name == undefined) {
                                yaml_input.groups[i].group_name = 'empty';
                            }

                            if (yaml_input.groups[i].campaign == undefined) {
                                yaml_input.groups[i].campaign = 'empty';
                            }

                            if (typeof yaml_input.groups[i].enabled != 'boolean') {
                                yaml_input.groups[i].enabled = false;
                            }

                            if (yaml_input.groups[i].technique_id == undefined) {
                                yaml_input.groups[i].technique_id = [];
                            }

                            if (yaml_input.groups[i].software_id == undefined) {
                                yaml_input.groups[i].software_id = [];
                            }

                            if (!Array.isArray(yaml_input.groups[i].technique_id)) {
                                yaml_input.groups[i].technique_id = [];
                            }

                            if (!Array.isArray(yaml_input.groups[i].software_id)) {
                                yaml_input.groups[i].software_id = [];
                            }

                            for (let x = 0; x < yaml_input.groups[i].technique_id.length; x++) {
                                if (yaml_input.groups[i].technique_id[x].match(/^T[0-9]{4}$/i) == null) {
                                    yaml_input.groups[i].technique_id.splice(x, 1);
                                }
                                if (yaml_input.groups[i].technique_id[x] != undefined) {
                                    yaml_input.groups[i].technique_id[x] = yaml_input.groups[i].technique_id[x].toUpperCase();
                                }
                            }
                            for (let x = 0; x < yaml_input.groups[i].software_id.length; x++) {
                                if (yaml_input.groups[i].software_id[x].match(/^S[0-9]{4}$/i) == null) {
                                    yaml_input.groups[i].software_id.splice(x, 1);
                                }
                                if (yaml_input.groups[i].software_id[x] != undefined) {
                                    yaml_input.groups[i].software_id[x] = yaml_input.groups[i].software_id[x].toUpperCase();
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
                        document.getElementById('groupFileReader').value = null;
                    }
                } else {
                    this.notifyInvalidFileType(this.selected_filename);
                }
            } catch (e) {
                //alert(e);
                this.notifyInvalidFileType(this.selected_filename);
            }
        },
        newFile() {
            this.filename = 'groups-new.yaml';
            this.selected_filename = 'groups-new.yaml';
            this.doc = _.cloneDeep(constants.YAML_OBJ_NEW_GROUPS_FILE);
            this.selectedRow.pop();
            this.deletedRows = [];
            this.fileChanged = false;
            this.setWatch();
        },
        cleanupBeforeDownload() {
            // empty function. must be here to make downloadYaml() work for every page
        },
        convertBeforeDownload() {
            // empty function. must be here to make downloadYaml() work for every page
        },
        deleteGroup(event) {
            this.deleteItem(event, 'groups', 'group_name', 'Group', this.recoverDeletedGroup);
        },
        recoverDeletedGroup(group_name) {
            this.recoverDeletedItem('groups', group_name);
        },
        preloadMarkDown() {
            // Preload the group help text from Github

            this.groupHelpText = 'Loading the help content...';
            this.$http.get(this.groupFileToRender).then(
                response => {
                    this.groupHelpText = response.body.replace(/\[(.+)\](\([#\w-]+\))/gm, '$1'); // remove links to other wiki pages
                    this.groupHelpText = this.groupHelpText.match(/## Group object((.*|\n)*)/gim, '$1')[0];
                    this.groupHelpText = this.groupHelpText.replace(/^## Group object/gim, '');
                },
                // eslint-disable-next-line no-unused-vars
                response => {
                    this.groupHelpText = 'An error occurred while loading the help content.';
                }
            );
        },
        notifyInvalidFileType(filename) {
            this.notifyDanger('Invalid YAML file type', "The file '" + filename + "' is not a valid group administration file.");
        }
    },
    filters: {
        listToString: function(value) {
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
