<template>
    <div>
        <div class="mb-3">
            <label>Applicable to</label>

            <div v-for="(row, i) in dataSource.data_source" :key="i" :row="row">
                <div id="collapseHeader">
                    <div class="row">
                        <div class="col-md-10 cursor-pointer" v-b-toggle="'collapse-ds-' + i">
                            <i class="when-opened tim-icons icon-minimal-up"></i>
                            <i class="when-closed tim-icons icon-minimal-down"></i>
                            &nbsp;{{ row.applicable_to.join(', ') }}
                        </div>
                        <div class="col collapse-trash-icon mr-md-2">
                            <i class="tim-icons icon-trash-simple icon-color cursor-pointer" @click="deleteApplicableTo(i)"></i>
                        </div>
                    </div>
                </div>

                <b-collapse :id="'collapse-ds-' + i" ref="collapseComponent">
                    <b-card id="collapseContent">
                        <list-editor-with-selects
                            :list="row.applicable_to"
                            :newItems="allSystems"
                            defaultItem="all"
                            :name="'Change applicable to value(s)'"
                            placeholder="applicable to"
                            class="mt-md-2 no-bottom-margin"
                            :externalListToValidate="getApplicableToList()"
                            :helpText="'Specifies to which type of system(s) this data source applies. The value \'all\' can be used to let it apply to every type of system.'"
                            notifyText="The value 'KEYNAME' is already part of the applicable_to for this data source. Duplicate entries are not allowed."
                            :isErrorFunction="isErrorFunction"
                            :getErrorTextFunction="getErrorText"
                            attributeName="applicable_to"
                            :defaultValueExclusive="true"
                        ></list-editor-with-selects>
                        <div class="row mt-md-0 mb-md-2" v-if="row.applicable_to.length == 0">
                            <div class="col-md-auto pr-md-0">
                                <i class="tim-icons icon-alert-circle-exc icon-color-warning"></i>
                            </div>
                            <div class="col-md-auto pl-md-2">
                                <label class="label-warning" id="warningText"
                                    >The applicable_to field should be filled in order for DeTT&CT to work properly.</label
                                >
                            </div>
                        </div>
                        <div class="row mt-md-3">
                            <div class="col-md-auto pr-md-0">
                                <h5 class="title mb-md-3">Data source key-value pairs</h5>
                            </div>
                            <div class="col ml-md-0" @click="helptextDataSourceKVPairs = true">
                                <icons icon="help" tooltip="Click to open more information."></icons>
                            </div>
                            <modal :show.sync="helptextDataSourceKVPairs" class="modal-help" id="dsModal" :centered="false" :show-close="true">
                                <h1 slot="header">Data source key-value pairs</h1>
                                <div class="markdown-popup">
                                    <VueShowdown :markdown="dsHelpText" />
                                </div>
                            </modal>
                        </div>
                        <div class="row">
                            <div class="col-md-4 pr-md-1">
                                <date-picker
                                    :date="row.date_registered"
                                    name="Date registered"
                                    :id="i.toString()"
                                    @dateUpdated="row.date_registered = $event"
                                ></date-picker>
                            </div>
                            <div class="col-md-4 pr-md-1">
                                <date-picker
                                    :date="row.date_connected"
                                    name="Date connected"
                                    :id="i.toString()"
                                    @dateUpdated="row.date_connected = $event"
                                ></date-picker>
                            </div>
                        </div>
                        <div class="row mt-md-2">
                            <div class="col-md-5 pr-md-1">
                                <toggle-button
                                    :state="dsEnabled(i)"
                                    name="Data source enabled"
                                    @toggleButtonUpdated="toggleEnabled(i)"
                                    helpText="Enables a data source by setting all data quality scores to 1, or restore to the previous value. Disables a data source by setting al data quality scores to 0."
                                ></toggle-button>
                            </div>
                            <div class="col-md-4 pr-md-1">
                                <toggle-button
                                    :state="row.available_for_data_analytics"
                                    name="Available for data analytics"
                                    @toggleButtonUpdated="row.available_for_data_analytics = $event"
                                ></toggle-button>
                            </div>
                        </div>
                        <list-editor :list="row.products" name="Products" placeholder="Products" class="mt-md-2"></list-editor>
                        <div class="row mt-md-0">
                            <div class="col-md-11 form-group pr-md-2">
                                <label class="card">Comment</label>
                                <extended-textarea
                                    :data_object="row"
                                    data_field="comment"
                                    id="datasource"
                                    rows="4"
                                    :cb_function="editCommentCallback"
                                ></extended-textarea>
                            </div>
                        </div>
                        <div class="row mt-md-3 col-md-5">
                            <div>
                                <h5 class="title mb-md-3">Data quality</h5>
                            </div>
                            <div class="col ml-md-0" @click="helptextDataQuality = true">
                                <icons icon="help" tooltip="Click to open more information."></icons>
                            </div>
                            <modal :show.sync="helptextDataQuality" class="modal-help" id="dqModal" :centered="false" :show-close="true">
                                <h1 slot="header">Scoring data quality</h1>
                                <div class="markdown-popup">
                                    <VueShowdown :markdown="dqHelpText" />
                                </div>
                            </modal>
                        </div>
                        <div class="row">
                            <div class="col-md-5">
                                <score-slider
                                    name="Device completeness"
                                    :score="row.data_quality.device_completeness"
                                    :markData="dataQualityScores"
                                    :markDataTooltip="dataQualityTooltip"
                                    @scoreUpdated="row.data_quality.device_completeness = $event"
                                ></score-slider>
                            </div>
                            <div class="col-md-5 ml-md-3">
                                <score-slider
                                    name="Data field completeness"
                                    :score="row.data_quality.data_field_completeness"
                                    :markData="dataQualityScores"
                                    :markDataTooltip="dataQualityTooltip"
                                    @scoreUpdated="row.data_quality.data_field_completeness = $event"
                                ></score-slider>
                            </div>
                        </div>
                        <div class="row mt-md-4">
                            <div class="col-md-5">
                                <score-slider
                                    name="Timeliness"
                                    :score="row.data_quality.timeliness"
                                    :markData="dataQualityScores"
                                    :markDataTooltip="dataQualityTooltip"
                                    @scoreUpdated="row.data_quality.timeliness = $event"
                                ></score-slider>
                            </div>
                            <div class="col-md-5 ml-md-3">
                                <score-slider
                                    name="Consistency"
                                    :score="row.data_quality.consistency"
                                    :markData="dataQualityScores"
                                    :markDataTooltip="dataQualityTooltip"
                                    @scoreUpdated="row.data_quality.consistency = $event"
                                ></score-slider>
                            </div>
                        </div>
                        <div class="row mt-md-4">
                            <div class="col-md-5">
                                <score-slider
                                    name="Retention"
                                    :score="row.data_quality.retention"
                                    :markData="dataQualityScores"
                                    :markDataTooltip="dataQualityTooltip"
                                    @scoreUpdated="row.data_quality.retention = $event"
                                ></score-slider>
                            </div>
                        </div>
                        <custom-key-value-editor :item="row" :defaultKeys="dataSourceDefaultKeys" class="mt-md-5"></custom-key-value-editor>
                    </b-card>
                </b-collapse>
            </div>
        </div>

        <div class="row mb-3">
            <div class="col">
                <button @click="addApplicableTo" class="btn-custom btn btn-secondary button-30">Add applicable to</button>
            </div>
        </div>
    </div>
</template>

<script>
import ListEditor from '@/components/Inputs/ListEditor';
import ListEditorWithSelects from '@/components/Inputs/ListEditorWithSelects';
import DatePicker from '@/components/Inputs/DatePicker';
import ToggleButton from '@/components/Inputs/ToggleButton';
import ScoreSlider from '@/components/Inputs/ScoreSlider';
import Icons from '@/components/Icons';
import ExtendedTextarea from '@/components/Inputs/ExtendedTextarea';
import CustomKeyValueEditor from '@/components/Inputs/CustomKeyValueEditor';
import Modal from '@/components/Modal';
import constants from '@/constants';
import { pageDetailMixin } from '@/mixins/PageDetailMixins.js';
import { notificationMixin } from '@/mixins/NotificationMixins.js';
import _ from 'lodash';

export default {
    data: function () {
        return {
            // the marker values as used for the data quality scoring ScoreSlider
            dataQualityScores: [0, 1, 2, 3, 4, 5],
            dataQualityTooltip: {
                0: 'None',
                1: 'Poor',
                2: 'Fair',
                3: 'Good',
                4: 'Very good',
                5: 'Excellent'
            },
            dataSourceDefaultKeys: Object.keys(constants.YAML_OBJ_DATA_SOURCES.data_source[0]),
            helptextDataQuality: false,
            helptextDataSourceKVPairs: false,
            commentModal: false,
            showHelpText: false
        };
    },
    mixins: [notificationMixin, pageDetailMixin],
    props: {
        dataSource: {
            type: Object,
            required: true
        },
        helpText: {
            type: String,
            required: true
        },
        dqHelpText: {
            type: String,
            required: true
        },
        dsHelpText: {
            type: String,
            required: true
        },
        prevDataSourceQuality: {
            type: Object,
            required: true
        },
        allSystems: {
            type: Array,
            required: true
        }
    },
    computed: {
        allSystemsValues() {
            let systems = [];
            for (let i = 0; i < this.allSystems.length; i++) {
                systems.push(this.allSystems[i]['applicable_to']);
            }
            return systems;
        }
    },
    components: {
        ListEditor,
        ListEditorWithSelects,
        CustomKeyValueEditor,
        ScoreSlider,
        Icons,
        ExtendedTextarea,
        DatePicker,
        ToggleButton,
        Modal
    },
    methods: {
        addApplicableTo() {
            for (let i = 0; i < this.dataSource.data_source.length; i++) {
                for (let x = 0; x < this.dataSource.data_source[i].applicable_to.length; x++) {
                    if (this.dataSource.data_source[i].applicable_to[x] == undefined) {
                        let title = 'Add new applicable to';
                        let msg = 'Only one applicable to can be added at a time.';
                        this.notifyWarning(title, msg);
                        return;
                    }
                }
            }

            let newItem = _.cloneDeep(constants.YAML_OBJ_DATA_SOURCES.data_source[0]);
            newItem.applicable_to = [];
            this.dataSource.data_source.push(newItem);
            setTimeout(() => {
                this.$root.$emit('bv::toggle::collapse', 'collapse-ds-' + (this.dataSource.data_source.length - 1));
            }, 10);
        },
        getApplicableToList() {
            let applicable_to_list = [];
            for (let i = 0; i < this.dataSource.data_source.length; i++) {
                for (let x = 0; x < this.dataSource.data_source[i].applicable_to.length; x++) {
                    if (this.dataSource.data_source[i].applicable_to[x] != null) {
                        applicable_to_list.push(this.dataSource.data_source[i].applicable_to[x]);
                    }
                }
            }
            return applicable_to_list;
        },
        deleteApplicableTo(index) {
            this.dataSource.data_source.splice(index, 1);
        },
        closeAllCollapses() {
            for (let i = 0; i < this.dataSource.data_source.length; i++) {
                this.$refs.collapseComponent[i].show = false;
            }
        },
        escapeKeyListener: function (evt) {
            if (evt.keyCode === 27 && this.helptextDataQuality) {
                this.helptextDataQuality = false;
            } else if (evt.keyCode === 27 && this.helptextDataSourceKVPairs) {
                this.helptextDataSourceKVPairs = false;
            } else if (evt.keyCode === 27 && this.commentModal != '') {
                this.$bvModal.hide(this.commentModal);
                this.commentModal = '';
            }
        },
        toggleEnabled(i) {
            /* eslint-disable */
            // disable or enable a data source and make sure the history is saved and restored
            let ds_name = this.dataSource['data_source_name'];
            let ds_applicable_to = this.dataSource.data_source[i].applicable_to.join(',');
            if (this.dsEnabled(i)) {
                if (!(ds_name in this.prevDataSourceQuality)) {
                    this.prevDataSourceQuality[ds_name] = {};
                }

                this.prevDataSourceQuality[ds_name][ds_applicable_to] = _.cloneDeep(this.dataSource.data_source[i].data_quality);
                for (let key in this.dataSource.data_source[i].data_quality) {
                    this.dataSource.data_source[i].data_quality[key] = 0;
                }
            } else {
                if (ds_name in this.prevDataSourceQuality && ds_applicable_to in this.prevDataSourceQuality[ds_name]) {
                    this.dataSource.data_source[i].data_quality = _.cloneDeep(this.prevDataSourceQuality[ds_name][ds_applicable_to]);
                } else {
                    for (let key in this.dataSource.data_source[i].data_quality) {
                        this.dataSource.data_source[i].data_quality[key] = 1;
                    }
                }
            }
            /* eslint-enable */
        },
        editCommentCallback(b) {
            this.commentModal = b;
        },
        dsEnabled(i) {
            for (const score of Object.values(this.dataSource.data_source[i].data_quality)) {
                if (score > 0) {
                    return true;
                }
            }
            return false;
        },
        isErrorFunction(item, list) {
            if ((item == 'all' && list.length > 1) || (!this.allSystemsValues.includes(item) && item != 'all')) {
                return true;
            } else {
                return false;
            }
        },
        getErrorText(item, list) {
            if (item == 'all' && list.length > 1) {
                return "The value 'all' is exclusive for the data source's applicable_to values and can therefore not be combined with other applicable_to values. Remove 'all' to let DeTT&CT work properly.";
            } else if (!this.allSystemsValues.includes(item) && item != 'all') {
                return (
                    "The value '" +
                    item +
                    "' is not specified within the 'systems' key-value pair. Add this applicable_to value to the 'systems' key-value pair, otherwise it will be ignored."
                );
            } else {
                return '';
            }
        }
    }
};
</script>

<style></style>
