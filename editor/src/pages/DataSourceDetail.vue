<template>
    <div class="card" v-if="dataSource != null">
        <auto-suggest-title
            title="Data source"
            :item="dataSource"
            itemIdName="data_source_name"
            :allItems="allDataSources"
            :suggestionList="dataSourceSuggestionList"
            :navigateItem="navigateItem"
        ></auto-suggest-title>
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
                    :date="dataSource.date_registered"
                    name="Date registered"
                    @dateUpdated="dataSource.date_registered = $event"
                ></date-picker>
            </div>
            <div class="col-md-4 pr-md-1">
                <date-picker :date="dataSource.date_connected" name="Date connected" @dateUpdated="dataSource.date_connected = $event"></date-picker>
            </div>
        </div>
        <div class="row mt-md-2">
            <div class="col-md-4 pr-md-1">
                <toggle-button
                    :state="dataSource.available_for_data_analytics"
                    name="Available for data analytics"
                    @toggleButtonUpdated="dataSource.available_for_data_analytics = $event"
                ></toggle-button>
            </div>
            <div class="col-md-5 pr-md-1">
                <toggle-button
                    :state="dsEnabled"
                    name="Data source enabled"
                    @toggleButtonUpdated="toggleEnabled"
                    helpText="Enables a data source by setting all data quality scores to 1, or restore to the previous value. Disables a data source by setting al data quality scores to 0."
                ></toggle-button>
            </div>
        </div>
        <list-editor :list="dataSource.products" name="Products" placeholder="Products" class="mt-md-2"></list-editor>
        <div class="row mt-md-0">
            <div class="col-md-11 form-group pr-md-2">
                <label class="card">Comment</label>
                <extended-textarea
                    :data_object="dataSource"
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
                    :score="dataSource.data_quality.device_completeness"
                    :markData="dataQualityScores"
                    :markDataTooltip="dataQualityTooltip"
                    @scoreUpdated="dataSource.data_quality.device_completeness = $event"
                ></score-slider>
            </div>
            <div class="col-md-5 ml-md-3">
                <score-slider
                    name="Data field completeness"
                    :score="dataSource.data_quality.data_field_completeness"
                    :markData="dataQualityScores"
                    :markDataTooltip="dataQualityTooltip"
                    @scoreUpdated="dataSource.data_quality.data_field_completeness = $event"
                ></score-slider>
            </div>
        </div>
        <div class="row mt-md-4">
            <div class="col-md-5">
                <score-slider
                    name="Timeliness"
                    :score="dataSource.data_quality.timeliness"
                    :markData="dataQualityScores"
                    :markDataTooltip="dataQualityTooltip"
                    @scoreUpdated="dataSource.data_quality.timeliness = $event"
                ></score-slider>
            </div>
            <div class="col-md-5 ml-md-3">
                <score-slider
                    name="Consistency"
                    :score="dataSource.data_quality.consistency"
                    :markData="dataQualityScores"
                    :markDataTooltip="dataQualityTooltip"
                    @scoreUpdated="dataSource.data_quality.consistency = $event"
                ></score-slider>
            </div>
        </div>
        <div class="row mt-md-4">
            <div class="col-md-5">
                <score-slider
                    name="Retention"
                    :score="dataSource.data_quality.retention"
                    :markData="dataQualityScores"
                    :markDataTooltip="dataQualityTooltip"
                    @scoreUpdated="dataSource.data_quality.retention = $event"
                ></score-slider>
            </div>
        </div>
        <custom-key-value-editor :item="dataSource" :defaultKeys="dataSourceDefaultKeys" class="mt-md-5"></custom-key-value-editor>
    </div>
</template>

<script>
import ListEditor from '@/components/Inputs/ListEditor';
import DatePicker from '@/components/Inputs/DatePicker';
import ToggleButton from '@/components/Inputs/ToggleButton';
import ScoreSlider from '@/components/Inputs/ScoreSlider';
import CustomKeyValueEditor from '@/components/Inputs/CustomKeyValueEditor';
import AutoSuggestTitle from '@/components/Inputs/AutoSuggestTitle';
import Icons from '@/components/Icons';
import ExtendedTextarea from '@/components/Inputs/ExtendedTextarea';
import constants from '@/constants';
import dataSources from '@/data/data_sources';
import Modal from '@/components/Modal';
import 'vue-directive-tooltip/dist/vueDirectiveTooltip.css';
import { pageDetailMixin } from '../mixins/PageDetailMixins.js';
import _ from 'lodash';

export default {
    data() {
        return {
            // the marker values as used for the data quality scoring ScoreSlider
            dataQualityScores: [0, 1, 2, 3, 4, 5],
            dataQualityTooltip: {
                '0': 'None',
                '1': 'Poor',
                '2': 'Fair',
                '3': 'Good',
                '4': 'Very good',
                '5': 'Excellent'
            },
            dataSourceDefaultKeys: Object.keys(constants.YAML_OBJ_DATA_SOURCES),
            dataSourceSuggestionList: dataSources,
            helptextDataQuality: false,
            helptextDataSourceKVPairs: false,
            commentModal: false
        };
    },
    mixins: [pageDetailMixin],
    props: {
        dataSource: {
            type: Object,
            required: true
        },
        allDataSources: {
            type: Array,
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
            type: Array,
            required: true
        },
        navigateItem: {
            type: Function,
            required: true
        }
    },
    methods: {
        escapeKeyListener: function(evt) {
            if (evt.keyCode === 27 && this.helptextDataQuality) {
                this.helptextDataQuality = false;
            } else if (evt.keyCode === 27 && this.helptextDataSourceKVPairs) {
                this.helptextDataSourceKVPairs = false;
            } else if (evt.keyCode === 27 && this.commentModal != '') {
                this.$bvModal.hide(this.commentModal);
                this.commentModal = '';
            }
        },
        toggleEnabled() {
            // disable or enable a data source
            let ds_name = this.dataSource['data_source_name'];
            if (this.dsEnabled) {
                this.prevDataSourceQuality[ds_name] = _.cloneDeep(this.dataSource.data_quality);
                for (let key in this.dataSource.data_quality) {
                    this.dataSource.data_quality[key] = 0;
                }
            } else {
                if (ds_name in this.prevDataSourceQuality) {
                    this.dataSource.data_quality = _.cloneDeep(this.prevDataSourceQuality[ds_name]);
                } else {
                    // eslint-disable-next-line no-redeclare
                    for (let key in this.dataSource.data_quality) {
                        this.dataSource.data_quality[key] = 1;
                    }
                }
            }
        },
        editCommentCallback(b) {
            this.commentModal = b;
        }
    },
    computed: {
        dsEnabled() {
            for (const score of Object.values(this.dataSource.data_quality)) {
                if (score > 0) {
                    return true;
                }
            }
            return false;
        }
    },
    components: {
        DatePicker,
        ListEditor,
        ToggleButton,
        ScoreSlider,
        CustomKeyValueEditor,
        AutoSuggestTitle,
        Modal,
        Icons,
        ExtendedTextarea
    }
};
</script>
