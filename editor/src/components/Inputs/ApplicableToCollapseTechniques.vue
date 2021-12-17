<template>
    <div>
        <div class="row mt-md-3">
            <div class="col-md-auto pr-md-0">
                <h5 class="title mb-md-3">{{ title }} scores</h5>
            </div>
            <div class="col ml-md-0" @click="showHelpText = true">
                <icons icon="help" tooltip="Click to open more information."></icons>
            </div>
            <modal :show.sync="showHelpText" class="modal-help" id="Modal" :centered="false" :show-close="true">
                <h1 slot="header">{{ title }}</h1>
                <div class="markdown-popup">
                    <VueShowdown :markdown="helpText" />
                </div>
            </modal>
        </div>

        <div class="mb-3">
            <label>Applicable to</label>
            <div v-for="(row, i) in applicable_to" :key="i" :row="row">
                <div id="collapseHeader">
                    <div class="row">
                        <div class="col-md-10 cursor-pointer" v-b-toggle="'collapse-' + title.toLowerCase() + '-' + i">
                            <i class="when-opened tim-icons icon-minimal-up"></i>
                            <i class="when-closed tim-icons icon-minimal-down"></i>
                            &nbsp;{{ row.applicable_to.join(', ') }}
                        </div>
                        <div class="col collapse-trash-icon mr-md-2">
                            <i class="tim-icons icon-trash-simple icon-color cursor-pointer" @click="deleteApplicableTo(i)"></i>
                        </div>
                    </div>
                </div>

                <b-collapse :id="'collapse-' + title.toLowerCase() + '-' + i" ref="collapseComponent">
                    <b-card id="collapseContent">
                        <list-editor
                            :list="row.applicable_to"
                            :name="'Change applicable to value(s)'"
                            placeholder="applicable to"
                            class="mt-md-2 no-bottom-margin"
                            :externalListToValidate="getApplicableToList()"
                            :helpText="
                                'Specifies to which type of system(s) this ' +
                                    title.toLowerCase() +
                                    ' applies. The value \'all\' can be used to let it apply to every type of system.'
                            "
                            notifyText="The value 'KEYNAME' is already part of the applicable_to for this technique. Duplicate entries are not allowed."
                            :suggestionList="applicableToSuggestionList"
                            :defaultValueExclusive="defaultValueExclusive"
                            :isErrorFunction="isErrorFunction"
                            errorText="The value 'all' is exclusive for the visibility's applicable_to values and can therefore not be combined with other applicable_to values. Remove 'all' to let DeTT&CT work properly."
                        ></list-editor>
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
                        <list-editor
                            v-if="showLocation"
                            :list="row.location"
                            :name="'Location of the ' + title.toLowerCase() + '(s)'"
                            placeholder="location"
                            class="mt-md-2"
                            :helpText="
                                'The location(s) where your detection is residing. For example, a specific ID or name of a detection rule/use case, SIEM or product name.'
                            "
                        ></list-editor>
                        <div class="row mt-md-2">
                            <div class="col">
                                <label class="card">Comment</label>
                            </div>
                        </div>
                        <div class="row mt-md-0">
                            <div class="col-md-11">
                                <extended-textarea
                                    :data_object="row"
                                    data_field="comment"
                                    :id="title + i"
                                    rows="4"
                                    :cb_function="editCommentCallback"
                                ></extended-textarea>
                            </div>
                        </div>
                        <div class="row mt-md-3">
                            <div class="col-md-4">
                                <score-slider
                                    :name="'Score date: ' + getLatestScoreDate(row.score_logbook)"
                                    :score="getLatestScore(row.score_logbook)"
                                    :markData="scores"
                                    :markDataTooltip="scoresTooltip"
                                    :showLabel="true"
                                    @scoreUpdated="setLatestScore(row.score_logbook, getLatestScoreDate(row.score_logbook), $event)"
                                ></score-slider>
                            </div>
                        </div>
                        <div class="row mt-md-4">
                            <div class="col-md-auto">
                                <b-button
                                    v-b-modal="title + '-score-logbook-modal-' + i"
                                    @click="currentModal = title + '-score-logbook-modal-' + i"
                                    class="btn-custom btn btn-secondary button-30"
                                    >Score logbook</b-button
                                >
                                <b-modal
                                    :id="title + '-score-logbook-modal-' + i"
                                    dialog-class="modal-edit-wide"
                                    content-class="modal-dark-mode"
                                    hide-footer
                                    hide-header
                                    no-close-on-esc
                                >
                                    <score-logbook
                                        :item="row.score_logbook"
                                        :scores="scores"
                                        :scoresTooltip="scoresTooltip"
                                        :defaultScore="defaultScore"
                                        :showAutoGenerated="showAutoGenerated"
                                        :modalId="title + '-score-logbook-modal-' + i"
                                        :emptyScoreEntry="emptyScoreEntry"
                                        @showHelptextScoreNow="showHelptextScore = true"
                                        :cb_function="editCommentCallback"
                                    ></score-logbook>
                                </b-modal>
                                <modal :show.sync="showHelptextScore" class="modal-help" :centered="false" :show-close="true">
                                    <h1 slot="header">{{ title }} scoring</h1>
                                    <div class="markdown-popup">
                                        <VueShowdown :markdown="helptextScore" />
                                    </div>
                                </modal>
                            </div>
                            <div class="col-md-auto">
                                <b-button v-b-modal="title + '-custom-kvpairs-modal-' + i" class="btn-custom btn btn-secondary button-30"
                                    >Custom key value pairs</b-button
                                >
                                <b-modal
                                    :id="title + '-custom-kvpairs-modal-' + i"
                                    dialog-class="modal-edit-small"
                                    content-class="modal-dark-mode"
                                    hide-footer
                                    hide-header
                                >
                                    <custom-key-value-editor
                                        :item="row"
                                        :defaultKeys="defaultKVKeys"
                                        :useInModal="true"
                                        :modalId="title + '-custom-kvpairs-modal-' + i"
                                    ></custom-key-value-editor>
                                </b-modal>
                            </div>
                        </div>
                    </b-card>
                </b-collapse>
            </div>
        </div>

        <div class="row mb-3">
            <div class="col">
                <button @click="addApplicableTo" class="btn-custom btn btn-secondary button-30">Add {{ title.toLowerCase() }} score</button>
            </div>
        </div>
    </div>
</template>

<script>
import ListEditor from '@/components/Inputs/ListEditor';
import Modal from '@/components/Modal';
import CustomKeyValueEditor from '@/components/Inputs/CustomKeyValueEditor';
import ScoreLogbook from '@/components/Inputs/ScoreLogbook';
import ScoreSlider from '@/components/Inputs/ScoreSlider';
import Icons from '@/components/Icons';
import ExtendedTextarea from '@/components/Inputs/ExtendedTextarea';
import { pageDetailMixin } from '@/mixins/PageDetailMixins.js';
import { notificationMixin } from '@/mixins/NotificationMixins.js';
import _ from 'lodash';

export default {
    data: function() {
        return {
            showHelpText: false,
            defaultKVKeys: Object.keys(this.emptyObject),
            showHelptextScore: false,
            currentModal: '',
            commentModal: ''
        };
    },
    mixins: [notificationMixin, pageDetailMixin],
    props: {
        title: {
            type: String,
            required: true
        },
        applicable_to: {
            type: Array,
            required: true
        },
        showLocation: {
            type: Boolean,
            required: false,
            default: true
        },
        helpText: {
            type: String,
            required: true
        },
        scores: {
            type: Array,
            required: true
        },
        scoresTooltip: {
            type: Object,
            required: true
        },
        defaultScore: {
            type: Number,
            required: true
        },
        showAutoGenerated: {
            type: Boolean,
            required: false,
            default: false
        },
        emptyScoreEntry: {
            type: Object,
            required: true
        },
        helptextScore: {
            type: String,
            required: true
        },
        emptyObject: {
            type: Object,
            required: true
        },
        applicableToSuggestionList: {
            type: Array,
            required: true
        },
        defaultValueExclusive: {
            type: Boolean,
            required: false,
            default: false
        }
    },
    components: {
        ListEditor,
        Modal,
        CustomKeyValueEditor,
        ScoreLogbook,
        ScoreSlider,
        Icons,
        ExtendedTextarea
    },
    methods: {
        escapeKeyListener: function(evt) {
            if (evt.keyCode === 27 && this.showHelptextScore) {
                this.showHelptextScore = false;
            } else if (evt.keyCode === 27 && this.showHelpText) {
                this.showHelpText = false;
            } else if (evt.keyCode === 27 && this.currentModal != '' && this.commentModal == '') {
                this.$bvModal.hide(this.currentModal);
            } else if (evt.keyCode === 27 && this.commentModal != '') {
                this.$bvModal.hide(this.commentModal);
                this.commentModal = '';
            }
        },
        addApplicableTo() {
            for (let i = 0; i < this.applicable_to.length; i++) {
                for (let x = 0; x < this.applicable_to[i].applicable_to.length; x++) {
                    if (this.applicable_to[i].applicable_to[x] == undefined) {
                        let title = 'Add new detection';
                        let msg = 'Only one ' + this.title.toLowerCase() + ' can be added at a time.';
                        this.notifyWarning(title, msg);
                        return;
                    }
                }
            }

            let newItem = _.cloneDeep(this.emptyObject);
            newItem.applicable_to = [];
            this.applicable_to.push(newItem);
            setTimeout(() => {
                this.$root.$emit('bv::toggle::collapse', 'collapse-' + this.title.toLowerCase() + '-' + (this.applicable_to.length - 1));
            }, 10);
        },
        getApplicableToList() {
            let applicable_to_list = [];
            for (let i = 0; i < this.applicable_to.length; i++) {
                for (let x = 0; x < this.applicable_to[i].applicable_to.length; x++) {
                    if (this.applicable_to[i].applicable_to[x] != null) {
                        applicable_to_list.push(this.applicable_to[i].applicable_to[x]);
                    }
                }
            }
            return applicable_to_list;
        },
        getLatestScoreDate(score_logbook) {
            let sorted = _.sortBy(score_logbook, 'date');
            let d = null;
            if (sorted.length >= 1) {
                d = sorted[sorted.length - 1].date;
            }
            if (d == null || d == '') {
                d = '[set date in score logbook]';
            }
            return d;
        },
        getLatestScore(score_logbook) {
            let sorted = _.sortBy(score_logbook, 'date');
            if (sorted.length >= 1) {
                return sorted[sorted.length - 1].score;
            } else {
                return -1;
            }
        },
        setLatestScore(score_logbook, d, event) {
            if (score_logbook.length == 0) {
                let newItem = _.cloneDeep(this.emptyScoreEntry);
                newItem.date = this.getCurrentDate();
                newItem.score = event;
                score_logbook.push(newItem);
            } else {
                for (let i = 0; i < score_logbook.length; i++) {
                    if (score_logbook[i].date == d) {
                        score_logbook[i].score = event;
                        if (this.showAutoGenerated) {
                            score_logbook[i].auto_generated = false;
                        }
                    } else if (score_logbook[i].date == null || score_logbook[i].date == '') {
                        score_logbook[i].date = this.getCurrentDate();
                        score_logbook[i].score = event;
                        if (this.showAutoGenerated) {
                            score_logbook[i].auto_generated = false;
                        }
                    }
                }
            }
        },
        getCurrentDate() {
            let today = new Date();
            let dd = today.getDate().toString();
            let mm = (today.getMonth() + 1).toString(); //January is 0!
            let yyyy = today.getFullYear().toString();
            return yyyy + '-' + mm.padStart(2, '0') + '-' + dd.padStart(2, '0');
        },
        deleteApplicableTo(index) {
            this.applicable_to.splice(index, 1);
        },
        closeAllCollapses() {
            for (let i = 0; i < this.applicable_to.length; i++) {
                this.$refs.collapseComponent[i].show = false;
            }
        },
        editCommentCallback(b) {
            this.commentModal = b;
        },
        isErrorFunction(item, list) {
            return this.defaultValueExclusive && item == 'all' && list.length > 1 ? true : false;
        }
    }
};
</script>

<style></style>
