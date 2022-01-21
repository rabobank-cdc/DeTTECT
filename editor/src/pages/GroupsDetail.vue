<template>
    <div>
        <div class="container-fluid d-flex flex-column">
            <div v-if="isNewGroup || editGroupName">
                <div class="row">
                    <div class="col-md-auto pr-md-0 pl-md-0 margin-top-8">
                        <label>Group name</label>
                    </div>
                    <div class="col-md-7 pl-md-2 pr-md-0">
                        <base-input
                            :value="group.group_name"
                            @change="group.group_name = $event.target.value"
                            @keyup.enter="editGroupName = false"
                            @keydown.tab="editGroupName = false"
                            @blur="editGroupName = false"
                        ></base-input>
                    </div>
                    <div class="col-md-auto">
                        <i class="tim-icons icon-check-2 icon-color icon-padding cursor-pointer" @click="editGroupName = false"></i>
                    </div>
                </div>
            </div>
            <div v-else class="row flex-fill">
                <div class="col-md pr-md-0 pl-md-0">
                    <span id="detailCard" class="card-title">{{ group.group_name }}</span>
                    <i class="tim-icons icon-pencil icon-color icon-padding cursor-pointer" @click="editGroupName = true"></i>
                </div>
            </div>
        </div>
        <div class="row mt-md-3">
            <div class="col-md-auto pr-md-0">
                <h5 class="title mb-md-3">Group key-value pairs</h5>
            </div>
            <div class="col ml-md-0" @click="helptextGroupKVPairs = true">
                <icons icon="help" tooltip="Click to open more information."></icons>
            </div>
            <modal :show.sync="helptextGroupKVPairs" class="modal-help" id="dsModal" :centered="false" :show-close="true">
                <h1 slot="header">Group key-value pairs</h1>
                <div class="markdown-popup">
                    <VueShowdown :markdown="groupHelpText" />
                </div>
            </modal>
        </div>
        <div class="row">
            <div class="col-md-5 pr-md-0 form-group">
                <div>
                    <label>Campaign name</label>
                </div>
                <div>
                    <base-input :value="group.campaign" @change="group.campaign = $event.target.value"></base-input>
                </div>
            </div>
            <div class="col-md-3 mt-md-1 form-group">
                <toggle-button
                    :state="group.enabled"
                    name="Enabled"
                    @toggleButtonUpdated="group.enabled = $event"
                    :extraPaddingBottom="false"
                ></toggle-button>
            </div>
        </div>
        <div class="row mt-md-0 mb-md-3" v-if="!isUniqueGroup">
            <div class="col-md-auto pr-md-0">
                <i class="tim-icons icon-alert-circle-exc icon-color-warning"></i>
            </div>
            <div class="col-md-auto pl-md-2">
                <label class="label-warning" id="warningText">The combination of group name and campaign should be unique.</label>
            </div>
        </div>
        <auto-suggest-group
            title="Technique IDs"
            :group="group"
            itemIdName="technique_id"
            :platforms="selectedPlatforms"
            :suggestionList="techniques"
            valueAttr="technique_id"
        ></auto-suggest-group>
        <div class="row mt-md-0 mb-md-3" v-if="group.technique_id.length < 1">
            <div class="col-md-auto pr-md-0">
                <i class="tim-icons icon-alert-circle-exc icon-color-warning"></i>
            </div>
            <div class="col-md-auto pl-md-2">
                <label class="label-warning" id="warningText">A group YAML should contain at least one technique ID.</label>
            </div>
        </div>
        <auto-suggest-group
            class="mt-md-3"
            title="Software IDs"
            :group="group"
            itemIdName="software_id"
            :platforms="selectedPlatforms"
            :suggestionList="software"
            valueAttr="software_id"
        ></auto-suggest-group>
        <custom-key-value-editor :item="group" :defaultKeys="groupDefaultKeys" class="mt-md-3"></custom-key-value-editor>
    </div>
</template>

<script>
import AutoSuggestGroup from '@/components/Inputs/AutoSuggestGroup';
import CustomKeyValueEditor from '@/components/Inputs/CustomKeyValueEditor';
import ToggleButton from '@/components/Inputs/ToggleButton';
import Modal from '@/components/Modal';
import Icons from '@/components/Icons';
import techniques from '@/data/techniques';
import software from '@/data/software';
import constants from '@/constants';
import { pageDetailMixin } from '@/mixins/PageDetailMixins.js';
import 'vue-directive-tooltip/dist/vueDirectiveTooltip.css';

export default {
    data() {
        return {
            techniques: techniques['ATT&CK-Enterprise'],
            software: software['ATT&CK-Enterprise'],
            groupDefaultKeys: Object.keys(constants.YAML_OBJ_GROUP),
            editGroupName: false,
            helptextGroupKVPairs: false
        };
    },
    mixins: [pageDetailMixin],
    props: {
        group: {
            type: Object,
            required: true
        },
        allGroups: {
            type: Array,
            required: true
        },
        selectedPlatforms: {
            type: Array,
            required: true
        },
        groupHelpText: {
            type: String
        }
    },
    watch: {
        group() {
            // this make sure to disable the edit 'box' when necessary
            this.editGroupName = false;
        }
    },
    methods: {
        escapeKeyListener: function (evt) {
            if (evt.keyCode === 27 && this.helptextGroupKVPairs) {
                this.helptextGroupKVPairs = false;
            }
        },
        getGroupIDs() {
            // return a list containing the combination of group_name+campaign of all group objects in the YAML file
            let groupIDs = [];
            for (let i = 0; i < this.allGroups.length; i++) {
                groupIDs.push(this.allGroups[i].group_name.toLowerCase() + this.allGroups[i].campaign.toLowerCase());
            }
            return groupIDs;
        }
    },
    computed: {
        isNewGroup() {
            return this.group.group_name == '' ? true : false;
        },
        isUniqueGroup() {
            // checks if the combination of group_name+campaign is unique
            let groupIDs = this.getGroupIDs();
            let counter = 0;

            for (let i = 0; i < groupIDs.length; i++) {
                if (groupIDs[i] == this.group.group_name.toLowerCase() + this.group.campaign.toLowerCase()) {
                    counter++;
                }
            }
            return counter > 1 ? false : true;
        }
    },
    components: {
        AutoSuggestGroup,
        ToggleButton,
        CustomKeyValueEditor,
        Modal,
        Icons
    }
};
</script>
