<template>
    <table class="table-file-details">
        <tr>
            <td width="100" colspan="2">
                <b>File details</b>
            </td>
        </tr>
        <tr>
            <td width="100">Filename:</td>
            <td>{{ filename }}</td>
        </tr>
        <tr>
            <td>File type:</td>
            <td>{{ doc['file_type'] }}</td>
        </tr>
        <tr>
            <td>Version:</td>
            <td>{{ doc['version'].toFixed(1) }}</td>
        </tr>
        <tr v-show="showName">
            <td>Name:</td>
            <td><base-input v-model="doc['name']" class="file-detail-edit"></base-input></td>
        </tr>
        <tr>
            <td class="vtop">Notes:</td>
            <td>
                <div class="textareaFileDetails">
                    <extended-textarea :data_object="doc" data_field="notes" rows="2" id="notes"></extended-textarea>
                </div>
            </td>
        </tr>
        <tr v-if="systemsOrPlatforms == 'systems'">
            <td class="vtop">Systems:</td>
            <td width=1000>
                <list-editor-extended
                    name="platform-selector"
                    :list="doc.systems"
                    class="mt-md-2 no-bottom-margin list-editor-extended"
                    notifyText="'KEYNAME' already exists. Duplicate entries are not allowed."
                    placeholder="applicable to"
                    subject_text="platform"
                    :values="platforms"
                    :valuesConversion="platformConversion"
                    :reservedKeywords="['all']"
                    :checkInUseFunction="checkSystemNotInUse"
                    :postRemoveFunction="removeApplicableToFromDataSources"
                    :postUpdateFunction="updateNameApplicableToForDataSources"
                ></list-editor-extended>
            </td>
        </tr>
        <tr v-else>
            <td>Platform:</td>
            <td>
                <!-- eslint-disable-next-line vue/require-v-for-key -->
                <label class="custom-checkbox" v-for="row in platforms" :for="row">
                    <input type="checkbox" :id="row" :value="row" v-model="doc.platform" @click="platformEventHandler(row)" @change="checkPlatform" />
                    {{ row }}
                </label>
            </td>
        </tr>
    </table>
</template>

<script>
import { notificationMixin } from '@/mixins/NotificationMixins.js';
import ExtendedTextarea from '@/components/Inputs/ExtendedTextarea';
import ListEditorExtended from '@/components/Inputs/ListEditorExtended';

export default {
    mixins: [notificationMixin],
    props: {
        filename: {
            type: String,
            required: true,
        },
        doc: {
            type: Object,
            required: true,
        },
        platforms: {
            type: Array,
            required: true,
        },
        platformConversion: {
            type: Object,
            required: false
        },
        showName: {
            type: Boolean,
            required: false,
            default: true,
        },
        systemsOrPlatforms: {
            type: String,
            required: true
        }
    },
    methods: {
        platformEventHandler(event) {
            // Extra event handler for handling platform checkboxes (regarding the 'all' option)
            if (event == 'all') {
                this.doc.platform = ['all'];
            } else {
                let all_index = -1;
                for (let i = 0; i < this.doc.platform.length; i++) {
                    if (this.doc.platform[i] == 'all') {
                        all_index = i;
                    }
                }
                if (all_index >= 0) {
                    this.doc.platform.splice(all_index, 1);
                }
            }
        },
        checkPlatform() {
            // Check function to notify the user when no platform is selected
            if (this.doc.platform.length == 0) {
                this.notifyDanger('Missing value', 'No value for platform selected. Please select one or more platforms.');
            }
        },
        checkSystemNotInUse(system) {
            let inUse = false;
            for (let i = 0; i < this.doc.data_sources.length; i++) {
                for (let j = 0; j < this.doc.data_sources[i].data_source.length; j++) {
                    for (let k = 0; k < this.doc.data_sources[i].data_source[j].applicable_to.length; k++) {
                        if(this.doc.data_sources[i].data_source[j].applicable_to[k] == system){
                            inUse = true;
                        }
                    }
                }
            }
            return !inUse;
        },
        removeApplicableToFromDataSources(name) {
            for (let i = 0; i < this.doc.data_sources.length; i++) {
                for (let j = 0; j < this.doc.data_sources[i].data_source.length; j++) {
                    for (let k = 0; k < this.doc.data_sources[i].data_source[j].applicable_to.length; k++) {
                        if(this.doc.data_sources[i].data_source[j].applicable_to[k] == name){
                            this.doc.data_sources[i].data_source[j].applicable_to.splice(k, 1);

                            if(this.doc.data_sources[i].data_source[j].applicable_to.length == 0){
                                this.doc.data_sources[i].data_source[j].applicable_to.push('all');
                            }
                            break;
                        }
                    }
                }
            }
        },
        updateNameApplicableToForDataSources(old_name, new_name) {
            for (let i = 0; i < this.doc.data_sources.length; i++) {
                for (let j = 0; j < this.doc.data_sources[i].data_source.length; j++) {
                    for (let k = 0; k < this.doc.data_sources[i].data_source[j].applicable_to.length; k++) {
                        if(this.doc.data_sources[i].data_source[j].applicable_to[k] == old_name){
                            this.doc.data_sources[i].data_source[j].applicable_to[k] = new_name;
                            break;
                        }
                    }
                }
            }
        }
    },
    components: {
        ExtendedTextarea,
        ListEditorExtended
    },
};
</script>

<style></style>
