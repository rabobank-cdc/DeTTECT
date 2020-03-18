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

export default {
    mixins: [notificationMixin],
    props: {
        filename: {
            type: String,
            required: true
        },
        doc: {
            type: Object,
            required: true
        },
        platforms: {
            type: Array,
            required: true
        },
        showName: {
            type: Boolean,
            required: false,
            default: true
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
        }
    }
};
</script>

<style></style>
