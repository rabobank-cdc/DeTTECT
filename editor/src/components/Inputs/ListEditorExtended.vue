<template>
    <div>
        <!-- eslint-disable-next-line vue/require-v-for-key -->
        <div class="row" v-for="(item, index) in list">
            <div class="col-md-3 pr-md-0">
                <base-input :value="item.applicable_to" @change="updateItem($event, index)"></base-input>
            </div>
            <div class="col mt-md-1">
                <i class="tim-icons icon-trash-simple icon-color icon-padding cursor-pointer" @click="deleteItem($event, index)"></i>
            </div>
            <div class="col-md-8 mt-md-0">
                <list-editor-with-selects
                    :list="item.platform"
                    :newItems="values"
                    :name="'Platforms:'"
                    placeholder="platform"
                    class="mt-md-2 systemsPlatformList"
                    notifyText="The value 'KEYNAME' is already part of the list. Duplicate entries are not allowed."
                    :isErrorFunction="isErrorFunction"
                    :getErrorTextFunction="getErrorText"
                    :defaultValueExclusive="true"
                    defaultItem="all"
                    :includeDefaultItemInList="false"
                ></list-editor-with-selects>
            </div>
        </div>
        <div class="row">
            <div class="col-md-3 pr-md-0 form-group">
                <base-input
                    :placeholder="placeholder"
                    v-model="newItem"
                    @keyup.enter="addItem"
                    @blur="addItem"
                    addonLeftIcon="tim-icons icon-simple-add"
                ></base-input>
            </div>
        </div>
    </div>
</template>
<script>
import Icons from '@/components/Icons';
import constants from '@/constants';
import { notificationMixin } from '@/mixins/NotificationMixins.js';
import ListEditorWithSelects from '@/components/Inputs/ListEditorWithSelects';

export default {
    data() {
        return {
            // eslint-disable-next-line no-undef
            caseInsensitive: require('case-insensitive'),
            newItem: ''
        };
    },
    mixins: [notificationMixin],
    components: {
        Icons,
        ListEditorWithSelects
    },
    props: {
        list: {
            type: Array,
            required: true
        },
        name: {
            type: String,
            required: true
        },
        placeholder: {
            type: String,
            required: true
        },
        helpText: {
            type: String,
            default: ''
        },
        notifyText: {
            type: String,
            required: false,
            default: "The value 'KEYNAME' is already part of the list. Duplicate entries are not allowed."
        },
        values: {
            type: Array,
            required: true
        },
        valuesConversion: {
            type: Object,
            required: true
        },
        subject_text: {
            type: String,
            required: true
        },
        reservedKeywords: {
            type: Array,
            required: false,
            default: () => []
        },
        postRemoveFunction: {
            type: Function,
            required: false
        },
        postUpdateFunction: {
            type: Function,
            required: false
        }
    },
    methods: {
        addItem() {
            // add an item to the list
            let applicable_to_values = this.list.map((value) => value.applicable_to);
            if (this.reservedKeywords.includes(this.newItem)) {
                this.notifyReservedKeyword(this.newItem);
                this.newItem = '';
            } else if (this.caseInsensitive(applicable_to_values).includes(this.newItem)) {
                this.notifyDuplicate(this.newItem);
                this.newItem = '';
            } else if (this.newItem != '') {
                this.list.push({ applicable_to: this.newItem, platform: ['all'] });
                this.newItem = '';
            }
        },
        updateItem(event, index) {
            // called when an item in the list is changed
            let applicable_to_values = this.list.map((value) => value.applicable_to);
            let value = event.target.value;
            if (this.caseInsensitive(applicable_to_values).includes(value)) {
                this.notifyDuplicate(value);
            } else if (value != '') {
                // call post update function:
                if (this.postUpdateFunction != undefined) {
                    this.postUpdateFunction(this.list[index].applicable_to, event.target.value);
                }

                this.list[index].applicable_to = value;
            }
        },
        deleteItem(event, index) {
            // don't remove the default item if it's the only item:
            if (this.list.length == 1 && this.list[0]['applicable_to'] == constants.YAML_OBJ_NEW_DATA_SOURCES_FILE['systems'][0]['applicable_to']) {
                return;
            }

            // call post remove function
            if (this.postRemoveFunction != undefined) {
                this.postRemoveFunction(this.list[index].applicable_to);
            }

            // remove an item from the list
            this.list.splice(index, 1);
            if (this.list.length == 0) {
                this.list.push(_.cloneDeep(constants.YAML_OBJ_NEW_DATA_SOURCES_FILE['systems'][0]));
            }
        },
        notifyDuplicate(keyName) {
            let title = 'Duplicate value';
            let msg = this.notifyText.replace('KEYNAME', keyName);
            this.notifyWarning(title, msg);
        },
        notifyReservedKeyword(keyName) {
            let title = 'Reserved keyword';
            let msg = "'" + keyName + "' is a reserved keyword. You cannot use this value.";
            this.notifyWarning(title, msg);
        },
        validator(value) {
            return this.values.map((value) => value.toLowerCase()).includes(value.toLowerCase()) || value == 'all';
        },
        checkInput(event, index) {
            if (this.list[index].platform.length == 0) {
                this.list[index].platform = ['all'];
            } else if (this.list[index].platform[this.list[index].platform.length - 1] == 'all') {
                this.list[index].platform = ['all'];
            } else {
                for (let i = 0; i < this.list[index].platform.length; i++) {
                    this.list[index].platform[i] = this.valuesConversion[this.list[index].platform[i].toLowerCase()];
                }
            }
        },
        isErrorFunction(item, list) {
            if (item == 'all' && list.length > 1) {
                return true;
            } else {
                return false;
            }
        },
        getErrorText(item, list) {
            if (item == 'all' && list.length > 1) {
                return "The value 'all' is exclusive for the system's platform values and can therefore not be combined with other platform values. Remove 'all' to let DeTT&CT work properly.";
            } else {
                return '';
            }
        }
    }
};
</script>
