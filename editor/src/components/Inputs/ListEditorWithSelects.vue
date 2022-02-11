<template>
    <div>
        <div class="row">
            <div class="col-md-auto pr-md-0">
                <label class="card">{{ name }}</label>
            </div>
            <div v-if="helpText != ''" class="col ml-md-0 pb-md-2">
                <icons icon="help" :tooltip="helpText"></icons>
            </div>
        </div>
        <!-- eslint-disable-next-line vue/require-v-for-key -->
        <div class="row" v-for="(item, index) in list">
            <div class="col-md-10 pr-md-0">
                <base-input
                    readonly
                    :value="item"
                    :idx="index"
                    @change="updateItem($event)"
                    :showError="isErrorFunction(item, list)"
                    :errorText="getErrorTextFunction(item, list)"
                ></base-input>
            </div>
            <div class="col mt-md-1">
                <i class="tim-icons icon-trash-simple icon-color icon-padding cursor-pointer" :idx="index" @click="deleteItem($event)"></i>
            </div>
        </div>
        <div class="row">
            <div class="col-md-10 pr-md-0 form-group">
                <select class="form-control" v-model="newItem" @change="addItem">
                    <option v-if="defaultItem != null && includeDefaultItemInList">{{ defaultItem }}</option>
                    <option v-if="attributeName != ''" v-for="option in newItems">
                        {{ option[attributeName] }}
                    </option>
                    <option v-if="attributeName == ''" v-for="option in newItems">
                        {{ option }}
                    </option>
                </select>
            </div>
            <div class="col mt-md-1">
                <i class="tim-icons icon-simple-add icon-color icon-padding cursor-pointer" @click="addItem"></i>
            </div>
        </div>
    </div>
</template>
<script>
import Icons from '@/components/Icons';
import { notificationMixin } from '@/mixins/NotificationMixins.js';

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
        Icons
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
        externalListToValidate: {
            type: Array,
            default: () => []
        },
        notifyText: {
            type: String,
            required: false,
            default: "The value 'KEYNAME' is already part of the list. Duplicate entries are not allowed."
        },
        newItems: {
            type: Array,
            required: true
        },
        defaultItem: {
            type: String
        },
        includeDefaultItemInList: {
            type: Boolean,
            required: false,
            default: true
        },
        isErrorFunction: {
            type: Function,
            required: false,
            default: () => false
        },
        getErrorTextFunction: {
            type: Function,
            required: false,
            default: () => ''
        },
        attributeName: {
            type: String,
            required: false,
            default: ''
        },
        defaultValueExclusive: {
            type: Boolean,
            required: false,
            default: false
        }
    },
    methods: {
        addItem() {
            // add an item to the list
            if (this.defaultValueExclusive && this.newItem == 'all') {
                if (this.caseInsensitive(this.externalListToValidate).includes(this.newItem)) {
                    this.notifyDuplicate(this.newItem);
                } else {
                    this.list.splice(0, this.list.length);
                    this.list.push('all');
                    this.newItem = '';
                }
            } else {
                // add an item to the list
                if (
                    this.caseInsensitive(this.list).includes(this.newItem) ||
                    this.caseInsensitive(this.externalListToValidate).includes(this.newItem)
                ) {
                    this.notifyDuplicate(this.newItem);
                } else if (this.newItem != '') {
                    this.list.push(this.newItem);
                    this.newItem = '';

                    if (this.defaultValueExclusive && this.list.indexOf('all') >= 0) {
                        this.list.splice(this.list.indexOf('all'), 1);
                    }
                }
            }
        },
        updateItem(event) {
            // called when an item in the list is changed
            let value = event.target.value;
            if (this.caseInsensitive(this.list).includes(value) || this.caseInsensitive(this.externalListToValidate).includes(value)) {
                this.notifyDuplicate(value);
            } else if (value != '') {
                this.$set(this.list, event.target.getAttribute('idx'), value);
            }
        },
        deleteItem(event) {
            // remove an item from the list
            let index = event.target.getAttribute('idx');
            this.list.splice(index, 1);

            if (this.list.length == 0 && this.defaultItem != null) {
                this.list.push(this.defaultItem);
            }
        },
        notifyDuplicate(keyName) {
            let title = 'Duplicate value';
            let msg = this.notifyText.replace('KEYNAME', keyName);
            this.notifyWarning(title, msg);
        }
    }
};
</script>
