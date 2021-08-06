<template>
    <div>
        <!-- eslint-disable-next-line vue/require-v-for-key -->
        <div class="row" v-for="(item, index) in list">
            <div class="col-md-3 pr-md-0">
                <base-input :value="item.applicable_to" @change="updateItem($event, index)"></base-input>
            </div>
            <div class="col-md-8 mt-md-0">
                <b-form-group>
                    <b-form-tags
                        input-id="tags-validation"
                        v-model="item.platform"
                        :input-attrs="{ 'aria-describedby': 'tags-validation-help' }"
                        :tag-validator="validator"
                        separator=""
                        :placeholder="'Enter ' +subject_text"
                        :invalid-tag-text="'Invalid ' +subject_text"
                        :duplicate-tag-text="'Duplicate ' +subject_text"
                        input-class="platform-chooser-input"
                        :remove-on-delete="true"
                        @input="checkInput($event,index)"
                    >
                    </b-form-tags>

                    <template #invalid-feedback>
                        You must provide at least 1 platform.
                    </template>

                    <template #description>
                        <div id="tags-validation-help">
                        Options: {{ values.join(', ') }}
                        </div>
                    </template>
                </b-form-group>
            </div>
            <div class="col mt-md-1">
                <i class="tim-icons icon-trash-simple icon-color icon-padding cursor-pointer" @click="deleteItem($event, index)"></i>
            </div>
        </div>
        <div class="row">
            <div class="col-md-3 pr-md-0 form-group">
                <base-input :placeholder="placeholder" v-model="newItem" @keyup.enter="addItem" @blur="addItem" addonLeftIcon="tim-icons icon-simple-add"></base-input>
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
        Icons,
    },
    props: {
        list: {
            type: Array,
            required: true,
        },
        name: {
            type: String,
            required: true,
        },
        placeholder: {
            type: String,
            required: true,
        },
        helpText: {
            type: String,
            default: '',
        },
        notifyText: {
            type: String,
            required: false,
            default: "The value 'KEYNAME' is already part of the list. Duplicate entries are not allowed.",
        },
        values: {
            type: Array,
            required: true,
        },
        valuesConversion: {
            type: Object,
            required: true
        },
        subject_text: {
            type: String,
            required: true
        }
    },
    methods: {
        addItem() {
            // add an item to the list
            let applicable_to_values = this.list.map(value => value.applicable_to);
            if (this.caseInsensitive(applicable_to_values).includes(this.newItem)) {
                this.notifyDuplicate(this.newItem);
            } else if (this.newItem != '') {
                this.list.push({'applicable_to': this.newItem, 'platform': ['all']});
                this.newItem = '';
            }
        },
        updateItem(event, index) {
            // called when an item in the list is changed
            let applicable_to_values = this.list.map(value => value.applicable_to);
            let value = event.target.value;
            if (this.caseInsensitive(applicable_to_values).includes(value)) {
                this.notifyDuplicate(value);
            } else if (value != '') {
                this.list[index].applicable_to = value;
            }
        },
        deleteItem(event, index) {
            // remove an item from the list
            this.list.splice(index, 1);
            if(this.list.length == 0){
                this.list.push({'applicable_to': 'Systems', 'platform': ['all']})
            }
        },
        notifyDuplicate(keyName) {
            let title = 'Duplicate value';
            let msg = this.notifyText.replace('KEYNAME', keyName);
            this.notifyWarning(title, msg);
        },
        validator(value) {
            return this.values.map(value => value.toLowerCase()).includes(value.toLowerCase()) || value == 'all';
        },
        checkInput(event, index) {
            if(this.list[index].platform.length == 0) {
                this.list[index].platform = ['all'];
            }
            else if(this.list[index].platform[this.list[index].platform.length-1] == 'all') {
                this.list[index].platform = ['all'];
            }
            else {
                for (let i=0; i < this.list[index].platform.length; i++) {
                    this.list[index].platform[i] = this.valuesConversion[this.list[index].platform[i].toLowerCase()];
                }
            }
        }
    },
};
</script>
