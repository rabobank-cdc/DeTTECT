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
        <div v-if="suggestionList.length == 0">
            <!-- eslint-disable-next-line vue/require-v-for-key -->
            <div class="row" v-for="(item, index) in list">
                <div class="col-md-10 pr-md-0">
                    <base-input
                        :value="item"
                        :idx="index"
                        :key="index"
                        @change="updateItem(item, $event)"
                        :showError="isErrorFunction(item, list)"
                        :errorText="getErrorText(item, list)"
                    ></base-input>
                </div>
                <div class="col mt-md-1">
                    <i class="tim-icons icon-trash-simple icon-color icon-padding cursor-pointer" :idx="index" @click="deleteItem($event)"></i>
                </div>
            </div>
            <div class="row">
                <div class="col-md-10 pr-md-0 form-group">
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
        <div v-else>
            <!-- eslint-disable-next-line vue/require-v-for-key -->
            <div class="row" v-for="(item, index) in list">
                <div class="col-md-10 pr-md-0 form-group customAutoCompletestyleInput">
                    <vue-simple-suggest
                        :list="suggestionListIncludingDefault"
                        :max-suggestions="0"
                        :filter-by-query="true"
                        :styles="autoCompleteStyle"
                        @select="selectedItemFromListChangeValue(item, $event, index)"
                        ref="suggestListVue"
                    >
                        <base-input
                            :value="item"
                            :idx="index"
                            :key="index"
                            @change="updateItem(item, $event)"
                            :showError="isErrorFunction(item, list)"
                            :errorText="getErrorText(item, list)"
                        ></base-input>
                    </vue-simple-suggest>
                </div>
                <div class="col mt-md-1">
                    <i class="tim-icons icon-trash-simple icon-color icon-padding cursor-pointer" :idx="index" @click="deleteItem($event)"></i>
                </div>
            </div>
            <div class="row">
                <div class="col-md-10 pr-md-0 form-group customAutoCompletestyleInputWithIcon">
                    <vue-simple-suggest
                        :list="suggestionListIncludingDefault"
                        :max-suggestions="0"
                        :filter-by-query="true"
                        :styles="autoCompleteStyle"
                        @select="selectedItemFromListNewValue"
                        @blur="addItem"
                        ref="suggestListVue"
                    >
                        <base-input
                            :placeholder="placeholder"
                            v-model="newItem"
                            @keyup.enter="addItemSuggestList"
                            addonLeftIcon="tim-icons icon-simple-add"
                            ref="suggestListInput"
                        ></base-input>
                    </vue-simple-suggest>
                </div>
            </div>
        </div>
    </div>
</template>
<script>
import Icons from '@/components/Icons';
import VueSimpleSuggest from 'vue-simple-suggest';
import 'vue-simple-suggest/dist/styles.css';
import { notificationMixin } from '@/mixins/NotificationMixins.js';

export default {
    data() {
        return {
            // eslint-disable-next-line no-undef
            caseInsensitive: require('case-insensitive'),
            newItem: '',
            autoCompleteStyle: {
                defaultInput: 'autocomplete-input',
                suggestions: 'autocomplete-result',
                suggestItem: 'autocomplete-suggest'
            }
        };
    },
    mixins: [notificationMixin],
    components: {
        Icons,
        VueSimpleSuggest
    },
    computed: {
        suggestionListIncludingDefault: function () {
            return [...new Set([this.defaultValue].concat(this.suggestionList))];
        }
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
        suggestionList: {
            type: Array,
            required: false,
            default: () => []
        },
        defaultValue: {
            type: String,
            required: false,
            default: 'all'
        },
        defaultValueExclusive: {
            type: Boolean,
            required: false,
            default: false
        },
        isErrorFunction: {
            type: Function,
            required: false,
            default: () => false
        },
        errorText: {
            type: String,
            required: false,
            default: ''
        }
    },
    methods: {
        selectedItemFromListNewValue(value) {
            this.newItem = value;
            this.$refs.suggestListInput.focus();
        },
        selectedItemFromListChangeValue(item, value, index) {
            if (
                item.toLowerCase() != value.toLowerCase() &&
                (this.caseInsensitive(this.list).includes(value) || this.caseInsensitive(this.externalListToValidate).includes(value))
            ) {
                this.notifyDuplicate(value);
            } else if (value != '') {
                this.$set(this.list, index, value);
            }
        },
        addItemKeyboard(event) {
            this.addItem(event.target.value);
        },
        addItem() {
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
        addItemSuggestList() {
            if (this.$refs.suggestListVue.hovered == null) {
                this.addItem();
            }
        },
        updateItem(item, event) {
            // called when an item in the list is changed
            let value = event.target.value;
            if (
                item.toLowerCase() != value.toLowerCase() &&
                (this.caseInsensitive(this.list).includes(value) || this.caseInsensitive(this.externalListToValidate).includes(value))
            ) {
                this.notifyDuplicate(value);
            } else if (value != '') {
                this.$set(this.list, event.target.getAttribute('idx'), value);
            }
        },
        deleteItem(event) {
            // remove an item from the list
            let index = event.target.getAttribute('idx');
            this.list.splice(index, 1);
        },
        notifyDuplicate(keyName) {
            let title = 'Duplicate value';
            let msg = this.notifyText.replace('KEYNAME', keyName);
            this.notifyWarning(title, msg);
        },
        getErrorText(item, list) {
            if (this.isErrorFunction(item, list)) {
                return this.errorText;
            } else {
                return '';
            }
        }
    }
};
</script>
