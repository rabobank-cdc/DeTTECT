<template>
    <div>
        <div class="container-fluid d-flex flex-column">
            <div v-if="isNewItem || editItem">
                <div class="row">
                    <div class="col-md-auto pr-md-0 pl-md-0 margin-top-8">
                        <label>{{ title }}</label>
                    </div>
                    <vue-simple-suggest
                        :value="item[itemIdName]"
                        :list="filteredSuggestionList"
                        :max-suggestions="0"
                        :filter-by-query="true"
                        :display-attribute="displayAttr"
                        :value-attribute="valueAttr"
                        @input="tmpItemId = $event"
                        @blur="setItemIdValue"
                        :styles="autoCompleteStyle"
                        class="col-md-7 pl-md-2 pr-md-0"
                    ></vue-simple-suggest>
                    <i class="tim-icons icon-check-2 icon-color icon-padding cursor-pointer" id="checkmark" @click="setItemIdValue"></i>
                </div>
            </div>
            <div v-else class="row flex-fill">
                <div class="col-md pr-md-0 pl-md-0">
                    <span v-if="itemTitle" id="detailCard" class="card-title">{{ item[itemTitle.id] + ' - ' + item[itemTitle.name] }}</span>
                    <span v-else id="detailCard" class="card-title">{{ item[itemIdName] }}</span>
                    <i class="tim-icons icon-pencil icon-color icon-padding cursor-pointer" @click="editItem = true"></i>
                    <span v-if="itemTitle" style="margin-left: 15px; font-size: 8pt"
                        ><a :href="'https://attack.mitre.org/techniques/' + item[itemTitle.id].replace('.', '/')" target="_blank"
                            >Open on ATT&amp;CK website</a
                        ></span
                    >
                </div>
                <div>
                    <label @click="navigateItem(false)" class="cursor-pointer" :title="'Previous ' + title.toLowerCase()">
                        <icons icon="arrow-up"></icons>
                    </label>
                    <label @click="navigateItem(true)" class="cursor-pointer" :title="'Next ' + title.toLowerCase()">
                        <icons icon="arrow-down"></icons>
                    </label>
                </div>
            </div>
        </div>
    </div>
</template>

<script>
import { autoSuggestMixins } from '@/mixins/AutoSuggestMixins.js';
import { notificationMixin } from '@/mixins/NotificationMixins.js';
import Icons from '@/components/Icons';

export default {
    data() {
        return {
            // eslint-disable-next-line no-undef
            caseInsensitive: require('case-insensitive'),
            tmpItemId: null,
            checkBoxClicked: false,
            editItem: false
        };
    },
    components: { Icons },
    mixins: [autoSuggestMixins, notificationMixin],
    props: {
        item: {
            type: Object,
            required: true
        },
        allItems: {
            type: Array,
            required: true
        },
        // expects an object with the following properties that are also part of the item Object
        //  - id (e.g. technique_id)
        //  - name (e.g. technique_name)
        itemTitle: {
            type: Object,
            default: null
        },
        valueAttr: {
            type: String,
            default: ''
        },
        displayAttr: {
            type: String,
            default: ''
        },
        isAttackEntity: {
            type: Boolean,
            default: false
        },
        platforms: {
            type: Array,
            default: null
        },
        notifyText: {
            type: String,
            required: false,
            default: "'ID' is an invalid TITLE."
        },
        navigateItem: {
            type: Function,
            required: true
        }
    },
    watch: {
        item() {
            // This makes sure to disable the edit 'box' when the user selects a new item in the table on the left.
            // (such as a data source or ATT&CK technique)
            this.editItem = false;
        }
    },
    methods: {
        getAttackEntityName(lookupId, keyId, keyName) {
            // Lookup the name of an ATT&CK entity that machteas the provided lookupId.
            // E.g. lookup the technique_name that belongs to a technique_id
            for (let i = 0; i < this.suggestionList.length; i++) {
                if (this.suggestionList[i][keyId] == lookupId) {
                    return this.suggestionList[i][keyName];
                }
            }
            return '';
        },
        // set a item ID value for 'item':
        // data_source_name  OR  technique_id and technique_name
        setItemIdValue(event) {
            // When the item is an entity in ATT&CK CTI (currently only techniques are supported), the below is handled differently
            if (this.isAttackEntity) {
                // empty values are ignored
                if (!this.tmpItemId.length > 0) {
                    return;
                }
                // performs two checks for a valid ID, and exit if not valid
                if (!this.tmpItemId.match(/\bT\d{4}(\.\d{3}|)\b/i)) {
                    if (event.target.id != 'checkmark') {
                        this.notifyInvalid(this.tmpItemId);
                    }
                    return;
                }
                let id = this.tmpItemId.match(/\b(T\d{4}(\.\d{3}|))\b/i)[0].toUpperCase();
                if (!id.startsWith('T')) {
                    if (event.target.id != 'checkmark') {
                        this.notifyInvalid(id);
                    }
                    return;
                }
                // check for duplicate entries, and exit if duplicate
                if (this.isDuplicateItem(id)) {
                    if (event.target.id != 'checkmark') {
                        let title = 'Duplicate ' + this.title.toLowerCase();
                        let msg =
                            'The ' +
                            this.title.toLowerCase() +
                            " '" +
                            id +
                            "' is already part of the YAML administration file. Duplicate entries are not allowed.";
                        this.notifyWarning(title, msg);
                    }
                    return;
                }
                // check if the ID is part of ATT&CK and applicable to any of the selected platforms (does not exit)
                if (!this.listKnownIDs.includes(id)) {
                    if (event.target.id != 'checkmark') {
                        let title = 'Unknown ' + this.title;
                        let msg = 'The ' + this.title + ' ' + id + ' is not part of ATT&CK.';
                        this.notifyWarning(title, msg);
                    }
                } else if (!this.listKnownIDsForPlatform.includes(id)) {
                    if (event.target.id != 'checkmark') {
                        let title = 'Non-applicable ' + this.title.toLowerCase();
                        let msg = 'The ' + this.title.toLowerCase() + ' ' + id + ' is not applicable to any of the selected platform(s).';
                        this.notifyWarning(title, msg);
                    }
                }

                this.item[this.itemIdName] = id;
                let name = this.getAttackEntityName(id, 'technique_id', 'technique_name');
                this.item['technique_name'] = name;

                this.tmpItemId = null;
                this.editItem = false;
            } else {
                if (this.tmpItemId != null && this.tmpItemId != '') {
                    // check for a duplicate item id value, if true exit
                    if (this.isDuplicateItem(this.tmpItemId)) {
                        if (event.target.id != 'checkmark') {
                            let title = 'Duplicate ' + this.title.toLowerCase();
                            let msg =
                                'The ' +
                                this.title.toLowerCase() +
                                " '" +
                                this.tmpItemId +
                                "' is already part of the YAML administration file. Duplicate entries are not allowed.";
                            this.notifyWarning(title, msg);
                        }
                        return;
                    }
                    if (!this.suggestionList.includes(this.tmpItemId)) {
                        if (event.target.id != 'checkmark') {
                            let title = 'Non-ATT&CK ' + this.title.toLowerCase();
                            let msg = 'The ' + this.title.toLowerCase() + " '" + this.tmpItemId + "' is not part of ATT&CK.";
                            this.notifyWarning(title, msg);
                        }
                    }
                    this.item[this.itemIdName] = this.tmpItemId;
                    this.tmpItemId = null;
                    this.editItem = false;
                }
            }
        },
        notifyInvalid(id) {
            let title = 'Invalid ' + this.title.toLowerCase();
            let msg = this.notifyText.replace('ID', id).replace('TITLE', this.title.toLowerCase());
            this.notifyWarning(title, msg);
        },
        isDuplicateItem(idValue) {
            // check if the item id value to be added/changed does not already exists within the YAML file
            if (
                this.caseInsensitive(this.allItemsIdValues).includes(idValue) &&
                !(this.editItem && this.caseInsensitive(this.item[this.itemIdName]).equals(idValue))
            ) {
                return true;
            } else {
                return false;
            }
        }
    },
    computed: {
        isNewItem() {
            return this.item[this.itemIdName] == '' ? true : false;
        },
        allItemsIdValues() {
            // get an array of all values within the 'allItems' for the key 'itemIdName'
            let idValueList = [];
            for (let i = 0; i < this.allItems.length; i++) {
                idValueList.push(this.allItems[i][this.itemIdName]);
            }
            return idValueList;
        },
        filteredSuggestionList() {
            // Returns a filtered list of IDs which are not part of any of the selected platforms, and which are not already part of the YAML file.
            // This will only execute if every item in the `suggestionList` contains a key-value pair 'platforms', which must be the case when 'platforms' is not null.
            // When platforms is null, it will do a basic check to make sure that items are not already part of the YAML file.
            if (this.platforms != null) {
                let tmpList = [];

                for (let i = 0; i < this.suggestionList.length; i++) {
                    if (
                        (this.platforms[0] == 'all' || this.platforms.some((item) => this.suggestionList[i]['platforms'].includes(item))) &&
                        !this.allItemsIdValues.includes(this.suggestionList[i][this.valueAttr])
                    ) {
                        tmpList.push(this.suggestionList[i]);
                    }
                }
                return tmpList;
            } else {
                let tmpList = [];
                for (let i = 0; i < this.suggestionList.length; i++) {
                    if (!this.allItemsIdValues.includes(this.suggestionList[i])) {
                        tmpList.push(this.suggestionList[i]);
                    }
                }
                return tmpList;
            }
        }
    }
};
</script>
