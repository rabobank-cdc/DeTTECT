<template>
    <div>
        <div class="row">
            <div class="col-md-auto pr-md-0">
                <label class="card">{{ title }}</label>
            </div>
        </div>
        <div class="row form-group" v-if="group[itemIdName].length > 0">
            <span class="attack-span" v-for="id in group[itemIdName]" v-bind:key="id">
                <p class="attack-id">{{ id }}</p>
                <i class="tim-icons icon-trash-simple icon-color mx-md-2 cursor-pointer" :id="id" @click="deleteItem($event)"></i>
            </span>
        </div>
        <div class="row">
            <div class="col-md-7 pr-md-0 form-group">
                <vue-simple-suggest
                    :placeholder="formattedTitle"
                    :list="filteredSuggestionList"
                    :max-suggestions="0"
                    :filter-by-query="true"
                    display-attribute="autosuggest"
                    :value-attribute="valueAttr"
                    @select="newID = $event[itemIdName]"
                    @input="newID = $event"
                    :styles="autoCompleteStyle"
                    ref="suggestInputTxt"
                ></vue-simple-suggest>
            </div>
            <div class="col">
                <button class="btn-custom btn btn-secondary button-add" @click="addItem">Add</button>
            </div>
        </div>
    </div>
</template>

<script>
import { autoSuggestMixins } from '@/mixins/AutoSuggestMixins.js';
import { notificationMixin } from '@/mixins/NotificationMixins.js';

export default {
    data() {
        return {
            newID: ''
        };
    },
    mixins: [autoSuggestMixins, notificationMixin],
    props: {
        group: {
            type: Object,
            required: true
        },
        valueAttr: {
            type: String,
            required: true
        },
        platforms: {
            type: Array,
            required: true
        }
    },
    methods: {
        deleteItem(event) {
            // remove an item (technique or software ID) from the list
            let id = event.target.getAttribute('id');
            if (id.startsWith('T')) {
                let idx = this.group.technique_id.indexOf(id);
                this.group.technique_id.splice(idx, 1);
            } else if (id.startsWith('S')) {
                let idx = this.group.software_id.indexOf(id);
                this.group.software_id.splice(idx, 1);
            }
        },
        addItem() {
            // Add an item (technique or software ID) to the list

            // empty entries are ignored
            if (!this.newID.length > 0) {
                return;
            }
            // performs two checks for a valid ID, and exit if not valid
            if (!this.newID.match(/\b(S\d{4}|T\d{4}(\.\d{3}|))\b/i)) {
                this.notifyInvalid(this.newID);
                return;
            }
            let id = this.newID.match(/\b((S\d{4}|T\d{4}(\.\d{3}|)))\b/i)[0].toUpperCase();
            if ((this.itemIdName == 'technique_id' && !id.startsWith('T')) || (this.itemIdName == 'software_id' && !id.startsWith('S'))) {
                this.notifyInvalid(id);
                return;
            }
            // check for duplicate entries, and exit if duplicate
            if (this.group[this.itemIdName].includes(id)) {
                let title = 'Duplicate ' + this.formattedTitle;
                let msg = 'The ' + this.formattedTitle + ' ' + id + ' is already part of the YAML file. Duplicate entries are not allowed.';
                this.notifyWarning(title, msg);
                return;
            }
            // check if the ID is part of ATT&CK and applicable to any of the selected platforms (does not exit)
            if (!this.listKnownIDs.includes(id)) {
                let title = 'Unknown ' + this.formattedTitle;
                let msg = 'The ' + this.formattedTitle + ' ' + id + ' is not part of ATT&CK.';
                this.notifyWarning(title, msg);
            } else if (!this.listKnownIDsForPlatform.includes(id)) {
                let title = 'Non-applicable ' + this.formattedTitle;
                let msg = 'The ' + this.formattedTitle + ' ' + id + ' is not applicable to any of the selected platform(s).';
                this.notifyWarning(title, msg);
            }
            this.$refs.suggestInputTxt.setText('');
            this.group[this.itemIdName].push(id);
        },
        notifyInvalid(id) {
            let title = 'Invalid ' + this.formattedTitle;
            let msg = "'" + id + "' is an invalid " + this.formattedTitle + '.';
            this.notifyWarning(title, msg);
        }
    },
    computed: {
        filteredSuggestionList() {
            // returns a filtered list of IDs which are not part of any of the selected platforms, and which are not already part of the YAML file
            let tmpList = [];

            for (let i = 0; i < this.suggestionList.length; i++) {
                if (
                    this.platforms[0] == 'all' ||
                    (this.platforms.some((item) => this.suggestionList[i]['platforms'].includes(item)) &&
                        !this.group[this.itemIdName].includes(this.suggestionList[i][this.itemIdName]))
                ) {
                    tmpList.push(this.suggestionList[i]);
                }
            }
            return tmpList;
        },
        formattedTitle() {
            return this.itemIdName.replace('_', ' ').replace('id', 'ID');
        }
    }
};
</script>
