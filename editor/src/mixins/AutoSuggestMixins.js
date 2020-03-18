import VueSimpleSuggest from 'vue-simple-suggest';
import 'vue-simple-suggest/dist/styles.css';

export const autoSuggestMixins = {
    data() {
        return {
            autoCompleteStyle: {
                defaultInput: 'autocomplete-input',
                suggestions: 'autocomplete-result',
                suggestItem: 'autocomplete-suggest'
            }
        };
    },
    props: {
        title: {
            type: String,
            required: true
        },
        // technique_id, oftware_id, data_source_name
        itemIdName: {
            type: String,
            required: true
        },
        suggestionList: {
            type: Array,
            required: true
        }
    },
    computed: {
        listKnownIDs() {
            // returns all IDs from within the suggestion list for the key that's equal to 'itemIdName'
            return this.suggestionList.map(a => a[this.itemIdName]);
        },
        listKnownIDsForPlatform() {
            // list of all IDs (technique or software ID) applicable to any of the selected platforms
            let tmpList = [];

            for (let i = 0; i < this.suggestionList.length; i++) {
                if (this.platforms[0] == 'all' || this.platforms.some(item => this.suggestionList[i]['platforms'].includes(item))) {
                    tmpList.push(this.suggestionList[i]);
                }
            }
            return tmpList.map(a => a[this.itemIdName]);
        }
    },
    components: {
        VueSimpleSuggest
    }
};
