<template>
    <div>
        <div class="row">
            <div class="col-md-auto pr-md-0">
                <h5 class="title">Custom key-value pairs</h5>
            </div>
            <div class="col ml-md-0">
                <icons
                    icon="help"
                    tooltip="It's possible to have custom key-value pairs in your YAML file. The Editor supports numbers and string for the value."
                ></icons>
            </div>
            <div v-if="useInModal" class="col">
                <button type="button" aria-label="Close" class="close" @click="$bvModal.hide(modalId)">×</button>
            </div>
        </div>
        <div class="row">
            <div class="col-md-4">
                <label class="card">Key</label>
            </div>
            <div class="col-md-5">
                <label class="card">Value</label>
            </div>
        </div>
        <div v-for="(v, k, index) in item" :key="index">
            <div class="row" v-if="!defaultKeys.includes(k)">
                <div class="col-md-4 pr-md-0">
                    <base-input :value="k" @change="updateKey(k, $event)"></base-input>
                </div>
                <div class="col-md-6">
                    <base-input :value="item[k]" @change="updateValue(k, $event)"></base-input>
                </div>
                <div class="col-md-0 mt-md-1">
                    <i class="tim-icons icon-trash-simple icon-color icon-padding cursor-pointer" @click="deleteProperty(k)"></i>
                </div>
            </div>
        </div>
        <div class="row">
            <div class="col-md-4 pr-md-0">
                <base-input v-model="newKey" placeholder="key" @keyup.enter="addProperty" addonLeftIcon="tim-icons icon-simple-add"></base-input>
            </div>
            <div class="col-md-6">
                <base-input v-model="newValue" placeholder="value" @keyup.enter="addProperty" @keydown.tab="addProperty" @blur="addProperty" addonLeftIcon="tim-icons icon-simple-add"></base-input>
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
            newKey: '',
            newValue: '',
            // eslint-disable-next-line no-undef
            caseInsensitive: require('case-insensitive')
        };
    },
    mixins: [notificationMixin],
    components: {
        Icons
    },
    props: {
        item: {
            type: Object,
            required: true
        },
        defaultKeys: {
            type: Array,
            required: true
        },
        useInModal: {
            type: Boolean,
            required: false,
            default: false
        },
        modalId: {
            type: String,
            required: false,
            default: ''
        }
    },
    methods: {
        updateKey(oldKey, event) {
            // update the name of the key for the custom key-value pair
            let newKey = event.target.value;
            if (this.isKeyAllowed(newKey)) {
                this.$set(this.item, newKey, this.item[oldKey]);
                this.$delete(this.item, oldKey);
            }
        },
        updateValue(key, event) {
            // update the value of a custom key-value pair
            this.item[key] = event.target.value;
        },
        deleteProperty(key) {
            // delete a custom key-value pair
            this.$delete(this.item, key);
        },
        addProperty() {
            // add a new custom key-value pair
            if (this.newKey != '' && this.isKeyAllowed(this.newKey)) {
                this.$set(this.item, this.newKey, this.newValue);
                this.newKey = '';
                this.newValue = '';
            }
        },
        isKeyAllowed(key) {
            // check to see if the name of the key is not part of the default key-value pair names
            if (this.caseInsensitive(this.defaultKeys).includes(key)) {
                let title = 'Reserved key';
                let msg = "The key '" + key + "' is not allowed for a custom key-value pair.";
                this.notifyWarning(title, msg);
                return false;
            }
            if (this.caseInsensitive(Object.keys(this.item)).includes(key)) {
                let title = 'Duplicate key';
                let msg = "The key '" + key + "' is already part of the YAML file. Duplicate entries are not allowed.";
                this.notifyWarning(title, msg);
                return false;
            }
            return true;
        }
    }
};
</script>
