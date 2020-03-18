<template>
    <div class="form-group">
        <div v-if="showLabel" :class="getDivStyleClass()">
            <div class="col-md-auto pr-md-0">
                <label class="card">{{ name }}</label>
            </div>
            <div v-if="helpText != ''" class="col ml-md-0">
                <icons icon="help" :tooltip="helpText"></icons>
            </div>
        </div>
        <div class="row toggle-button">
            <div class="col-md-auto">
                <toggle-button
                    :value="state"
                    :sync="true"
                    @change="switchButton"
                    :labels="{ checked: 'Yes', unchecked: 'No' }"
                    :font-size="14"
                    :height="30"
                    :width="95"
                    :color="{
                        checked: '#00bf9a',
                        unchecked: '#ff8d72',
                        disabled: '#CCCCCC'
                    }"
                />
            </div>
        </div>
    </div>
</template>

<script>
import Icons from '@/components/Icons';

import { ToggleButton } from 'vue-js-toggle-button';
export default {
    props: {
        state: {
            type: Boolean,
            default: false
        },
        name: {
            type: String,
            required: true
        },
        helpText: {
            type: String,
            default: ''
        },
        showLabel: {
            type: Boolean,
            required: false,
            default: true
        },
        extraPaddingBottom: {
            type: Boolean,
            required: false,
            default: true
        }
    },
    methods: {
        // emit an event when the value of the toggle is changed
        switchButton(event) {
            this.$emit('toggleButtonUpdated', event.value);
        },
        getDivStyleClass() {
            if (this.extraPaddingBottom) {
                return 'row pb-md-2';
            } else {
                return 'row';
            }
        }
    },
    components: {
        ToggleButton,
        Icons
    }
};
</script>
