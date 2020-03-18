<template>
    <div class="form-group">
        <label v-if="showLabel" class="card">{{ name }}</label>
        <vue-slider
            :value="score"
            @change="updateScore"
            dotSize="18"
            :data="markData"
            :tooltip-formatter="val => markDataTooltip[val]"
            :marks="true"
            :useKeyboard="true"
            :tooltypeStyle="{ 'background-color': '#419EF9', 'border-color': '#419EF9' }"
            :processStyle="{ 'background-color': '#419EF9' }"
            :labelStyle="{ color: 'rgb(255, 255, 255, 0.8)' }"
        ></vue-slider>
    </div>
</template>

<script>
import VueSlider from 'vue-slider-component';
import 'vue-slider-component/theme/default.css';

export default {
    props: {
        score: {
            type: Number,
            required: true
        },
        markData: {
            type: Array,
            required: true
        },
        markDataTooltip: {
            type: Object,
            required: true
        },
        name: {
            type: String,
            required: true
        },
        showLabel: {
            type: Boolean,
            required: false,
            default: true
        }
    },
    methods: {
        // emit an event when the score is updated
        updateScore(event) {
            this.$emit('scoreUpdated', event);
        }
    },
    components: {
        VueSlider
    }
};
</script>
