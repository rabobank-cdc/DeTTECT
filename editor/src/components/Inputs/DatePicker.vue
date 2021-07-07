<template>
    <div class="form-group">
        <label v-if="showLabel" class="card">{{ name }}</label>
        <datepicker
            :key="id"
            :value="date"
            @selected="updateDate"
            format="yyyy-MM-dd"
            :monday-first="true"
            :typeable="true"
            input-class="form-control"
        ></datepicker>
    </div>
</template>

<script>
import Datepicker from 'vuejs-datepicker';
import moment from 'moment';

export default {
    props: {
        date: {
            type: [String, Date],
            default: ''
        },
        name: {
            type: String,
            required: true
        },
        showLabel: {
            type: Boolean,
            required: false,
            default: true
        },
        id: {
            type: String,
            required: true
        }
    },
    methods: {
        updateDate(event) {
            // emit an event when the date changes and make sure the format is ok
            let tmpDate = moment(event, 'DD/MM/YYYY').format('YYYY-MM-DD');
            if (tmpDate != 'Invalid date') {
                this.$emit('dateUpdated', tmpDate);
            }
        }
    },
    components: {
        Datepicker
    }
};
</script>
