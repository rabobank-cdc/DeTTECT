<template>
    <div class="card" v-if="dataSource != null">
        <auto-suggest-title
            title="Data source"
            :item="dataSource"
            itemIdName="data_source_name"
            :allItems="allDataSources"
            :suggestionList="dataSourceSuggestionList"
            :navigateItem="navigateItem"
        ></auto-suggest-title>
        <applicable-to-collapse-data-sources
            :dataSource="dataSource"
            :allSystems="allSystems"
            helpText="..."
            :dqHelpText="dqHelpText"
            :dsHelpText="dsHelpText"
            :prevDataSourceQuality="prevDataSourceQuality"
            ref="collapseDataSourceComponent"
        ></applicable-to-collapse-data-sources>
    </div>
</template>

<script>
import ApplicableToCollapseDataSources from '@/components/Inputs/ApplicableToCollapseDataSources';
import AutoSuggestTitle from '@/components/Inputs/AutoSuggestTitle';
import Icons from '@/components/Icons';
import dataSources from '@/data/data_sources';
import customDataSources from '@/data/custom_data_sources';
import { pageDetailMixin } from '../mixins/PageDetailMixins.js';
import _ from 'lodash';

export default {
    data() {
        return {
            dataSourceSuggestionList: dataSources.concat(customDataSources).sort()
        };
    },
    mixins: [pageDetailMixin],
    props: {
        dataSource: {
            type: Object,
            required: true
        },
        allDataSources: {
            type: Array,
            required: true
        },
        dqHelpText: {
            type: String,
            required: true
        },
        dsHelpText: {
            type: String,
            required: true
        },
        prevDataSourceQuality: {
            type: Array,
            required: true
        },
        navigateItem: {
            type: Function,
            required: true
        },
        allSystems: {
            type: Array,
            required: true
        }
    },
    methods: {
        closeAllCollapses() {
            this.$refs.collapseDataSourceComponent.closeAllCollapses();
        },
    },
    components: {
        AutoSuggestTitle,
        Icons,
        ApplicableToCollapseDataSources
    }
};
</script>
