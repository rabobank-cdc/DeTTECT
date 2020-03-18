<template>
  <table class="table tablesorter" :class="tableClass">
    <thead :class="theadClasses">
    <tr>
      <slot name="columns">
        <th v-for="column in columns" :key="column">{{column}}</th>
      </slot>
    </tr>
    </thead>
    <tbody :class="tbodyClasses">
    <tr v-for="(item, index) in data" :key="index">
      <slot :row="item">
        <td v-for="(column, index) in columns"
            :key="index"
            v-if="hasValue(item, column)">
          {{itemValue(item, column)}}
        </td>
        <td v-if="deleteButton"><i class="tim-icons icon-trash-simple"/></td>
      </slot>
    </tr>
    </tbody>
  </table>
</template>
<script>
  import moment from 'moment'
  export default {
    name: 'base-table',
    props: {
      deleteButton: Boolean,
      columns: {
        type: Array,
        default: () => [],
        description: "Table columns"
      },
      data: {
        type: Array,
        default: () => [],
        description: "Table data"
      },
      type: {
        type: String, // striped | hover
        default: "",
        description: "Whether table is striped or hover type"
      },
      theadClasses: {
        type: String,
        default: '',
        description: "<thead> css classes"
      },
      tbodyClasses: {
        type: String,
        default: '',
        description: "<tbody> css classes"
      }
    },
    computed: {
      tableClass() {
        return this.type && `table-${this.type}`;
      }
    },
    methods: {
      hasValue(item, column) {
        return item[column.toLowerCase()] !== "undefined";
      },
      itemValue(item, column) {
        let value = item[column.toLowerCase()];
        if(column.indexOf('.') >= 0){
          let splitted_col = column.split('.');
          value = item;
          splitted_col.forEach(function(s) {
            value = value[s];
          });
        }

        if(Array.isArray(value)){
          value = value.join(', ');
        }
        else if(value instanceof Date){
          // value = value;
          value = moment(value, 'DD/MM/YYYY').format('YYYY-MM-DD');
        }

        if(value == 'None') { value = '';}
        return value;
      }
    }
  };
</script>
<style>
</style>
