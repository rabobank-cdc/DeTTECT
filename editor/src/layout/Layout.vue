<template>
  <div class="wrapper">
    <side-bar>
      <template slot="links">
        <sidebar-link to="/home" :name="'Home'" icon="tim-icons icon-bank"/>
        <sidebar-link to="/datasources" :name="'Data sources'" icon="tim-icons icon-coins"/>
        <sidebar-link to="/techniques" :name="'Techniques'" icon="tim-icons icon-zoom-split"/>
        <sidebar-link to="/groups" :name="'Groups'" icon="tim-icons icon-single-02"/>
      </template>
    </side-bar>
    <div class="main-panel">
      <dashboard-content @click.native="toggleSidebar">
      </dashboard-content>
      <content-footer></content-footer>
    </div>
  </div>
</template>
<style lang="scss">
</style>
<script>
  import ContentFooter from "./Footer.vue";
  import DashboardContent from "./Content.vue";
  export default {
    components: {
      ContentFooter,
      DashboardContent
    },
    methods: {
      toggleSidebar() {
        if (this.$sidebar.showSidebar) {
          this.$sidebar.displaySidebar(false);
        }
      }
    }
  };
</script>

<style>

</style>