import Vue from 'vue';
import Router from 'vue-router';
import Layout from '../layout/Layout.vue';
import HomePage from '../pages/HomePage.vue';
import DataSourcesPage from '../pages/DataSourcesPage.vue';
import TechniquesPage from '../pages/TechniquesPage.vue';
import GroupsPage from '../pages/GroupsPage.vue';

Vue.use(Router);

export default new Router({
  routes: [
    {
      path: "/",
      component: Layout,
      redirect: "/home",
      children: [
        {
          path: "home",
          name: "home",
          component: HomePage
        },
        {
          path: "datasources",
          name: "datasources",
          component: DataSourcesPage
        },
        {
          path: "techniques",
          name: "techniques",
          component: TechniquesPage
        },
        {
          path: "groups",
          name: "groups",
          component: GroupsPage
        }
      ]
    }
  ]
});
