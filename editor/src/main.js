/*
 =========================================================
 * Vue Black Dashboard - v1.1.0
 =========================================================

 * Product Page: https://www.creative-tim.com/product/black-dashboard
 * Copyright 2018 Creative Tim (http://www.creative-tim.com)

 =========================================================

 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

 */
import Vue from 'vue';
import VueRouter from 'vue-router';
import RouterPrefetch from 'vue-router-prefetch';
import App from './App';
import router from './router/router';
import SmartTable from 'vuejs-smart-table';
import VueResource from 'vue-resource';
import VueShowdown from 'vue-showdown';
import Tooltip from 'vue-directive-tooltip';
import { BootstrapVue, BootstrapVueIcons } from 'bootstrap-vue';

import BlackDashboard from './plugins/blackDashboard';
Vue.use(BlackDashboard);
Vue.use(VueRouter);
Vue.use(RouterPrefetch);
Vue.use(SmartTable);
Vue.use(VueResource);
Vue.use(VueShowdown, {
    options: {
        openLinksInNewWindow: true,
        tables: true
    }
});
Vue.use(Tooltip);
Vue.use(BootstrapVue);
Vue.use(BootstrapVueIcons);

/* eslint-disable no-new */
new Vue({
    router,
    render: (h) => h(App)
}).$mount('#app');
