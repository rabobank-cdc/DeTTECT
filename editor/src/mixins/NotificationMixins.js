import NotificationTemplate from '@/pages/Notifications/NotificationTemplate';

export const notificationMixin = {
    data() {
        return {};
    },
    methods: {
        notifyInfo(title, message) {
            this.$notify({
                component: NotificationTemplate,
                icon: 'tim-icons icon-zoom-split',
                horizontalAlign: 'right',
                verticalAlign: 'top',
                type: 'info',
                timeout: 10000,
                title: title,
                message: message
            });
        },
        notifyInfoWithCallback(title, message, cb_function, cb_function_text, cb_function_key) {
            this.$notify({
                component: NotificationTemplate,
                icon: 'tim-icons icon-trash-simple',
                horizontalAlign: 'right',
                verticalAlign: 'top',
                type: 'info',
                timeout: 10000,
                title: title,
                message: message,
                cb_function: cb_function,
                cb_function_text: cb_function_text,
                cb_function_key: cb_function_key
            });
        },
        notifyDanger(title, message) {
            this.$notify({
                component: NotificationTemplate,
                icon: 'tim-icons icon-alert-circle-exc',
                horizontalAlign: 'right',
                verticalAlign: 'top',
                type: 'danger',
                timeout: 10000,
                title: title,
                message: message
            });
        },
        notifyDangerWithCallback(title, message, cb_function, cb_function_text, cb_function_key, infinite) {
            let timeout = 10000;
            if (infinite) {
                timeout = 0;
            }
            this.$notify({
                component: NotificationTemplate,
                icon: 'tim-icons icon-alert-circle-exc',
                horizontalAlign: 'right',
                verticalAlign: 'top',
                type: 'danger',
                timeout: timeout,
                title: title,
                message: message,
                cb_function: cb_function,
                cb_function_text: cb_function_text,
                cb_function_key: cb_function_key
            });
        },
        notifyWarning(title, message) {
            this.$notify({
                component: NotificationTemplate,
                icon: 'tim-icons icon-alert-circle-exc',
                horizontalAlign: 'right',
                verticalAlign: 'top',
                type: 'warning',
                timeout: 10000,
                title: title,
                message: message
            });
        }
    }
};
