export const pageDetailMixin = {
    data() {
        return {};
    },
    created: function() {
        document.addEventListener('keyup', this.escapeKeyListener);
    },
    destroyed: function() {
        document.removeEventListener('keyup', this.escapeKeyListener);
    },
    components: {},
    methods: {}
};
