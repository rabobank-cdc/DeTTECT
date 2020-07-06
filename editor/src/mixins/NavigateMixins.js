export const navigateMixins = {
    data() {
        return {};
    },
    created: function() {
        document.addEventListener('keyup', this.arrowKeysListener);
    },
    destroyed: function() {
        document.removeEventListener('keyup', this.arrowKeysListener);
    },
    components: {},
    methods: {
        arrowKeysListener: function(evt) {
            if (evt.keyCode === 40 && evt.shiftKey) {
                // Shift + ArrowDown
                window.getSelection().empty();
                this.navigateItem(true);
            } else if (evt.keyCode === 38 && evt.shiftKey) {
                // Shift + ArrowUp
                window.getSelection().empty();
                this.navigateItem(false);
            }
        }
    }
};
