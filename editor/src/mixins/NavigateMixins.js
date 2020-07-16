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
            if (evt.keyCode === 40 && evt.shiftKey && evt.ctrlKey) {
                // Ctrl + Shift + ArrowDown
                this.navigateItem(true);
            } else if (evt.keyCode === 38 && evt.shiftKey && evt.ctrlKey) {
                // Ctrl + Shift + ArrowUp
                this.navigateItem(false);
            }
        }
    }
};
