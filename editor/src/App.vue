<template>
    <div>
        <notifications></notifications>
        <keep-alive>
            <router-view :key="$route.fullPath"></router-view>
        </keep-alive>
    </div>
</template>

<script>
    export default {
        methods: {
            disableRTL() {
                if (!this.$rtl.isRTL) {
                    this.$rtl.disableRTL();
                }
            },
            toggleNavOpen() {
                let root = document.getElementsByTagName('html')[0];
                root.classList.toggle('nav-open');
            }
        },
        mounted() {
            this.$watch('$route', this.disableRTL, { immediate: true });
            this.$watch('$sidebar.showSidebar', this.toggleNavOpen);
        },
        created() {
            if (process.env.NODE_ENV == 'production') {
                window.addEventListener('beforeunload', event => {
                    // Cancel the event as stated by the standard.
                    event.preventDefault();
                    // Chrome requires returnValue to be set.
                    event.returnValue = '';
                });
            }
        }
    };
</script>

<style lang="scss"></style>
