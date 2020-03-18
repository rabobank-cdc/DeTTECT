<template>
    <label class="text-reader">
        <input type="file" @change="loadTextFromFile" :id="id" />
    </label>
</template>

<script>
    export default {
        props: {
            setFileNameFn: Function,
            id: String
        },
        methods: {
            loadTextFromFile(ev) {
                const file = ev.target.files[0];
                const reader = new FileReader();
                this.setFileNameFn(ev.target.files[0].name);

                reader.onload = e => this.$emit('load', e.target);
                reader.readAsText(file);
            }
        }
    };
</script>
