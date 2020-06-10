<template>
    <div>
        <textarea
            :rows="rows"
            placeholder=". . ."
            class="form-control textarea-border pl-md-3 textarea-customstyle"
            v-model="data_object[data_field]"
        >
        </textarea>
        <div v-b-modal="'comment-modal-' + id" class="icon-example" @click="callCbFunction('comment-modal-' + id)"></div>
        <b-modal :id="'comment-modal-' + id" dialog-class="modal-edit-small" content-class="modal-dark-mode" hide-footer hide-header no-close-on-esc>
            <div class="row">
                <div class="col-md-auto pr-md-0">
                    <h5 class="title">Comment</h5>
                </div>
                <div class="col">
                    <button
                        type="button"
                        aria-label="Close"
                        class="close"
                        @click="
                            $bvModal.hide('comment-modal-' + id);
                            callCbFunction('comment-modal-' + id);
                        "
                    >
                        ×
                    </button>
                </div>
            </div>
            <div class="row">
                <div class="col-md-12">
                    <textarea
                        rows="50"
                        placeholder=". . ."
                        class="form-control textarea-border textarea-modal pl-md-3"
                        v-model="data_object[data_field]"
                    ></textarea>
                </div>
            </div>
        </b-modal>
    </div>
</template>

<script>
export default {
    data() {
        return {};
    },
    components: {},
    props: {
        data_object: {
            type: Object,
            required: true,
        },
        data_field: {
            type: String,
            required: true,
        },
        id: {
            type: String,
            required: true,
        },
        cb_function: {
            type: Function,
            required: false,
        },
        rows: {
            type: String,
            required: true,
        },
    },
    methods: {
        callCbFunction(b) {
            if (this.cb_function != undefined) {
                this.cb_function(b);
            }
        },
    },
};
</script>
