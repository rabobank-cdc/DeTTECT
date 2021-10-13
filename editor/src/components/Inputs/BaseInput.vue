<template>
    <div
        class="form-group"
        :class="{
            'input-group': hasIcon,
            'input-group-focus': focused
        }"
    >
        <slot name="label">
            <label v-if="label" class="control-label">
                {{ label }}
            </label>
        </slot>
        <slot name="addonLeft">
            <span v-if="addonLeftIcon" class="input-group-prepend">
                <div class="input-group-text">
                    <i :class="addonLeftIcon"></i>
                </div>
            </span>
        </slot>
        <slot>
            <input :value="value" v-bind="$attrs" v-on="listeners" :class="inputStyle" aria-describedby="addon-right addon-left" ref="inputRef" v-b-tooltip.hover.left :title="errorText" />
        </slot>
        <slot name="addonRight">
            <span v-if="addonRightIcon" class="input-group-append">
                <div class="input-group-text">
                    <i :class="addonRightIcon"></i>
                </div>
            </span>
        </slot>
        <slot name="helperText"></slot>
    </div>
</template>
<script>
export default {
    inheritAttrs: false,
    name: 'base-input',
    props: {
        label: {
            type: String,
            description: 'Input label'
        },
        value: {
            type: [String, Number],
            description: 'Input value'
        },
        addonRightIcon: {
            type: String,
            description: 'Input icon on the right'
        },
        addonLeftIcon: {
            type: String,
            description: 'Input icon on the left'
        },
        showError: {
            type: Boolean,
            required: false,
            default: false
        },
        errorText: {
            type: String,
            required: false,
            default: ''
        }
    },
    model: {
        prop: 'value',
        event: 'input'
    },
    data() {
        return {
            focused: false
        };
    },
    computed: {
        hasIcon() {
            const { addonRight, addonLeft } = this.$slots;
            return addonRight !== undefined || addonLeft !== undefined || this.addonRightIcon !== undefined || this.addonLeftIcon !== undefined;
        },
        listeners() {
            return {
                ...this.$listeners,
                input: this.onInput,
                blur: this.onBlur,
                focus: this.onFocus
            };
        },
        inputStyle() {
            let style = "form-control"
            if(this.showError){
                style += " error"
            }
            return style
        }
    },
    methods: {
        onInput(evt) {
            this.$emit('input', evt.target.value);
        },
        onFocus(evt) {
            this.focused = true;
            this.$emit('focus', evt.target.value);
        },
        onBlur(evt) {
            this.focused = false;
            this.$emit('blur', evt.target.value);
        },
        focus() {
            this.focused = true;
            this.$refs.inputRef.focus();
        }
    }
};
</script>
<style></style>
