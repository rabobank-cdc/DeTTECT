import VueScrollTo from 'vue-scrollto';
import constants from '@/constants';
import FileReader from '@/components/FileReader';
import FileDetails from '@/components/FileDetails';
import jsyaml from 'js-yaml';
import _ from 'lodash';

var options = {
    container: 'body',
    easing: 'ease-in',
    offset: -35,
    duration: 0,
    force: false,
    cancelable: true,
    // eslint-disable-next-line no-unused-vars
    onStart: function(element) {
        // scrolling started
    },
    // eslint-disable-next-line no-unused-vars
    onDone: function(element) {
        // scrolling is done
    },
    onCancel: function() {
        // scrolling has been interrupted
    },
    x: false,
    y: true
};

export const pageMixin = {
    data() {
        return {
            filename: '',
            selected_filename: '',
            doc: null,
            selectedRow: [],
            fileChanged: false,
            unwatchFunction: null,
            deletedRows: [],
            lastScrollPosition: 0,
            file_details_visible: true,
            file_details_lock: false,
            showFileName: ''
        };
    },
    components: {
        FileReader,
        FileDetails
    },
    mounted () {
        window.addEventListener('scroll', this.onScroll)
    },
    destroyed () {
        window.removeEventListener('scroll', this.onScroll)
    },
    methods: {
        getPlatforms(domain) {
            return domain == 'enterprise-attack' ? constants.PLATFORMS : constants.PLATFORMS_ICS;
        },
        getPlatformConversion(domain) {
            return domain == 'enterprise-attack' ? constants.PLATFORM_CONVERSION : constants.PLATFORM_CONVERSION_ICS;
        },
        navigateToTop() {
            VueScrollTo.scrollTo('#pageTop', 300, options);
        },
        navigateToDetail() {
            VueScrollTo.scrollTo('#detailCard', 300, options);
        },
        setFileName(filename) {
            // Callback function for file-reader component
            this.selected_filename = filename;
        },
        selectItem(event) {
            // selectionChanged event from the data table
            if (this.selectedRow != event) {
                this.selectedRow = event;
                if (event.length > 0) {
                    this.navigateToDetail();
                }
            }
        },
        addItem(type, key, emptyObject) {
            // Add an item to the table and select it in the detail component
            // Check if no empty items are in the dataset (one new item is allowed at a time):
            this.filters.filter.value = '';
            let emptyRow = null;
            for (let i = 0; i < this.doc[type].length; i++) {
                if (this.doc[type][i][key] == '') {
                    emptyRow = this.doc[type][i];
                }
            }

            if (emptyRow != null) {
                let typeStr = type.replace('_', ' ').slice(0, -1);
                this.notifyWarning('Add new ' + typeStr, 'Only one ' + typeStr + ' can be added at a time.');
                this.selectedRow.pop();
                this.selectedRow.push(emptyRow);
            } else {
                let newrow = _.cloneDeep(emptyObject);
                this.doc[type].push(newrow);
                this.selectedRow.pop();
                this.selectedRow.push(newrow);
            }
        },
        getSelectedItem() {
            // Returns the selected row if there is one selected, otherwise null
            if (this.selectedRow != null && this.selectedRow.length > 0) {
                return this.selectedRow[0];
            } else {
                return null;
            }
        },
        deleteItem(event, type, keys, title, cb_function) {
            // Save the information to make undelete possible
            let key_id = event.target.getAttribute(keys[0])
            for(let i = 1; i < keys.length; i++){
                key_id = key_id + '-' + event.target.getAttribute(keys[i]);
            }
            let index = -1;
            for (let i = 0; i < this.doc[type].length; i++) {
                let key_to_check = this.doc[type][i][keys[0]];
                for(let j = 1; j < keys.length; j++){
                    key_to_check = key_to_check + '-' + this.doc[type][i][keys[j]];
                }
                if (key_id == key_to_check) {
                    index = i;
                    break;
                }
            }
            this.deletedRows.push({
                key: key_id,
                value: this.doc[type][index]
            });

            // the below code results in hiding the details page when deleting:
            // - an empty item (i.e. without a name)
            // - the selected item
            if (this.selectedRow != null && this.selectedRow.length > 0) {
                let selected_key_id = this.selectedRow[0][keys[0]];
                for (let i = 1; i < keys.length; i++){
                    selected_key_id = selected_key_id + '-' + this.selectedRow[0][keys[i]];
                }
                if (key_id == '' || key_id == selected_key_id) {
                    this.selectedRow.pop();
                }
            }

            // The actual delete
            this.doc[type].splice(index, 1);
            let msg = '';
            key_id == '' ? (msg = 'The empty ' + title.toLowerCase() + ' is removed.') : (msg = title + " '" + key_id + "' is removed.");
            this.notifyInfoWithCallback('Removal status', msg, cb_function, 'Undo this action', key_id);
        },
        recoverDeletedItem(type, event_key, all_items, keys) {
            // Recover deleted item (also works for multiple deleted items)
            let recoverRow = null;
            for (let i = 0; i < this.deletedRows.length; i++) {
                if (event_key == this.deletedRows[i]['key']) {
                    recoverRow = this.deletedRows[i]['value'];
                    break;
                }
            }
            if (recoverRow != null) {
                // Check if the item was added meanwhile:
                for (let i = 0; i < all_items.length; i++) {
                    let key_id = all_items[i][keys[0]];
                    for(let j = 1; j < keys.length; j++){
                        key_id = key_id + '-' + all_items[i][keys[j]];
                    }


                    if(event_key == key_id){
                        return;
                    }
                }

                this.doc[type].push(recoverRow);
                this.selectedRow.pop();
                this.selectedRow.push(recoverRow);
            }
        },
        downloadYaml(type, key) {
            // Call the unwatch function to make sure that this.doc isn't watched file altering the object during the download.
            // The splice function that is called underneath causes unexpected behaviour that results in altering the object
            // after the download and fileChange=false is done.
            this.unwatchFunction();

            // "Download" (save) the YAML file
            // Remove empty rows:
            let indexEmptyRow = -1;
            for (let i = 0; i < this.doc[type].length; i++) {
                if (this.doc[type][i][key] == '') {
                    indexEmptyRow = i;
                }
            }
            if (indexEmptyRow >= 0) {
                this.doc[type].splice(indexEmptyRow, 1);
                this.selectedRow.pop();
            }

            this.cleanupBeforeDownload();

            // Copy the doc variable before downloading to convert some values specific for the type of page
            let newDoc = _.cloneDeep(this.doc);
            this.convertBeforeDownload(newDoc);

            var blob = new Blob([jsyaml.dump(newDoc, { lineWidth: 2000 })], {
                type: 'text/plain;charset=utf-8'
            });
            var FileSaver = require('file-saver');
            FileSaver.saveAs(blob, this.filename);
            this.fileChanged = false;

            // Set the watch on this.doc again:
            this.setWatch();
        },
        setWatch() {
            if (this.unwatchFunction != null) {
                this.unwatchFunction();
            }
            this.unwatchFunction = this.$watch(
                'doc',
                // eslint-disable-next-line no-unused-vars
                function(after, before) {
                    this.fileChanged = true;
                },
                { deep: true }
            );
        },
        askNewFile() {
            if (this.fileChanged) {
                this.$bvModal
                    .msgBoxConfirm('You have unsaved changes that will be lost if you choose to continue.', {
                        title: 'Unsaved changes',
                        size: 'sm',
                        cancelVariant: 'warning',
                        okVariant: 'info',
                        okTitle: 'Continue',
                        modalClass: 'confirmMessage'
                    })
                    .then((value) => {
                        if (value) {
                            this.newFile();
                        }
                    });
            } else {
                this.newFile();
            }
        },
        navigateItem(next) {
            let step = 1;
            if (!next) {
                step = -1;
            }
            // First, loop through the visible rows (this takes the sorting and filtering into account):
            let table = this.$refs.data_table.$el.rows;
            let found_index = 0;
            for (let i = 0; i < table.length; i++) {
                if (table[i].className == 'table-selected-custom') {
                    found_index = i;
                    break;
                }
            }
            // Do not proceed when it's the first or last row:
            if ((found_index != 0 && !next) || (found_index != table.length - 1 && next)) {
                // Unset current selected row:
                this.$refs.data_table.$el.rows[found_index].className = '';
                this.selectedRow.pop();
                // Select previous/next row just visually:
                this.$refs.data_table.$el.rows[found_index + step].className = 'table-selected-custom';

                // Next, loop through the dataset rows, looking for the new selected item to formally select:
                let rows = this.$refs.data_table_rows;
                let found_row;
                for (let i = 0; i < rows.length; i++) {
                    if (rows[i].$el.className == 'table-selected-custom') {
                        found_row = rows[i].row;
                        break;
                    }
                }
                this.selectedRow.push(found_row);
            }
        },
        onScroll () {
            const currentScrollPosition = window.pageYOffset;
            if (Math.abs(currentScrollPosition - this.lastScrollPosition) > 80) {
                this.hideFileDetails(false);
                this.lastScrollPosition = currentScrollPosition
            }
        },
        changePageTitle () {
            if(this.file_details_visible){
                this.showFileName = '';
            }
            else if(this.filename != ''){
                this.showFileName = ': ' + this.filename;
            }
        }
    }
};
