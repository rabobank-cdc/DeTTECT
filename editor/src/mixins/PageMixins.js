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
            platforms: constants.PLATFORMS
        };
    },
    components: {
        FileReader,
        FileDetails
    },
    methods: {
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
        deleteItem(event, type, key, title, cb_function) {
            let key_id = event.target.getAttribute(key);
            let index = -1;
            for (let i = 0; i < this.doc[type].length; i++) {
                if (key_id == this.doc[type][i][key]) {
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
            if (this.selectedRow != null && this.selectedRow.length > 0 && (key_id == '' || key_id == this.selectedRow[0][key])) {
                this.selectedRow.pop();
            }
            this.doc[type].splice(index, 1);
            let msg = '';
            key_id == '' ? (msg = 'The empty ' + title.toLowerCase() + ' is removed.') : (msg = title + " '" + key_id + "' is removed.");
            this.notifyInfoWithCallback('Removal status', msg, cb_function, 'Undo this action', key_id);
        },
        recoverDeletedItem(type, key) {
            // Recover deleted item (also works for multiple deleted items)
            let recoverRow = null;
            for (let i = 0; i < this.deletedRows.length; i++) {
                if (key == this.deletedRows[i]['key']) {
                    recoverRow = this.deletedRows[i]['value'];
                    break;
                }
            }
            if (recoverRow != null) {
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

            // Check platform:
            if (this.doc.platform.length == 0) {
                this.notifyDanger('Missing value', 'No value for platform selected. Please select one or more platforms.');
                return;
            }

            // Copy the doc variable before downloading to convert some values specific for the type of page
            let newDoc = _.cloneDeep(this.doc);
            this.convertBeforeDownload(newDoc);

            var blob = new Blob([jsyaml.safeDump(newDoc, { lineWidth: 2000 })], {
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
                    .then(value => {
                        if (value) {
                            this.newFile();
                        }
                    });
            } else {
                this.newFile();
            }
        }
    }
};
