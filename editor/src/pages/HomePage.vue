<template>
    <div class="row" id="pageTop">
        <div class="col">
            <div class="card card-card">
                <div class="card-header">
                    <h2 class="card-title"><i class="tim-icons icon-bank pb-md-2"></i> Home</h2>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-5">
                            <h4>Introduction</h4>
                            <p>
                                The DeTT&CT data source, technique and group YAML files can be edited using this editor.
                            </p>
                            <p class="mt-md-3">
                                Usefull links on the Wiki:
                                <ul
                                    ><li><a href="https://github.com/rabobank-cdc/DeTTECT/wiki/Getting-started" target="_blank">Getting started with DeTT&CT</a></li>
                                    <li><a href="https://github.com/rabobank-cdc/DeTTECT/wiki/dettect-editor" target="_blank">DeTT&CT Editor</a></li>
                                    <li>
                                        <a href="https://github.com/rabobank-cdc/DeTTECT/wiki/Future-dev#dettct-editor" target="_blank">Future developments</a>
                                    </li></ul
                                >
                            </p>
                        </div>
                        <div class="col-md-5">
                            <h4>Client-side and saving results</h4>
                            <p>
                                The DeTT&CT Editor is entirely client-side. Therefore, the content of your YAML file is not send to a server.
                            </p>
                            <p class="mt-md-2">It is important to take into account that modifed YAML files should be download using the button
                                <strong>Save YAML file</strong>, to save the results.</p>
                        </div>
                    </div>
                    <div class="row mt-md-2">
                        <div class="col-md-5">
                            <h4>Keyboard shortcuts</h4>
                            <p>
                                <ul>
                                    <li>Ctrl+Shift+Up/Down: go to the next or previous item when editing a data source or technique administration YAML file.</li>
                                </ul>
                            </p>
                            <h4>Limitations</h4>
                            <p>
                                With a few exceptions, all key-value pairs within a data source, techniques or group YAML file can be edited. More info can be found <a href="https://github.com/rabobank-cdc/DeTTECT/wiki/Future-dev#dettct-editor" target="_blank">here</a>.
                            </p>
                            <p class="mt-md-2">
                                Please note that comments (<code>#</code>) within your YAML files are not preserved due to lack of support in the YAML JavaScript library. Put your comments within a key-value pair to keep them. For example: <code>my-comment-1: your comment goes here</code>.
                            </p>
                        </div>
                        <div class="col-md-5">
                            <h4>Authors and contributions</h4>
                            <p>DeTT&CT is developed and maintained by <a href="https://github.com/marcusbakker" target="_blank">Marcus Bakker</a> (Twitter: <a href="https://twitter.com/Bakk3rM" target="_blank">@Bakk3rM</a>) and
                            <a href="https://github.com/rubinatorz" target="_blank">Ruben Bouman</a> (Twitter: <a href="https://twitter.com/rubenb_2/" target="_blank">@rubenb_2</a>). Feel free to contact, DMs are open.</p>

                            <p class="mt-md-2"> We welcome contributions! Contributions can be both in code, as well as in ideas you might have for further development, usability improvements, etc.</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</template>

<script>
export default {
    name: 'groups-page',
    data() {
        return {};
    }
};
</script>

<style></style>
