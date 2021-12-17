import openpyxl
import json

FILE_PATH_DETTECT_DS_XLSX = '../../../data/dettect_data_sources.xlsx'
EXCEL_COLUMNS_OF_INTEREST = ['E', 'F', 'G', 'H']
FILE_DATA_SOURCES_PLATFORMS = 'dettect_data_sources.json'


class DeTTECTDataSources():
    """
    Update the mapping of techniques to DeTT&CT data sources ('dettect_data_sources.json')
    based on the content within 'dettect_data_sources.xlsx'.
    """

    def __init__(self):
        self.excel_dict = self._create_dict_from_excel()

    def _create_dict_from_excel(self):
        """
        Create a dictionary from the Excel file 'dettect_data_sources.xlsx' with the data we need.
        :return:
        """
        excel_file = openpyxl.load_workbook(FILE_PATH_DETTECT_DS_XLSX)
        excel_sheet = excel_file['Techniques']

        excel_dict = {}

        row_idx = 2
        for _ in excel_sheet.iter_rows():
            tech_id = excel_sheet['A' + str(row_idx)].value
            if tech_id != None:
                excel_dict[tech_id] = []

                for c in EXCEL_COLUMNS_OF_INTEREST:
                    cell_value = excel_sheet[c + str(row_idx)].value
                    if cell_value:
                        excel_dict[tech_id].append(excel_sheet[c + str(row_idx)].value)
            row_idx += 1

        return excel_dict

    def create_dettect_data_sources_json(self):
        """
        Generate the content for the file 'dettect_data_sources.json' and write to disk.
        :return:
        """
        ds_per_technique = []

        for k, v in self.excel_dict.items():
            tmp_d = {}
            tmp_d['technique_id'] = k

            # Make sure that Network Traffic Content is always shown last in the list
            # (also sort the DeTT&CT data sources)
            all_data_source_except = set(v).difference(['Network Traffic Content'])
            sorted_ds = [ds + ' [DeTT&CT data source]' for ds in sorted(list(all_data_source_except))] + \
                [ds for ds in v if ds == 'Network Traffic Content']
            tmp_d['dettect_data_sources'] = sorted_ds

            ds_per_technique.append(tmp_d)

        # Write file to disk
        with open('../../../data/' + FILE_DATA_SOURCES_PLATFORMS, 'w') as f:
            json.dump(ds_per_technique, f, indent=2)
        return ds_per_technique


if __name__ == "__main__":
    dettect_data_sources = DeTTECTDataSources()
    dettect_data_sources.create_dettect_data_sources_json()
