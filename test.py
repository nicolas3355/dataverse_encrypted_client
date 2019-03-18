from dataverse import Connection

host = 'dataverse.massopen.cloud'
token = '275ea54d-c449-432f-80ed-f1a541d4e972'

connection = Connection(host, token)
# For non-https connections (e.g. local dev environment), try:
#   connection = Connection(host, token, use_https=False)

dataverse = connection.get_dataverse('test')  # fetch dataverse by id
dataset = dataverse.get_dataset_by_doi('doi:10.5072/FK2/YQMMZW')
dataset.upload_file("test.txt", "txt", False)  # upload a file test.txt
