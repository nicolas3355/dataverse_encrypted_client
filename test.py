from dataverse import Connection
from enc_file import enc_file
from enc_file import wrap_key_owner
import requests
import json


host = 'demo.dataverse.org'
token = 'ae1379dd-29b3-40b7-b583-c4e40cc3656e'

connection = Connection(host, token)
# For non-https connections (e.g. local dev environment), try:
#   connection = Connection(host, token, use_https=False)


# " name": "Scientific Research",
# " alias": "science",
# " dataverseContacts:nhaddad@bu.edu"
# " POST http://$SERVER/api/dataverses/$id?key=$apiKey"

# def create_dataverse(dataset, alias, name, email, parent=':root'):
#    url = "http://demo.dataverse.org/api/v1/
#    resp = requests.post(
#        '{0}/dataverses/{1}'.format(dataset.native_base_url, parent),
#        json={
#            'alias': alias,
#            'name': name,
#            'dataverseContacts': [{'contactEmail': email}],
#        },
#        params={'key': dataset.token},
#    )
#
#    if resp.status_code == 404:
#        raise exceptions.DataverseNotFoundError(
#            'Dataverse {0} was not found.'.format(parent)
#        )
#    elif resp.status_code != 201:
#        raise exceptions.OperationFailedError(
#            '{0} Dataverse could not be created.'.format(name)
#        )
#
#    dataset.get_service_document(refresh=True)
# return dataset.get_dataverse(alias)

# creation of a dataverse automatically is not currently working
# I have created one manually with id:  testing_dataverse_123
# fetch dataverse by id
dataverse = connection.get_dataverse('testing_dataverse_123')

# I have created the dataset in dataverse manually: "doi:10.5072/FK2/6MGCWY"
dataset = dataverse.get_dataset_by_doi('doi:10.5072/FK2/6MGCWY')

# upload a string under a filename
dataset.upload_file("test_file.txt", "string of what's inside the file", False)

# upload a file as is from path
dataset.upload_filepath("test_file.txt")

# upload and encrypt file from path with a random key
out = enc_file("test_file.txt")
if(out is None):
    print("error encrypting file")
else:
    key, nonce, ciphertext = out
dataset.upload_file("encryped_test_file.txt", nonce + ciphertext, False)


def update_metadata(dataset, metadata):
    """Updates dataset draft with provided metadata.
    Will create a draft version if none exists.
    :param dict metadata: json retrieved from `get_version_metadata`
    """
#   url = '{0}/datasets/{1}/versions/:draft'.format(
#   dataset.connection.native_base_url,
#   dataset.id,
#   )
#   resp = requests.put(
#   url,
#   headers={'Content-type': 'application/json'},
#   data=json.dumps(m),
#   params={'key': dataset.connection.token},
#   )
#
#    if resp.status_code != 200:
#        print resp

#    updated_metadata = resp.json()['data']
#    dataset._metadata['draft'] = updated_metadata

# update metadata
# get all the old metadata
# find the file that I am updating the metadata for
# add the following
# {orgs: [{orgId, encryptedDataKey}...]}
# {owner:  encryptedDataKey}
# metadata file contains the information necessary to decrypt the data


metadata = dataset.get_metadata()
update_metadata(dataset)

metadata_filename = "metadata.txt"


def get_file_content(url, connection):
    request = requests.get(url, params={"key": connection.token})
    if request.status_code == "200":
        return request.content


def get_metadata(dataset):
    # find the filename with the metadata
    metadata_file = dataset.get_file(metadata_filename)
    if metadata_file is not None:
        return get_file_content(metadata_file.download_url)
    return None


def update_metadata(dataset, new_metadata_content):
    # delete the old metadata on dataverse if it exists
    metadata_file = dataset.get_file(metadata_filename)
    if metadata_file is not None:
        dataset.delete_file(metadata_file)
    # upload new metadata
    dataset.upload_file(metadata_filename, new_metadata_content, False)


#   def update_metdata(dataset, filename, data_key, org_map, owner_passphrase):
#       metadata = dataset.get_metadata()
#       print(metadata)
#       return
#       files = metadata['files']
#       for i in range(0, len(files)):
#           if files[i]['dataFile']['filename'] == filename:
#               files[i]['dataFile']['owner'] = wrap_key_owner(
#                      "owner_passphrase", "data_key")
#               files[i]['dataFile']['orgs'] = []
#       dataset.update_metadata(metadata)


update_metadata(dataset, "encrypted_test_file.txt", None, None, None)
