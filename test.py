from dataverse import Connection
from enc_file import enc_file
host = 'demo.dataverse.org'
token = 'ae1379dd-29b3-40b7-b583-c4e40cc3656e'

connection = Connection(host, token)
# For non-https connections (e.g. local dev environment), try:
#   connection = Connection(host, token, use_https=False)


# " name": "Scientific Research",
# " alias": "science",
# " dataverseContacts:nhaddad@bu.edu"
# " POST http://$SERVER/api/dataverses/$id?key=$apiKey"

# def create_dataverse(self, alias, name, email, parent=':root'):
#    url = "http://demo.dataverse.org/api/v1/
#    resp = requests.post(
#        '{0}/dataverses/{1}'.format(self.native_base_url, parent),
#        json={
#            'alias': alias,
#            'name': name,
#            'dataverseContacts': [{'contactEmail': email}],
#        },
#        params={'key': self.token},
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
#    self.get_service_document(refresh=True)
# return self.get_dataverse(alias)

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
key, nonce, ciphertext = enc_file("test_file.txt")
dataset.upload_file("encryped_test_file.txt", nonce + ciphertext, False)

# update metadata
# get all the old metadata
# find the file that I am updating the metadata for
# add the following
# {orgs: [{orgId, encryptedDataKey}...]}
# {owner:  encryptedDataKey}
