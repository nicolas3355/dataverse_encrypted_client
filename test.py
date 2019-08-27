from dataverse import Connection
from enc_file import *
import requests
import json
import base64
from nacl.public import PrivateKey, SealedBox


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

# I have created the dataset in dataverse manually: "doi:10.70122/FK2/0HH8BM"
dataset = dataverse.get_dataset_by_doi('doi:10.70122/FK2/O13BQC')

# upload a string under a filename
#dataset.upload_file("test_file.txt", "string of what's inside the file", False)

# # upload a file as is from path
# dataset.upload_filepath("test_file.txt")

# # upload and encrypt file from path with a random key
# out = enc_file("test_file.txt")
# if(out is None):
#     print("error encrypting file")
# else:
#     key, nonce, ciphertext = out
# dataset.upload_file("encrypted_test_file.txt", ciphertext, False)


# def update_metadata(dataset, metadata):
#    """Updates dataset draft with provided metadata.
#    Will create a draft version if none exists.
#    :param dict metadata: json retrieved from `get_version_metadata`
#    """
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


# metadata = dataset.get_metadata()
# update_metadata(dataset)

metadata_filename = "metadata.txt"


def get_file_content(url, connection):
    request = requests.get(url, params={"key": connection.token})
    if request.status_code == 200:
        return request.content
        #returns encoded, add .decode() to return normally

def get_metadata(dataset, connection):
    # find the filename with the metadata
    metadata_file = dataset.get_file(metadata_filename)
    if metadata_file is not None:
        return get_file_content(metadata_file.download_url, connection)

    return None

def get_enc_file(dataset, connection, filename):
    file = dataset.get_file(filename)
    if filename is not None:
        return get_file_content(file.download_url, connection)

    return none

def update_metadata(dataset, new_metadata_content):
    # delete the old metadata on dataverse if it exists
    metadata_file = dataset.get_file(metadata_filename)
    if metadata_file is not None:
        dataset.delete_file(metadata_file)
    # upload new metadata
    dataset.upload_file(metadata_filename, new_metadata_content, False)


def update_metadata_of_file(dataset, filename, data_key, org_map,
                            owner_passphrase, owner_id):
    metadata = get_metadata(dataset, connection)
    owner_wrapped_key = wrap_key_owner(owner_passphrase, data_key)
    decoded_key = base64.encodestring(owner_wrapped_key).decode('ascii')
    # {files: {file1:{owner-id:{}, owner-wrapped-key:{},
    #   orgs:{org-id:"org-wrapped-key",}}, ...}}

    obj = {"owner_id": owner_id, "owner_wrapped_key":
           decoded_key, "org": {}}

    # wrap the data_key for each one of the orgs
    if org_map is not None:
        for org_name in org_map:
            # adds each organization + public key to metadata
            public_key_org = org_map[org_name]
            org_wrapped_key = wrap_key_org(public_key_org, data_key)
            decoded_key = base64.encodestring(org_wrapped_key).decode('ascii')
            obj["org"][org_name] = decoded_key

    if(metadata is None):
        print ("Creating new metadata, metadata is empty")
        metadata = {"files": {filename: obj}}
        metadata = json.dumps(metadata)
        print(metadata)
    else:
        metadata = json.loads(metadata)
        metadata["files"][filename] = obj
        metadata = json.dumps(metadata)
    update_metadata(dataset, metadata)


def update_metadata_org(dataset, filename, data_key, org_name,
                        public_key_org):
    # for adding a new org into the metadata -- need to first derive data_key
    metadata = get_metadata(dataset, connection)
    org_wrapped_key = wrap_key_org(public_key_org, data_key)
    decoded_key = base64.encodestring(org_wrapped_key).decode('ascii')

    metadata = json.loads(metadata)
    metadata["files"][filename]["org"][org_name] = decoded_key
    metadata = json.dumps(metadata)
    update_metadata(dataset, metadata)


def test_owner(passphrase, keymap):
    """ Full test for the owner uploading encrypted file(s) with
    metadata and then downloading and decrypting"""

    # upload a file as is from path
    dataset.upload_filepath("test_file.txt")

    # upload and encrypt file from path with a random key
    out = enc_file("test_file.txt")
    if(out is None):
        print("error encrypting file")
    else:
        key, nonce, ciphertext = out
    dataset.upload_file("encrypted_test_file.txt", ciphertext, False)

    # add keys to file's metadata
    update_metadata_of_file(dataset, "encrypted_test_file.txt", key, keymap,
                        passphrase, "id")

    # download encrypted file and get key from metadata
    encrypted_file = get_enc_file(dataset,connection,"encrypted_test_file.txt")
    metadata = json.loads(get_metadata(dataset, connection).decode())
    owner_key = metadata['files']['encrypted_test_file.txt']['owner_wrapped_key']

    # decrypt file
    k = base64.decodestring(owner_key.encode())
    key = unwrap_key_owner(passphrase, k)
    decrypted_file = dec_str(encrypted_file,key)
    return decrypted_file, key

# test organization keys
sk0 = PrivateKey.generate()
print(type(sk0))
pk0 = sk0.public_key
print(type(pk0))
sk1 = PrivateKey.generate()
pk1 = sk1.public_key

keymap = {"org0": pk0, "org1": pk1}

#decrypted, key = test_owner("password", keymap)

#print(decrypted)

#update_metadata_org(dataset, "encrypted_test_file.txt", key, "test_org", skbob)

def test_org(private_key, org_name):
    # for removing and decrypting for an organization (not owner)
    encrypted_file = get_enc_file(dataset,connection,"encrypted_test_file.txt")

    # get key from metadata
    metadata = json.loads(get_metadata(dataset, connection).decode())
    org_key = metadata['files']['encrypted_test_file.txt']['org'][org_name]

    # decrypt file
    k = base64.decodestring(org_key.encode())
    key = unwrap_key_org(private_key, k)
    decrypted_file = dec_str(encrypted_file,key)
    return decrypted_file

