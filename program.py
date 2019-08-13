from dataverse import Connection
from enc_file import *
import requests
import json
import base64
from nacl.public import PrivateKey, SealedBox
import argparse


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

	return None

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
	print(type(org_map))
	if org_map != "None":
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


def add_user(args):
	# for adding a new user into the metadata -- need to first derive data_key
	filename = args.filename
	org_name = args.org_name
	passphrase = args.passphrase
	#public_key = args.public_key
	#public_key = b'0\xad\xf3\xcf\xdfV\x85\xdaF\x99\xa0\x85/p\x19,]\x84\xbf\xa0\x9f\x90\xe4\xcb\x0fq\xe0s\xfa\xee\rV'
	#with open(public_keys) as file:
	#	pub_keys = json.load(file)
	#	public_key = pub_keys[org_name]

	#print(type(public_key))
	#public_key = public_keys[org_name]
	#metadata = get_metadata(dataset, connection)
	metadata = json.loads(get_metadata(dataset, connection).decode())

	owner_key = metadata['files'][filename]['owner_wrapped_key']
	k = base64.decodestring(owner_key.encode())
	data_key = unwrap_key_owner(passphrase, k)
	
	org_wrapped_key = wrap_key_org(public_key, data_key)
	decoded_key = base64.encodestring(org_wrapped_key).decode('ascii')

	#metadata = json.loads(metadata)
	metadata["files"][filename]["org"][org_name] = decoded_key
	metadata = json.dumps(metadata)
	update_metadata(dataset, metadata)
	return


def remove_user(args):
	filename = args.filename
	org_name = args.org_name

	metadata = get_metadata(dataset, connection)
	metadata = json.loads(metadata)
	try:
		del metadata["files"][filename]["org"][org_name]
	except KeyError:
		print('User does not exist.')
		return
	metadata = json.dumps(metadata)
	update_metadata(dataset, metadata)
	print('User access revoked.')
	return


def upload_file(args):
	filepath = args.filepath
	keymap = args.keymap
	filename = args.filename
	passphrase = args.passphrase

	out = enc_file(filepath)
	if out is None:
		print("error encrypting file")
	else:
		key, nonce, ciphertext = out
	dataset.upload_file(filename, ciphertext, False)

	# add keys to file's metadata
	print(type(keymap))
	update_metadata_of_file(dataset, filename, key, keymap,
						passphrase, "id")
	print("File uploaded.")
	return


def download_file(args):
	filename = args.filename
	passphrase = args.passphrase

	encrypted_file = get_enc_file(dataset,connection,filename)
	metadata = json.loads(get_metadata(dataset, connection).decode())
	owner_key = metadata['files'][filename]['owner_wrapped_key']

	# decrypt file
	k = base64.decodestring(owner_key.encode())
	key = unwrap_key_owner(passphrase, k)
	decrypted_file = dec_str(encrypted_file,key)
	print(decrypted_file)
	return decrypted_file


def update_password(args):
	old_pass = args.old_passphrase
	new_pass = args.new_passphrase
	filename = args.filename

	metadata = json.loads(get_metadata(dataset, connection).decode())
	owner_key = metadata['files'][filename]['owner_wrapped_key']
	k = base64.decodestring(owner_key.encode())
	data_key = unwrap_key_owner(old_pass, k)

	owner_wrapped_key = wrap_key_owner(new_pass, data_key)
	decoded_key = base64.encodestring(owner_wrapped_key).decode('ascii')
	metadata['files'][filename]['owner_wrapped_key'] = decoded_key
	metadata = json.dumps(metadata)
	update_metadata(dataset, metadata)
	print('Password updated.')
	return



host = 'demo.dataverse.org'
token = 'ae1379dd-29b3-40b7-b583-c4e40cc3656e'

connection = Connection(host, token)


dataverse = connection.get_dataverse('testing_dataverse_123')

# I have created the dataset in dataverse manually: "doi:10.70122/FK2/0HH8BM"
dataset = dataverse.get_dataset_by_doi('doi:10.70122/FK2/O13BQC')

metadata_filename = "metadata.txt"


FUNCTION_MAP = {'upload' : upload_file,
				#'add_user' : give_access,
				#'remove_user' : revoke_access,
				#'change_password' : update_pass,
				'download' : download_file }

parser = argparse.ArgumentParser(description='To work with encrypted files in dataverse')

subparsers = parser.add_subparsers(help='sub-command help')

#parser for uploading a file
upload = subparsers.add_parser('upload', help='Encrypt and upload a new file')
upload.add_argument('filepath', type=str, help='Path to file on system')
upload.add_argument('passphrase', type=str, help='Your passphrase -- '
					'will be used for downloading and adding users')
upload.add_argument('keymap', help='Keymap of authorized users, if none,'
					' input "None"')
upload.add_argument('filename', type=str, help='Filename in dataverse')
upload.set_defaults(func=upload_file)

download = subparsers.add_parser('download', help='Download and decrypt a file')
download.add_argument('filename', type=str, help='Filename in dataverse')
download.add_argument('passphrase', type=str, help='Your passphrase')
download.set_defaults(func=download_file)

add = subparsers.add_parser('add_user', help='Add a new authorized user')
add.add_argument('filename', type=str, help='Filename in dataverse')
add.add_argument('org_name', type=str, help='Organization name')
add.add_argument('passphrase', type=str, help='Your passphrase')
#add.add_argument('public_key', type=bytes, help='File with orgs and PKs')
add.set_defaults(func=add_user)

remove = subparsers.add_parser('remove_user', help='Revoke access for a user')
remove.add_argument('filename', type=str, help='Filename to revoke access from')
remove.add_argument('org_name', type=str, help='Org name as saved in metadata')
remove.set_defaults(func=remove_user)

change = subparsers.add_parser('update_pass', help='Change your passphrase')
change.add_argument('old_passphrase', type=str, help='Your old passphrase')
change.add_argument('new_passphrase', type=str, help='Your new passphrase')
change.add_argument('filename', type=str, help='Filename in dataverse')
change.set_defaults(func=update_password)

args = parser.parse_args()

args.func(args)









