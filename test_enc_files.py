import enc_file as enc

filename = "test_file.txt"

data_key, nonce, n_ciphertext = enc.enc_file(filename)

print("Data key: ")
print(data_key,"\n")

# overwriting file with encrypted version (nonce + ciphertext)
f = open(filename,'wb')
f.write(n_ciphertext)
f.close()

plaintext = enc.dec_file(filename, data_key)

print("Plaintext from test_file.txt: ")
print(plaintext,"\n")

skbob = enc.PrivateKey.generate()
pkbob = skbob.public_key

c_text = enc.wrap_key_org(pkbob, data_key)
p_text = enc.unwrap_key_org(skbob, c_text)

print("Should print data key from above: ")
print(p_text, "\n")

password = "password"

c_owner = enc.wrap_key_owner(password, data_key)
p_owner = enc.unwrap_key_owner(password, c_owner)

print("Should print data key from above: ")
print(p_owner, "\n")

if (data_key == p_owner) & (data_key == p_text):
	print("It all works")
else:
	print("1+ key is wrong")

# rewriting original file 
f = open(filename,'w')
f.write(" this is a test file upload from python api")
f.close()

