package proj2

// git push -u origin [branch_name]
// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	// You neet to add with
	// go get github.com/nweaver/cs161-p2/userlib
	"github.com/ryanleh/cs161-p2/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"

	// optional
	_ "strconv"
	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg
	// see someUsefulThings() below
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// The structure definition for a user record
type User struct {
	Username string

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password

/*InitUser
- Derive sourceKey = Argon2Key(password, username, 16)
- k1 = HMACEval(sourceKey, username)
- k2 = HMACEval(sourceKey, 1 + username)
- Generate public/private keys using PKEKeyGen() and DSKeyGen()

- userUUID = bytesToUUID(HMACEval(k1, username))
- Determine if this UUID is already in the dataStore, if so, return

- Create new User struct
- Populate User with RSA_sk, DS_sk, and map[sharedfileUUID] = k6||k7
- This map[sharedfileUUID, your_version_of_filename] = k6||k7 will be a list of all files for which you have access to but are not an owner
- Pad User
- userEntry = HMACEval(k1, SymEnc(k2, IV, userdata)), SymEnc(k2, IV, userdata)
- datastore[userUUID] = userEntry

- keystore[username||"enc"] = RSA_pk
- keystore[username||"sig"] = DS_pk

- return userdata (is this safe) */
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	return &userdata, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.

/*GetUser
- Derive sourceKey = Argon2Key(password, username, 16)
- k1 = HMACEval(sourceKey, username)
- k2 = HMACEval(sourceKey, 1 + username)
- userUUID = bytesToUUID(HMACEval(k1, username))

- Check if userUUID is in the datastore. If not, return error
- a userUUID won't exist if the username/password combo is wrong (any other way to check this?)
- get the userEntry at userUUID
- Take HMACEval(k1, SymEnc(k2, IV, userdata)) and verify this with userEntry
- If not equal, return error
*/
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	return userdataptr, nil
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
// edge case, storing a file that's already stored

/*StoreFile
- Obtain username from userdata
- Derive sourceKey = Argon2Key(password, username, 16)  (how can the user find the password in the implementation?)
- k3 = HMACEval(sourceKey, filename + username + "enc")
- k4 = HMACEval(sourceKey, filename + username + "sig")
- k6 = HMACEval(sourceKey, filename + username + "shareEnc")
- k7 = HMACEval(sourceKey, filename + username + "shareSig")
- fileUUID = bytesToUUID(HMAC(k4, filename))
- sharedfileUUID = bytesToUUID(HMAC(k6, k7))

- Check if fileUUID or sharedfileUUID already exists in datastore. If so, return

- create fileData struct
- populate fileData with signature, ciphertext, and list_of_shared_people
- ciphertext = SymEnc(k3, IV, list(data))
- list_of_shared_people = list(userUUID of owner)  (when you first store a file, you are the only person who can access)
- signature = HMACEval(k4, ciphertext||list_of_shared_people)

- store datastore[fileUUID] = HMACEval(k4, SymEnc(k3, IV, fileData))
*/
func (userdata *User) StoreFile(filename string, data []byte) {
	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	return
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

/*ShareFile
- See if filename = your_version_of_filename in map[sharedfileUUID, your_version_of_filename] in userdata
- If so, you are trying to share a file for which you are not the owner
	- create magic_string = DSSign(sender's private key, PKEEnc(recipient's public key, k6||k7))

- If not,
- Obtain username from userdata
- Derive sourceKey = Argon2Key(password, username, 16)  (how can the user find the password in the implementation?)
- k3 = HMACEval(sourceKey, filename + username + "enc")
- k4 = HMACEval(sourceKey, filename + username + "sig")
- k6 = HMACEval(sourceKey, filename + username + "shareEnc")
- k7 = HMACEval(sourceKey, filename + username + "shareSig")
- magic_string = DSSign(sender's private key, PKEEnc(recipient's public key, k6||k7))

- fileUUID = bytesToUUID(HMAC(k4, filename))
- sharedfileUUID = bytesToUUID(HMAC(k6, k7))

- Find fileUUID in datastore
- If fileUUID doesn't exist, return
- If fileUUID exists, verify & decrypt the filedata and encrypt/HMAC it again with k6 & k7
- delete fileUUID from datastore

- Later, if Bob calls receiveFile, he will verify & decrypt magic_string, and use k6, k7 to calculate the sharedfileUUID
*/
func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {

	return
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {
	return nil
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	return
}
