package proj2

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
	Username    string
	SourceKey   []byte
	HmacKey     []byte
	SymKey      []byte
	UserUUID    uuid.UUID
	RsaSk       userlib.PKEDecKey
	DsSk        userlib.DSSignKey
	SharedFiles map[string]string
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type DataToStore struct {
	CipherText []byte
	Sigma      []byte
	Iv         []byte
}

type UserEntry struct {
	CipherText []byte
	Sigma      []byte
	Iv         []byte
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
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	// generate RSA encryption keys
	rsaPk, rsaSk, _ := userlib.PKEKeyGen()
	userlib.KeystoreSet(username+"enc", rsaPk)

	// generate RSA signature keys
	dsSk, dsPk, _ := userlib.DSKeyGen()
	userlib.KeystoreSet(username+"sig", dsPk)

	// generate other keys
	sourceKey, hmacKey, symKey := generateKeysForDataStore(username, password)

	// check if username already exists
	filename, _ := userlib.HMACEval(hmacKey[0:16], []byte(username))
	userUUID := bytesToUUID(filename)
	// if a user with the same username and password exists, return an error
	if _, ok := userlib.DatastoreGet(userUUID); ok {
		return nil, errors.New("Username already exists")
	}

	// initialize User struct
	userdataptr.Username = username
	userdataptr.SourceKey = sourceKey
	userdataptr.HmacKey = hmacKey[0:16]
	userdataptr.SymKey = symKey[0:16]
	userdataptr.UserUUID = userUUID
	userdataptr.RsaSk = rsaSk
	userdataptr.DsSk = dsSk
	userdataptr.SharedFiles = make(map[string]string)

	userdataMarshal, _ := json.Marshal(userdata)
	// userlib.DebugMsg("userdata: %v", string(userdataMarshal))

	// encrypt and store userdata in the datastore
	var encryptedData UserEntry
	iv := userlib.RandomBytes(16)
	encryptedData.Iv = iv
	encryptedData.CipherText = userlib.SymEnc(userdataptr.SymKey, iv, padString(userdataMarshal))
	encryptedData.Sigma, _ = userlib.HMACEval(userdataptr.HmacKey, encryptedData.CipherText)

	data, _ := json.Marshal(encryptedData)
	// userlib.DebugMsg("encrypted datatostore: %v", string(data))
	userdataptr.StoreFile(string(filename), data)

	return &userdata, nil
}

func generateKeysForDataStore(username string, password string) ([]byte, []byte, []byte) {
	sourceKey := userlib.Argon2Key([]byte(password), []byte(username), 16)
	hmacKey, _ := userlib.HMACEval(sourceKey, []byte(username))
	encKey, _ := userlib.HMACEval(sourceKey, []byte(username+"1"))
	return sourceKey, hmacKey, encKey
}

// pad with 0 and the last byte contains how many bytes of padding needed
// padding reference : https://sourcegraph.com/github.com/apexskier/cryptoPadding/-/blob/ansix923.go#L17
func padString(str []byte) []byte {
	var padBytes int
	if len(str)%userlib.AESBlockSize == 0 {
		padBytes = userlib.AESBlockSize
	} else {
		padBytes = userlib.AESBlockSize - (len(str) % userlib.AESBlockSize)
	}
	padText := []byte(strings.Repeat(string([]byte{byte(0)}), padBytes-1))
	str = append(str, append(padText, byte(padBytes))...)
	// userlib.DebugMsg("str length: %v", len(str))
	return str
}

func unpadString(str []byte) []byte {
	padBytes := int(str[len(str)-1])
	return str[0 : len(str)-padBytes]
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	return userdataptr, nil
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	fileUUID := bytesToUUID([]byte(filename))
	userlib.DatastoreSet(fileUUID, data)
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
