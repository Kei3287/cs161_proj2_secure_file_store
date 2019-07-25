package proj2

import (
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/google/uuid"
	"github.com/ryanleh/cs161-p2/userlib"
)

// when running go test -v, make sure to use unique username throught the test file

func TestInit(t *testing.T) {
	t.Log("Initialization test")

	// You may want to turn it off someday
	userlib.SetDebugStatus(true)
	// someUsefulThings()  //  Don't call someUsefulThings() in the autograder in case a student removes it
	// userlib.SetDebugStatus(false)
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}

func TestInitError(t *testing.T) {
	t.Log("Initialization test")
	userlib.SetDebugStatus(true)
	u, err := InitUser("alice2", "p")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u, err = InitUser("alice2", "p")
	if err == nil {
		t.Error("Failed to initialize user", err)
		return
	}

	t.Log("should return nil")
	t.Log("Got user", u)
}

func TestGetUser(t *testing.T) {
	t.Log("getUser test")
	userlib.SetDebugStatus(true)
	username := "alice3"
	password := "pass"
	u, err := InitUser(username, password)
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u, err = GetUser(username, password)
	if err != nil {
		t.Error(err)
		return
	}
	t.Log("Got user", u)
	sourceKey := userlib.Argon2Key([]byte(password), []byte(username), 16)
	hmacKey, symKey := generateKeysForDataStore(username, sourceKey)
	u.SymKey = symKey
	filename, _ := userlib.HMACEval(hmacKey[0:16], []byte(username))
	userUUID := bytesToUUID(filename)
	if u.Username != username || u.UserUUID != userUUID {
		t.Error("data doesn't match")
		return
	}
}

<<<<<<< HEAD
func TestStore(t *testing.T) {
	t.Log("Testing StoreFile")
	userlib.SetDebugStatus(true)

	alice5, err := InitUser("alice5", "alice_password")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user Alice", err)
		return
	}

	alice5.StoreFile("file_x", []byte("My name is Barry Allen and I am the Flash"))
	alice5.StoreFile("file_x", []byte("I am Flash"))

	alice5.StoreFile("file_y", []byte("My name is Barry Allen and I am the Flash"))
	alice5.StoreFile("file_z", []byte("I'm still the Flash"))

	bob5, err := InitUser("bob5", "bob_password")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user Bob", err)
		return
	}

	bob5.StoreFile("file_x", []byte("Alice think's she's the Flash, but she's not"))
	bob5.StoreFile("file_a", []byte("I am the Flash"))

	aliceFilexEnckey, _ := userlib.HMACEval(alice5.SourceKey, []byte("file_x"+alice5.Username+"enc"))
	aliceFilexEnc, _ := userlib.HMACEval(aliceFilexEnckey[0:16], []byte("file_x"))
	aliceFilexUUID := bytesToUUID(aliceFilexEnc)

	aliceFileyEnckey, _ := userlib.HMACEval(alice5.SourceKey, []byte("file_y"+alice5.Username+"enc"))
	aliceFileyEnc, _ := userlib.HMACEval(aliceFileyEnckey[0:16], []byte("file_y"))
	aliceFileyUUID := bytesToUUID(aliceFileyEnc)

	aliceFilezEnckey, _ := userlib.HMACEval(alice5.SourceKey, []byte("file_z"+alice5.Username+"enc"))
	aliceFilezEnc, _ := userlib.HMACEval(aliceFilezEnckey[0:16], []byte("file_z"))
	aliceFilezUUID := bytesToUUID(aliceFilezEnc)

	bobFilexEnckey, _ := userlib.HMACEval(bob5.SourceKey, []byte("file_x"+bob5.Username+"enc"))
	bobFilexEnc, _ := userlib.HMACEval(bobFilexEnckey[0:16], []byte("file_x"))
	bobFilexUUID := bytesToUUID(bobFilexEnc)

	bobFileaEnckey, _ := userlib.HMACEval(bob5.SourceKey, []byte("file_a"+bob5.Username+"enc"))
	bobFileaEnc, _ := userlib.HMACEval(bobFileaEnckey[0:16], []byte("file_a"))
	bobFileaUUID := bytesToUUID(bobFileaEnc)

	alice5Enc, _ := userlib.HMACEval(alice5.HmacKey[0:16], []byte(alice5.Username))
	alice5UUID := bytesToUUID(alice5Enc)

	bob5Enc, _ := userlib.HMACEval(bob5.HmacKey[0:16], []byte(bob5.Username))
	bob5UUID := bytesToUUID(bob5Enc)

	entireDatastore := userlib.DatastoreGetMap()

	datastoreKeys := make([]userlib.UUID, len(entireDatastore))
	i := 0
	for k := range entireDatastore {
		datastoreKeys[i] = k
		i++
	}

	localDatastoreKeys := []userlib.UUID{aliceFilexUUID, aliceFileyUUID, aliceFilezUUID, bobFilexUUID, bobFileaUUID, alice5UUID, bob5UUID}

	// These print statements show what is inside the two lists. Do TestLoad later to actually see if file values fetched are correct
	//fmt.Println(localDatastoreKeys)
	//fmt.Println(datastoreKeys)

	if reflect.DeepEqual(localDatastoreKeys, datastoreKeys) {
		t.Error("datastore keys not correct")
		return
	}
=======
func TestGetUserError(t *testing.T) {
	t.Log("getUserError test")
	userlib.SetDebugStatus(true)
	username := "alice4"
	password := "pass"
	u, err := InitUser(username, password)
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u, err = GetUser("a", password)
	if err == nil {
		t.Error("failed to get an error")
		return
	}
	u, err = GetUser(username, "fake password")
	if err == nil {
		t.Error("failed to get an error")
		return
	}

	t.Log("should return nil")
	t.Log("Got user", u)
}

func generateKeyAndUUID(username string, password string) (hmacKey []byte, symKey []byte, userUUID uuid.UUID) {
	sourceKey := userlib.Argon2Key([]byte(password), []byte(username), 16)
	hmacKey, symKey = generateKeysForDataStore(username, sourceKey)
	filename, _ := userlib.HMACEval(hmacKey[0:16], []byte(username))
	userUUID = bytesToUUID(filename)
	return hmacKey, symKey, userUUID
}

func TestGetUserAttack(t *testing.T) {
	t.Log("getUserAttack test")
	userlib.SetDebugStatus(true)
	username5 := "alice5"
	username6 := "alice6"
	username7 := "alice7"
	username8 := "alice8"
	password := "pass"
	u, err := InitUser(username5, password)
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, _, userUUID := generateKeyAndUUID(username5, password)

	// datastore delete entry attack
	userlib.DatastoreDelete(userUUID)
	u, err = GetUser(username5, password)
	if err == nil {
		t.Error("failed to detect the corruption of data")
		return
	}

	// keystore clear attack
	u, err = InitUser(username6, password)
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	userlib.KeystoreClear()
	u, err = GetUser(username6, password)
	if err == nil {
		t.Error("failed to detect the corruption of data")
		return
	}

	// modify the data on datastore attack
	u, err = InitUser(username7, password)
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u, err = InitUser(username8, password)
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	_, _, userUUID7 := generateKeyAndUUID(username7, password)
	_, _, userUUID8 := generateKeyAndUUID(username8, password)
	val, _ := userlib.DatastoreGet(userUUID7)
	userlib.DatastoreSet(userUUID8, val)
	u, err = GetUser(username8, password)
	if err == nil {
		t.Error("failed to detect the corruption of data")
		return
	}

	t.Log("should return nil")
	t.Log("Got user", u)
>>>>>>> 7d88a10b52be4bc1520f923586d366d2c95b5e5a
}

// func TestStorage(t *testing.T) {
// 	// And some more tests, because
// 	u, err := GetUser("alice", "fubar")
// 	if err != nil {
// 		t.Error("Failed to reload user", err)
// 		return
// 	}
// 	t.Log("Loaded user", u)

// 	v := []byte("This is a test")
// 	u.StoreFile("file1", v)

// 	v2, err2 := u.LoadFile("file1")
// 	if err2 != nil {
// 		t.Error("Failed to upload and download", err2)
// 		return
// 	}
// 	if !reflect.DeepEqual(v, v2) {
// 		t.Error("Downloaded file is not the same", v, v2)
// 		return
// 	}
// }

// func TestShare(t *testing.T) {
// 	u, err := GetUser("alice", "fubar")
// 	if err != nil {
// 		t.Error("Failed to reload user", err)
// 		return
// 	}
// 	u2, err2 := InitUser("bob", "foobar")
// 	if err2 != nil {
// 		t.Error("Failed to initialize bob", err2)
// 		return
// 	}

// 	var v, v2 []byte
// 	var magic_string string

// 	v, err = u.LoadFile("file1")
// 	if err != nil {
// 		t.Error("Failed to download the file from alice", err)
// 		return
// 	}

// 	magic_string, err = u.ShareFile("file1", "bob")
// 	if err != nil {
// 		t.Error("Failed to share the a file", err)
// 		return
// 	}
// 	err = u2.ReceiveFile("file2", "alice", magic_string)
// 	if err != nil {
// 		t.Error("Failed to receive the share message", err)
// 		return
// 	}

// 	v2, err = u2.LoadFile("file2")
// 	if err != nil {
// 		t.Error("Failed to download the file after sharing", err)
// 		return
// 	}
// 	if !reflect.DeepEqual(v, v2) {
// 		t.Error("Shared file is not the same", v, v2)
// 		return
// 	}

// }
