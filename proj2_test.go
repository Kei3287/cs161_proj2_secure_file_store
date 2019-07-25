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
}

func TestStore(t *testing.T) {
	t.Log("Testing StoreFile")
	userlib.SetDebugStatus(true)

	alice0001, err := InitUser("alice0001", "alice_password")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user alice0001", err)
		return
	}

	alice0001.StoreFile("file_x", []byte("My name is Barry Allen and I am the Flash"))
	alice0001.StoreFile("file_x", []byte("I am Flash"))

	alice0001.StoreFile("file_y", []byte("My name is Barry Allen and I am the Flash"))
	alice0001.StoreFile("file_z", []byte("I'm still the Flash"))

	bob0001, err := InitUser("bob0001", "bob_password")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user bob0001", err)
		return
	}

	bob0001.StoreFile("file_x", []byte("Alice think's she's the Flash, but she's not"))
	bob0001.StoreFile("file_a", []byte("I am the Flash"))

	aliceFilexEnckey, _ := userlib.HMACEval(alice0001.SourceKey, []byte("file_x"+alice0001.Username+"enc"))
	aliceFilexEnc, _ := userlib.HMACEval(aliceFilexEnckey[0:16], []byte("file_x"))
	aliceFilexUUID := bytesToUUID(aliceFilexEnc)

	aliceFileyEnckey, _ := userlib.HMACEval(alice0001.SourceKey, []byte("file_y"+alice0001.Username+"enc"))
	aliceFileyEnc, _ := userlib.HMACEval(aliceFileyEnckey[0:16], []byte("file_y"))
	aliceFileyUUID := bytesToUUID(aliceFileyEnc)

	aliceFilezEnckey, _ := userlib.HMACEval(alice0001.SourceKey, []byte("file_z"+alice0001.Username+"enc"))
	aliceFilezEnc, _ := userlib.HMACEval(aliceFilezEnckey[0:16], []byte("file_z"))
	aliceFilezUUID := bytesToUUID(aliceFilezEnc)

	bobFilexEnckey, _ := userlib.HMACEval(bob0001.SourceKey, []byte("file_x"+bob0001.Username+"enc"))
	bobFilexEnc, _ := userlib.HMACEval(bobFilexEnckey[0:16], []byte("file_x"))
	bobFilexUUID := bytesToUUID(bobFilexEnc)

	bobFileaEnckey, _ := userlib.HMACEval(bob0001.SourceKey, []byte("file_a"+bob0001.Username+"enc"))
	bobFileaEnc, _ := userlib.HMACEval(bobFileaEnckey[0:16], []byte("file_a"))
	bobFileaUUID := bytesToUUID(bobFileaEnc)

	alice0001Enc, _ := userlib.HMACEval(alice0001.HmacKey[0:16], []byte(alice0001.Username))
	alice0001UUID := bytesToUUID(alice0001Enc)

	bob0001Enc, _ := userlib.HMACEval(bob0001.HmacKey[0:16], []byte(bob0001.Username))
	bob0001UUID := bytesToUUID(bob0001Enc)

	entireDatastore := userlib.DatastoreGetMap()

	datastoreKeys := make([]userlib.UUID, len(entireDatastore))
	i := 0
	for k := range entireDatastore {
		datastoreKeys[i] = k
		i++
	}

	localDatastoreKeys := []userlib.UUID{aliceFilexUUID, aliceFileyUUID, aliceFilezUUID, bobFilexUUID, bobFileaUUID, alice0001UUID, bob0001UUID}

	// These print statements show what is inside the two lists. Do TestLoad later to actually see if file values fetched are correct
	//fmt.Println(localDatastoreKeys)
	//fmt.Println(datastoreKeys)

	if reflect.DeepEqual(localDatastoreKeys, datastoreKeys) {
		t.Error("datastore keys not correct")
		return
	}
}

func TestLoadFile(t *testing.T) {
	t.Log("Testing StoreFile")
	userlib.SetDebugStatus(true)

	alice0002, err := InitUser("alice0002", "alice_password")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user alice0002", err)
		return
	}

	bob0002, err := InitUser("bob0002", "bob_password")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user bob0002", err)
		return
	}

	alice0002.StoreFile("file1", []byte("pizza does not belong on pepperoni"))
	alice0002.StoreFile("file2", []byte("Bob, I think the government is onto me."))

	alicefile1, _ := alice0002.LoadFile("file1")
	if !reflect.DeepEqual(alicefile1, []byte("pizza does not belong on pepperoni")) {
		t.Error("alicefile1 contents incorrect")
		return
	}

	alicefile2, _ := alice0002.LoadFile("file2")
	if !reflect.DeepEqual(alicefile2, []byte("Bob, I think the government is onto me.")) {
		t.Error("alicefile2 contents incorrect")
		return
	}

	alice0002.StoreFile("file1", []byte("I have updated file1"))

	alicefile1, _ = alice0002.LoadFile("file1")
	if !reflect.DeepEqual(alicefile1, []byte("pizza does not belong on pepperoni")) {
		t.Error("alicefile1 contents incorrect") // This implementation assumes calling StoreFile on an existing filename doesn't update it. Debatable
		return
	}

	bob0002.StoreFile("file1", []byte("I like to make my filenames the same name as Alice's filenames to troll her"))

	bobfile1, _ := bob0002.LoadFile("file1")
	if !reflect.DeepEqual(bobfile1, []byte("I like to make my filenames the same name as Alice's filenames to troll her")) {
		t.Error("bobfile1 contents incorrect")
		return
	}

	bob0002.StoreFile("Bob's Favorite File", []byte("I have been tracked down by Dr. Phil and must retreat back into the woods"))

	bobfilefavorite, _ := bob0002.LoadFile("Bob's Favorite File")
	if !reflect.DeepEqual(bobfilefavorite, []byte("I have been tracked down by Dr. Phil and must retreat back into the woods")) {
		t.Error("bobfile1 contents incorrect")
		return
	}

}

//func TestStorage(t *testing.T) {
//	// And some more tests, because
//	u, err := GetUser("alice", "fubar")
//	if err != nil {
//		t.Error("Failed to reload user", err)
//		return
//	}
//	t.Log("Loaded user", u)
//
//	v := []byte("This is a test")
//	u.StoreFile("file1", v)
//
//	v2, err2 := u.LoadFile("file1")
//	if err2 != nil {
//		t.Error("Failed to upload and download", err2)
//		return
//	}
//	if !reflect.DeepEqual(v, v2) {
//		t.Error("Downloaded file is not the same", v, v2)
//		return
//	}
//}

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
