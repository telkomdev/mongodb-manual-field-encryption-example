package main

import (
	"context"
	"fmt"
	"time"

	"github.com/telkomdev/go-crypsi/aesx"
	"github.com/telkomdev/go-crypsi/hmacx"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Users struct {
	Name              string    `bson:"name,omitempty"`
	Email             string    `bson:"email,omitempty"`
	EmailHashed       string    `bson:"emailHashed,omitempty"` // The HASH version is used for Filter and Indexing
	CreaditCard       string    `bson:"creditCard,omitempty"`
	CreaditCardHashed string    `bson:"creditCardHashed,omitempty"` // The HASH version is used for Filter and Indexing
	CreatedAt         time.Time `bson:"createdAt,omitempty"`
}

const (
	MongoDBURI = "mongodb://admin:admin@localhost:27017/codebasedb?retryWrites=true&w=majority"
	AES256Key  = "abc$#128djdyAgbjau&YAnmcbagryt5x"
)

func main() {

	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(MongoDBURI))
	if err != nil {
		panic(err)
	}

	defer func() {
		if err = client.Disconnect(context.Background()); err != nil {
			panic(err)
		}
	}()

	// begin insertOne
	userCollection := client.Database("codebasedb").Collection("users")

	resultInsert, err := InsertUser(userCollection, "Andy", "andy@gmail.com", "4649938263657520")
	if err != nil {
		panic(err)
	}
	// end insertOne

	fmt.Println(resultInsert)

	resultInsert, err = InsertUser(userCollection, "Bony", "bony@gmail.com", "4649932469202470")
	if err != nil {
		panic(err)
	}
	// end insertOne

	fmt.Println(resultInsert)

	// find One
	userOne, err := FindByEmail(userCollection, "wuri@yahoo.com")
	if err != nil {
		panic(err)
	}

	fmt.Println(userOne)
}

func InsertUser(userCollection *mongo.Collection, name, email, creditCard string) (string, error) {
	emailEncrypted, err := aesx.EncryptWithAES256CBC([]byte(AES256Key), []byte(email))
	if err != nil {
		return "", err
	}

	emailHashed, err := hmacx.Sha256Hex([]byte(AES256Key), []byte(email))
	if err != nil {
		return "", err
	}

	creditCardEncrypted, err := aesx.EncryptWithAES256CBC([]byte(AES256Key), []byte(creditCard))
	if err != nil {
		return "", err
	}

	creditCardHashed, err := hmacx.Sha256Hex([]byte(AES256Key), []byte(creditCard))
	if err != nil {
		return "", err
	}

	user := Users{
		Name:              name,
		Email:             string(emailEncrypted),
		EmailHashed:       emailHashed,
		CreaditCard:       string(creditCardEncrypted),
		CreaditCardHashed: creditCardHashed,
		CreatedAt:         time.Now(),
	}

	resultInsert, err := userCollection.InsertOne(context.Background(), user)
	if err != nil {
		return "", err
	}
	// end insertOne

	return fmt.Sprintf("Document inserted with ID: %s", resultInsert.InsertedID), nil
}

func FindByEmail(userCollection *mongo.Collection, email string) (*Users, error) {
	// email should be hashed first, before being used in filters
	emailHashed, err := hmacx.Sha256Hex([]byte(AES256Key), []byte(email))
	if err != nil {
		return nil, err
	}

	// filter By Hashed Email
	findOneFilter := bson.D{{Key: "emailHashed", Value: emailHashed}}

	userOne := new(Users)
	err = userCollection.FindOne(context.Background(), findOneFilter).Decode(&userOne)
	if err != nil {
		return nil, err
	}

	// decrypt the encrypted data
	emailDecrypted, err := aesx.DecryptWithAES256CBC([]byte(AES256Key), []byte(userOne.Email))
	if err != nil {
		return nil, err
	}

	// set Email field with Decrypted Email
	userOne.Email = string(emailDecrypted)

	creditCardDecrypted, err := aesx.DecryptWithAES256CBC([]byte(AES256Key), []byte(userOne.CreaditCard))
	if err != nil {
		return nil, err
	}

	// set CreaditCard field with Decrypted CreaditCard
	userOne.CreaditCard = string(creditCardDecrypted)

	return userOne, nil
}

// mongo --username admin --password --authenticationDatabase codebasedb
