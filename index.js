const { MongoClient, Binary } = require('mongodb');
const { aesEncryption, hmac } = require('crypsi');

const AES_256_KEY = 'abc$#128djdyAgbjau&YAnmcbagryt5x';
const MONGODB_URI = "mongodb://admin:admin@localhost:27017/codebasedb?retryWrites=true&w=majority";

async function insertData(name, email, creditCard) {
    try {
        const database = 'codebasedb';

        const userCollections = 'users';

        const options = {
            keepAlive: true,
            maxPoolSize: 50,
            socketTimeoutMS: 10000,
            connectTimeoutMS: 10000
        };

        const client = new MongoClient(MONGODB_URI, options);

        await client.connect();

        const encryptedEmail = aesEncryption.encryptWithAes256Cbc(AES_256_KEY, email).toString('hex');
        const emailHashed = hmac.sha256(AES_256_KEY, email);

        const creditCardEncrypted = aesEncryption.encryptWithAes256Cbc(AES_256_KEY, creditCard).toString('hex');
        const creditCardHashed = hmac.sha256(AES_256_KEY, creditCard);

        const db = client.db(database);
        await db.collection(userCollections).insertOne({
            name: name,
            email: encryptedEmail,
            emailHashed: emailHashed,
            creditCard: creditCardEncrypted,
            creditCardHashed: creditCardHashed,
            createdAt: new Date(),
        });

        await client.close();
    } catch(e) {
        console.log('error connecting to database server', e);
    }
}

async function findByEmail(email) {
    try {
        const database = 'codebasedb';

        const userCollections = 'users';

        const options = {
            keepAlive: true,
            maxPoolSize: 50,
            socketTimeoutMS: 10000,
            connectTimeoutMS: 10000
        };

        const client = new MongoClient(MONGODB_URI, options);

        await client.connect();

        // email should be hashed first, before being used in filters
        const emailHashed = hmac.sha256(AES_256_KEY, email);

        // filter By Hashed Email
	    const findOneFilter = {"emailHashed": emailHashed};

        const db = client.db(database);
        const userOne = await db.collection(userCollections).findOne(findOneFilter);

        // set Email field with Decrypted Email
        userOne.email = aesEncryption.decryptWithAes256Cbc(AES_256_KEY, userOne.email).toString();

        // set CreaditCard field with Decrypted CreaditCard
        userOne.creditCard = aesEncryption.decryptWithAes256Cbc(AES_256_KEY, userOne.creditCard).toString();

        console.log(userOne);

        await client.close();
    } catch(e) {
        console.log('error connecting to database server', e);
    }
}

// test

// insertData('wuri', 'wuri@yahoo.com', '4649931847550758')
// .then(() => console.log('insert data succeed'))
// .catch(e => console.log(e));

findByEmail('andy@gmail.com')
.then(() => console.log('read data succeed'))
.catch(e => console.log(e));