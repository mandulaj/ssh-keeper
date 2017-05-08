/*jshint esversion: 6*/

var crypto = require("crypto");
var zlib = require('zlib');
var fs = require("fs");


var packageJson = {
  "entry1": 1,
  "entry2": 2,
  "entry3": 3,
  "Very Long text1": "Et ad ullam ipsa quia. Temporibus voluptas provident voluptas consequatur a dolores. Quae cumque iure possimus adipisci eius. Corrupti natus esse aut aut. Aut fugit hic eius praesentium autem ea. Labore dolorum sed sit. Enim rerum libero deserunt assumenda dolorum numquam quos rem. Rem et sit rerum adipisci. Rem vel laudantium amet qui reprehenderit. Odit nobis dolor perspiciatis ex. Dolores accusamus corrupti dolorum a impedit. Non praesentium ipsam repellendus repudiandae sit dignissimos voluptates voluptatem. Enim debitis doloremque earum consequatur consectetur voluptatem quibusdam ut. Dolores at esse voluptate rerum sunt. Ullam dolor atque itaque. Iure iusto perspiciatis saepe ea quia rerum est. Neque eaque in qui molestias. Impedit soluta officia consectetur incidunt corrupti. Odio accusamus rem aliquid enim. Unde eum et voluptatum voluptatum. Enim repellat maiores consequatur dolor excepturi mollitia. Nemo id nobis voluptas rem. Tempore voluptatibus exercitationem blanditiis. Officia occaecati assumenda impedit voluptas voluptas.",
  "Very Long text2": "Et ad ullam ipsa quia. Temporibus voluptas provident voluptas consequatur a dolores. Quae cumque iure possimus adipisci eius. Corrupti natus esse aut aut. Aut fugit hic eius praesentium autem ea. Labore dolorum sed sit. Enim rerum libero deserunt assumenda dolorum numquam quos rem. Rem et sit rerum adipisci. Rem vel laudantium amet qui reprehenderit. Odit nobis dolor perspiciatis ex. Dolores accusamus corrupti dolorum a impedit. Non praesentium ipsam repellendus repudiandae sit dignissimos voluptates voluptatem. Enim debitis doloremque earum consequatur consectetur voluptatem quibusdam ut. Dolores at esse voluptate rerum sunt. Ullam dolor atque itaque. Iure iusto perspiciatis saepe ea quia rerum est. Neque eaque in qui molestias. Impedit soluta officia consectetur incidunt corrupti. Odio accusamus rem aliquid enim. Unde eum et voluptatum voluptatum. Enim repellat maiores consequatur dolor excepturi mollitia. Nemo id nobis voluptas rem. Tempore voluptatibus exercitationem blanditiis. Officia occaecati assumenda impedit voluptas voluptas.",
  "Very Long text3": "Et ad ullam ipsa quia. Temporibus voluptas provident voluptas consequatur a dolores. Quae cumque iure possimus adipisci eius. Corrupti natus esse aut aut. Aut fugit hic eius praesentium autem ea. Labore dolorum sed sit. Enim rerum libero deserunt assumenda dolorum numquam quos rem. Rem et sit rerum adipisci. Rem vel laudantium amet qui reprehenderit. Odit nobis dolor perspiciatis ex. Dolores accusamus corrupti dolorum a impedit. Non praesentium ipsam repellendus repudiandae sit dignissimos voluptates voluptatem. Enim debitis doloremque earum consequatur consectetur voluptatem quibusdam ut. Dolores at esse voluptate rerum sunt. Ullam dolor atque itaque. Iure iusto perspiciatis saepe ea quia rerum est. Neque eaque in qui molestias. Impedit soluta officia consectetur incidunt corrupti. Odio accusamus rem aliquid enim. Unde eum et voluptatum voluptatum. Enim repellat maiores consequatur dolor excepturi mollitia. Nemo id nobis voluptas rem. Tempore voluptatibus exercitationem blanditiis. Officia occaecati assumenda impedit voluptas voluptas.",
  "Very Long text4": "Et ad ullam ipsa quia. Temporibus voluptas provident voluptas consequatur a dolores. Quae cumque iure possimus adipisci eius. Corrupti natus esse aut aut. Aut fugit hic eius praesentium autem ea. Labore dolorum sed sit. Enim rerum libero deserunt assumenda dolorum numquam quos rem. Rem et sit rerum adipisci. Rem vel laudantium amet qui reprehenderit. Odit nobis dolor perspiciatis ex. Dolores accusamus corrupti dolorum a impedit. Non praesentium ipsam repellendus repudiandae sit dignissimos voluptates voluptatem. Enim debitis doloremque earum consequatur consectetur voluptatem quibusdam ut. Dolores at esse voluptate rerum sunt. Ullam dolor atque itaque. Iure iusto perspiciatis saepe ea quia rerum est. Neque eaque in qui molestias. Impedit soluta officia consectetur incidunt corrupti. Odio accusamus rem aliquid enim. Unde eum et voluptatum voluptatum. Enim repellat maiores consequatur dolor excepturi mollitia. Nemo id nobis voluptas rem. Tempore voluptatibus exercitationem blanditiis. Officia occaecati assumenda impedit voluptas voluptas.",
  "Very Long text5": "Et ad ullam ipsa quia. Temporibus voluptas provident voluptas consequatur a dolores. Quae cumque iure possimus adipisci eius. Corrupti natus esse aut aut. Aut fugit hic eius praesentium autem ea. Labore dolorum sed sit. Enim rerum libero deserunt assumenda dolorum numquam quos rem. Rem et sit rerum adipisci. Rem vel laudantium amet qui reprehenderit. Odit nobis dolor perspiciatis ex. Dolores accusamus corrupti dolorum a impedit. Non praesentium ipsam repellendus repudiandae sit dignissimos voluptates voluptatem. Enim debitis doloremque earum consequatur consectetur voluptatem quibusdam ut. Dolores at esse voluptate rerum sunt. Ullam dolor atque itaque. Iure iusto perspiciatis saepe ea quia rerum est. Neque eaque in qui molestias. Impedit soluta officia consectetur incidunt corrupti. Odio accusamus rem aliquid enim. Unde eum et voluptatum voluptatum. Enim repellat maiores consequatur dolor excepturi mollitia. Nemo id nobis voluptas rem. Tempore voluptatibus exercitationem blanditiis. Officia occaecati assumenda impedit voluptas voluptas.",
  "More": "secret",
  "secret":"secret",
  "LongText": "Updates the cipher with data, the encoding of which is given in input_encoding and can be 'utf8', 'ascii' or 'binary'. If no encoding is provided, then a buffer is expected. If data is a Buffer then input_encoding is ignored. \nThe output_encoding specifies the output format of the enciphered data, and can be 'binary', 'base64' or 'hex'. If no encoding is provided, then a buffer is returned.\nReturns the enciphered contents, and can be called many times with new data as it is streamed."
};



var defaultOptions = {
  cipher: 'aes-256-ctr',
  digest: 'sha256',
  keyLength: 32,
  iterations: Math.pow(2,12)
};

class SecureJson {
  constructor(key, data, config) {
    this.key = key; // Buffer
    this.data = data; // Object
    this.config = config || defaultOptions;
    this.header = {
      cipher: this.config.cipher,
      digest: this.config.digest,
      keyLength: this.config.keyLength,
      iterations: this.config.iterations,
      saltCipher: null,
      saltHMAC: null,
      iv: null,
    };

    this.secureData = null; // base64 string

  }
  Encrypt (){
    return Promise.all([getRandomDataPromise(16),getRandomDataPromise(32),getRandomDataPromise(32)])
      .then(([iv,saltCipher, saltHmac])=>{
          this.header.iv = iv;
          this.header.saltCipher = saltCipher;
          this.header.saltHMAC = saltHmac;

          return this.data;
      })
      .then(this.encodeData.bind(this))
      .then(this.deflateData.bind(this))
      .then(this.cipherData.bind(this))
      .then(this.packageData.bind(this))
      .then(this.hmacData.bind(this))
      .catch(console.log);

  }

  encodeData(data) {
    return Buffer.from(JSON.stringify(data));
  }

  decodeData(data) {
    return JSON.parse(data);
  }

  deflateData(data) {
    return zlib.deflateRawSync(data);
  }

  inflateData(data) {
    return zlib.inflateRawSync(data);
  }

  // Generates a new IV and returns
  cipherData(data) {
    var key = deriveKey(this.key, this.header.saltCipher, this.header);

    var ciph = crypto.createCipheriv(this.config.cipher, key, this.header.iv);
    var enc = ciph.update(data);
    enc = Buffer.concat([enc,ciph.final()]);
    return enc;

  }

  decipherData(data) {
    var key = deriveKey(this.key, this.header.saltCipher, this.header);
    var dec = crypto.createDecipheriv(this.header.cipher,key, this.header.iv);

    var outputBuffer = dec.update(data);
    outputBuffer = Buffer.concat([outputBuffer, dec.final()]);

    return outputBuffer;
  }

  packageData (encipheredData) {
    return {
      header: {
        cipher: this.header.cipher,
        digest: this.header.digest,
        keyLength: this.header.keyLength,
        iterations: this.header.iterations,
        saltCipher: this.header.saltCipher.toString('base64'),
        saltHMAC: this.header.saltHMAC.toString('base64'),
        iv: this.header.iv.toString('base64')
      },
      data: encipheredData.toString('base64')
    };
  }

  depackageData(main) {
    this.header.cipher = main.header.cipher;
    this.header.saltCipher = Buffer.from(main.header.saltCipher, "base64");
    this.header.iv = Buffer.from(main.header.iv, "base64");

    var data = Buffer.from(main.data,"base64");
    return data;
  }

  depackageForMAC(main) {
    this.header.digest = main.header.digest;
    this.header.keyLength = main.header.keyLength;
    this.header.iterations = main.header.iterations;
    this.header.saltHMAC = Buffer.from(main.header.saltHMAC,"base64");
  }

  hmacData (main) {
    var stringified = Buffer.from(this.encodeData(main));
    var macCheck = this.hmac(stringified);
    this.secureData = {
      main: stringified.toString('base64'),
      hmac: macCheck.toString('base64')
    };

    return this.secureData;

  }

  checkHMAC(data){

    var mainStringified = Buffer.from(data.main,'base64');
    var main = this.decodeData(mainStringified.toString());
    this.depackageForMAC(main);
    var macTag = Buffer.from(data.hmac,"base64");

    var macCheck = this.hmac(mainStringified);

    if(!Buffer.compare(macTag, macCheck)) {
      return main;
    } else {
      throw "Invalid MAC";
    }
  }



  hmac (data) {
    var key = deriveKey(this.key, this.header.saltHMAC, this.header);
    var mac = crypto.createHmac(this.header.digest, key);
    mac.update(data);

    return mac.digest();
  }




  /**
  * json
  *
  */
  Decrypt() {
    return Promise.resolve(this.secureData)
      .then(this.checkHMAC.bind(this))
      .then(this.depackageData.bind(this))
      .then(this.decipherData.bind(this))
      .then(this.inflateData.bind(this))
      .then(this.decodeData.bind(this))
      .catch(console.log);


  }
}

function getRandomDataPromise(num) {
  return new Promise((resolve, reject)=>{
    crypto.randomBytes(num, (err, data)=>{
      if(err) return reject(err);
      resolve(data);
    });
  });
}

function deriveKey (key, salt, crypto_config) {
  return crypto.pbkdf2Sync(key, salt, crypto_config.iterations, crypto_config.keyLength, crypto_config.digest);
}


/*
var testJson = encodeData("secret", packageJson, {cipher: "aes-256-ctr", salt: "salt", iterations: Math.pow(2,12), keyLength: 32});
console.log(testJson);
//fs.writeFileSync("enc.json", JSON.stringify(testJson))

var json = require("./enc.json");

var res = decodeData("secret", json);
console.log(JSON.parse(res));*/


var secureData = new SecureJson(Buffer.from("secret"), packageJson, {cipher: 'aes-256-ctr', digest:'sha256', iterations:Math.pow(2,12), keyLength: 32});

secureData.Encrypt().then((data)=>{
  console.log("Done Encrypt");
  console.log(data);
});


var input = { main: 'eyJoZWFkZXIiOnsiY2lwaGVyIjoiYWVzLTI1Ni1jYmMiLCJkaWdlc3QiOiJzaGEyNTYiLCJrZXlMZW5ndGgiOjMyLCJpdGVyYXRpb25zIjo0MDk2LCJzYWx0Q2lwaGVyIjoiOHhtcDdWNk95eGRQOHNYOHdGaTFWV29uU2liLzMzWm9qaUhNOFQ1V0l0az0iLCJzYWx0SE1BQyI6IjRrOUEvbGg3bmJMdFJURnZZMU9wWm5LWVpxOHpDTEtPMlRWWnJDVzFCTm89IiwiaXYiOiIvQmRNM1VHT0dMTGpHd0pWYkg4TlhnPT0ifSwiZGF0YSI6IlVRS0s3SjBkb0xHTmErRGFpeVVnRDB2aGptTlcyK1ptS3JzNytqOEdHZEZjd1Q3R0VkMjNjVzB0VUczczlBZ0xMVHV0bDdoRURaQURMbXlRenAxRWViUjl0UDJOWDN6MXhWdnRFM3JGY2dUSmZnUHlxdXZaLzJyeGc4MzlGZit5ZDZ4ZU02SUlDQUE2V2lkclRsbE1oWXFGUkl2eXloVk9RbjJoRW1GZTlwdER4Sjc1QnRpcGp5bmtneWNvZG5IeWsxSjFUKzkyK1N0UmtJMUk1UTU4bVJxOFVBSS9vbWJBOERJczBEUDQyZWRzU2FHNmJGSk5JUG5LWlJuZ3lYK0hnaHFJWmhFa2VUWGsvZnd0a1ZwVDE0SGRFWlN4RmF1em5nRHVUTXhDU0lvQmt1Z2xaTzBLV3dFUXAyUDNpUzRvV2FLSExUZW9nemtuZE9NdWZibm5NNUtXWWt1TFlyaXZtU202ZStLU1lteDJobEtPRStqaTR3RE1BY0x5M1FVOW5IbWppdmRhakZBT2hJOE9iVW9qdEZUUndRdHlPSW5NWkxTbE96NXlpNVAxa2t2UktuZFdnMkk0VUZXT0hDdkZQSXZLQk1UZUFWL09iYU1DLzBBcWdhRWVDYW1vWC9OL0NhTGVONCsvU29lSDJFRjI3V21CZ1l3YzM2Z0FrOTg5c3FmSE9HaGs4N21aZE5OMTMyem1maERrQ2tVaDNFa2NNZGVIQXhZWndEdmxTcEhNU3RPRmgyQ2xRQjhEaDBLNERFRTh1TExsM2Z5WGE1QnlWdmRtUlR4Z2JlWG0wQnBUbHBORG9ibHdQb2Jqdm1ORkV5VFIzeElRMzliRERpR2NkZnJreHI1eXNrbUR6RlZYcWluVWxPVmh4aGVnNzVsdVluSE80Rk5GN0dnLzhxaDIxV3c4Ri83aVlnV2oxSEwyUHlUZWV2Ti9EcmhQdld3THBsSnZNSmJ4UytsQ3pPWEgyR2RZUEZ4ajRyNXlWMTNIWFFub0pqZExJa2FhRy9QNVVZT1E1Wngra2w0UmladnFLcFZrdW9mMk52V2tORFNoMGxUU1RsQS9CdkJzTk5ZdThKeDY5V1ZxODRaZ2dlN1JSd1d2NmFuMmxtV0IwaHREbEFodzRUNCtyZzNwUDVJUzZtNHJKSU55SForaDNlM2prVFhmYWpSR0VYQTUvK2Y1YWE2T2IveW4xOG9oZUxOUHZnN1FwZzF0SGUwZWVyMkdiU2FDbS9NM0xocmI2WWR6ZEp6dWcvV1ZjVXVEQ1VpRlBjV2ZrMUw3aXdZTTFTR2w3Mkl6aGRHQ20vZE5XbmtkaEsyMjU2TTV3SzZuUFh6L0NvZ0g1TVlSZ2FWdG96ME96Mm5Md1ArSDZzZ3c5MWhTSXNOUkladVoxbTl0RENmM2cwWjhmWS9ac3Qxazc1RnhjN0hQQWp0NUFnOCtxUHB6b3A0ZkZ6NVp4ZVlwRjZvKzJqdHRzRzRyLzZmM2tKN0p1cjJUcWRKcE5RPT0ifQ==',
  hmac: 'pYlYRg6PLy81jsAQDpQN30aQsOOU42oETYuJw5hax3Q=' };


var newData = new SecureJson(Buffer.from('secret'))
newData.secureData = input

newData.Decrypt().then((data)=>{
  console.log("Done Decrypt");
  console.log(data);
});

//setTimeout(()=>{}, 2000)
