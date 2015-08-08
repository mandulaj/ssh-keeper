var crypto = require("crypto");
var fs = require("fs")


var packageJson = {
  "entry1": 1,
  "entry2": 2,
  "entry3": 3,
  "More": "secret",
  "secret":"secret",
  "LongText": "Updates the cipher with data, the encoding of which is given in input_encoding and can be 'utf8', 'ascii' or 'binary'. If no encoding is provided, then a buffer is expected. If data is a Buffer then input_encoding is ignored. \nThe output_encoding specifies the output format of the enciphered data, and can be 'binary', 'base64' or 'hex'. If no encoding is provided, then a buffer is returned.\nReturns the enciphered contents, and can be called many times with new data as it is streamed."
}

var HASH_FUNCTION = "sha256";



function encodeData(key, data, crypto_config) {
  var data_string;

  try {
    data_string = JSON.stringify(data);
  } catch (err) {
    console.error("Error converting data: ", err)
    return
  }

  var crypto_key = deriveKey(key, crypto_config)
  var enc = cipher(crypto_key, data_string, crypto_config)
  var rootJson =  {
    main: {
      data: enc.enc,
      iv: enc.iv,
      crypto_config: crypto_config
    }
  }
  var mac = hmac(crypto_key, JSON.stringify(rootJson.main))
  rootJson.mac = mac
  return rootJson;
}

function cipher(key, clearText, crypto_config) {
  var iv = crypto.randomBytes(16);

  var ciph = crypto.createCipheriv(crypto_config.cipher, key, iv)
  var enc = ciph.update(clearText,"utf8","base64")
  enc += ciph.final("base64")

  return {
    iv: iv.toString("base64"),
    enc: enc
  }

}


function hmac (key, data) {
  var mac = crypto.createHmac(HASH_FUNCTION, key);
  mac.update(data);
  return mac.digest("base64");
}

function deriveKey (key, crypto_config) {
    return crypto.pbkdf2Sync(key, crypto_config.salt, crypto_config.iteration, crypto_config.keyLength, HASH_FUNCTION)
}

/**
 * json
 *
*/
function decodeData(key, enc_json) {
  var hashkey = deriveKey(key, enc_json.main.crypto_config)
  var mac = hmac(hashkey, JSON.stringify(enc_json.main))
  if (mac === enc_json.mac) {
    console.log("success")
  } else {
    console.error("Mismatching HMAC")
    return null
  }
  var iv = new Buffer(enc_json.main.iv, "base64");
  var cipherText = new Buffer(enc_json.main.data, "base64")
  return decipher(hashkey, iv, cipherText, enc_json.main.crypto_config);

}




function decipher(key, iv, cipherText, crypto_config) {
  var dec = crypto.createDecipheriv(crypto_config.cipher,key, iv)

  var outputBuffer = dec.update(cipherText)
  outputBuffer += dec.final()

  return outputBuffer;
}

var testJson = encodeData("secret", packageJson, {cipher: "aes-256-ctr", salt: "salt", iteration: Math.pow(2,12), keyLength: 32})
console.log(testJson)
//fs.writeFileSync("enc.json", JSON.stringify(testJson))

var json = require("./enc.json")

var res = decodeData("secret", json)
console.log(JSON.parse(res))
