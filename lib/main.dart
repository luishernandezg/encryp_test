import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:flutter/material.dart';
import 'package:jose/jose.dart';

Future<void> main() async {
  /*----------------------Create a JWE----------------------------*/
  print('---------------TEST WHIT jose package--------------------');
  // create a builder
  var builder = JsonWebEncryptionBuilder();

  // set the content
  builder.stringContent = "Hello world!";

  // set some protected header
  // builder.setProtectedHeader("createdAt", DateTime.now().toIso8601String());

  // add a key to encrypt the Content Encryption Key
  var jwkTest = JsonWebKey.generate('A128CBC-HS256');
  var jwk2 = JsonWebKey.symmetric(key: BigInt.parse("1234567891234567"));

  var jwk = JsonWebKey.fromJson(
    {
      "kty": "oct",
      "k": "MTIzNDU2Nzg5MTIzNDU2Nzg5MTIzNDU2Nzg5MTIzNDU=",
      "alg": "A128CBC-HS256",
      "use": "enc",
      "keyOperations": ['encrypt', 'decrypt'],
    },
  );

  print("jwkTest: $jwkTest");
  print("jwk: $jwk");
  print("jwk.keyType: ${jwk.keyType}");
  print("jwk.algorithm: ${jwk.algorithm}");

  builder.addRecipient(jwk, algorithm: "dir");

  // set the content encryption algorithm to use
  builder.encryptionAlgorithm = "A128CBC-HS256";

  // build the jws
  var jwe = builder.build();
  print("commonHeader ${jwe.commonHeader}");
  print("sharedUnprotectedHeader ${jwe.sharedUnprotectedHeader}");
  print("recipients ${jwe.recipients}");

  // output the compact serialization
  print("jwe compact serialization: ${jwe.toCompactSerialization()}");

  // output the json serialization
  print("jwe json serialization: ${jwe.toJson()}");

  /*----------------------Decode and decrypt a JWE----------------------------*/

  var encoded = jwe.toCompactSerialization();

  // create a JsonWebEncryption from the encoded string
  var jwe2 = JsonWebEncryption.fromCompactSerialization(encoded);

  var keyStore = JsonWebKeyStore()..addKey(jwk);

  // decrypt the payload
  var payload = await jwe2.getPayload(keyStore);
  print("decrypted content: ${payload.stringContent}");

  /////////////////////////////////////////////////////////////////////////////
  print('---------------TEST WHIT cryptography package--------------------');
  final message = utf8.encode('Hello encryption!');

  final algorithm = AesGcm.with256bits();
  final secretKey = await algorithm.newSecretKey();
  final nonce = algorithm.newNonce();

  // Encrypt
  final secretBox = await algorithm.encrypt(
    message,
    secretKey: secretKey,
    nonce: nonce,
  );
  print('Nonce: ${secretBox.nonce}');
  print('Ciphertext: ${secretBox.cipherText}');
  print('MAC: ${secretBox.mac.bytes}');

  // Decrypt
  final clearText = await algorithm.decrypt(
    secretBox,
    secretKey: secretKey,
  );
  print('Cleartext: ${utf8.decode(clearText)}');
}
