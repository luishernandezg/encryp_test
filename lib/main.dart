import 'package:flutter/material.dart';
import 'package:jose/jose.dart';

Future<void> main() async {
  /*----------------------Create a JWE----------------------------*/
  // create a builder
  var builder = JsonWebEncryptionBuilder();

  // set the content
  builder.stringContent = "Hello world!";
  builder.protectedHeader;

  // set some protected header
  // builder.setProtectedHeader("createdAt", DateTime.now().toIso8601String());

  print(' HEADER ${builder.protectedHeader}');

  // add a key to encrypt the Content Encryption Key
  var jwkTest = JsonWebKey.generate('A256GCM');

  var jwk = JsonWebKey.fromJson(
    {
      "kty": "oct",
      "k": "12345678912345678912345678912345",
      "alg": "A256GCM",
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
  builder.encryptionAlgorithm = "A256GCM";

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
}
