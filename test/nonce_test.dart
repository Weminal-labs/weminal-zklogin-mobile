import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sui/cryptography/ed25519_keypair.dart';
import 'package:sui/sui_client.dart';
import 'package:zklogin/constants.dart';
import 'package:zklogin/weminal_utils.dart';
import 'package:zklogin/wenimal_nonce.dart';
import 'package:zklogin/wenimal_poseidon.dart';

void main() {
  test('generate nonce test', () async {
    SuiClient client = SuiClient(Constants.baseNet);

    // get ephemeralKeyPair
    var ephemeralkey = Ed25519Keypair();
    print('privite key: ${ephemeralkey.getSecretKey()}');
    print('public key: ${ephemeralkey.getPublicKey()}');
    //
    var publicKey = ephemeralkey.getPublicKey();
    var publicKeyBytes = toBigIntBE(publicKey.toSuiBytes());
    final eph_public_key_0 = publicKeyBytes ~/ BigInt.from(2).pow(128);
    final eph_public_key_1 = publicKeyBytes % BigInt.from(2).pow(128);
    //
    BigInt randomness = createRandomness();
    print('randomness: $randomness');
    var getEpoch = await client.getLatestSuiSystemState();
    //
    var epoch = getEpoch.epoch;
    var maxEpoch = double.parse(epoch) + 10;
    print('maxEpoch: $maxEpoch');
    //
    var bigNum = poseidonHash([
      eph_public_key_0,
      eph_public_key_1,
      BigInt.from(maxEpoch),
      randomness
    ]);

    var Z = toBigEndianBytes(bigNum, 20);
    var nonce = base64Url.encode(Z);
    nonce = nonce.replaceAll('=', '');

    var extendedEphemeralPublicKey =
        toBigIntBE(ephemeralkey.getPublicKey().toSuiBytes()).toString();

    if (nonce.length != NONCE_LENGTH) {
      throw Exception(
          'Length of nonce $nonce (${nonce.length}) is not equal to $NONCE_LENGTH');
    }
    print('nonce: $nonce');
  });
}
