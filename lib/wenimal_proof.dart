import 'dart:typed_data';
import 'package:sui/sui.dart';
import 'package:zklogin/ZkLoginStore.dart';
import 'package:zklogin/model/request_proof_model.dart';
import 'package:zklogin/wenimal_nonce.dart';

import 'constants.dart';

const int NONCE_LENGTH = 27; //27

Future<RequestProofModel> getRequestProofInput() async {
  var extendedEphemeralPublicKey =
      toBigIntBE(ZkLoginStore.ephemeralKey.getPublicKey().toSuiBytes())
          .toString();

  RequestProofModel requestProofModel = RequestProofModel(
      extendedEphemeralPublicKey: extendedEphemeralPublicKey,
      maxEpoch: ZkLoginStore.maxEpoch.toString(),
      jwtRandomness: ZkLoginStore.randomness.toString(),
      salt: '255873485666802367946136116146407409355',
      keyClaimName: 'sub');
  return requestProofModel;
}
