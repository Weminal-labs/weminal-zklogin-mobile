import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:jwt_decoder/jwt_decoder.dart';
import 'package:sui/sui.dart';
import 'package:http/http.dart' as http;
import 'package:zklogin/zk_login_store.dart';
import 'package:zklogin/wenimal_proof.dart';

import '../zk_sign_builder.dart';
import '../model/request_proof_model.dart';
import '../weminal_utils.dart';
import '../wenimal_address.dart';

class LoginProvider extends ChangeNotifier {
  String zkSignature = '';
  String userAddress = '';

  void loadAddressAndSignature(
      String userJwt, Map<String, dynamic> resProofRequestInfo) async {
    Map<String, String> addressAndSignature =
        await _handleLogin(userJwt, resProofRequestInfo);
    userAddress = addressAndSignature['userAddress']!;
    notifyListeners();
  }

  Future<Map<String, String>> _handleLogin(String userJwt, dynamic res) async {
    RequestProofModel requestProofModel = res['requestProofModel'];
    requestProofModel.jwt = userJwt;

    var proof = await getProof(RequestProofModel(
        jwt: requestProofModel.jwt,
        extendedEphemeralPublicKey:
            requestProofModel.extendedEphemeralPublicKey,
        maxEpoch: requestProofModel.maxEpoch,
        jwtRandomness: requestProofModel.jwtRandomness,
        salt: requestProofModel.salt,
        keyClaimName: requestProofModel.keyClaimName));
    var userAddress = jwtToAddress(
        requestProofModel.jwt!, BigInt.parse(requestProofModel.salt));
    print('userAddress: $userAddress');
    final decodedJWT = JwtDecoder.decode(requestProofModel.jwt!);
    var addressSeed = genAddressSeed(BigInt.parse(requestProofModel.salt),
        'sub', decodedJWT['sub'], decodedJWT['aud']);
    ProofPoints proofPoints = ProofPoints.fromJson(proof['proofPoints']);
    ZkLoginSignatureInputs zkLoginSignatureInputs = ZkLoginSignatureInputs(
      proofPoints: proofPoints,
      issBase64Details: Claim.fromJson(proof['issBase64Details']),
      addressSeed: addressSeed.toString(),
      headerBase64: proof['headerBase64'],
    );
    print('myProof: $proof');
    print('ephemeralKeyPair: ${ZkLoginStore.ephemeralKey}');
    ZkSignBuilder.setInfo(
        inputZkLoginSignatureInputs: zkLoginSignatureInputs,
        inputMaxEpoch: ZkLoginStore.maxEpoch);
    return {
      'userAddress': userAddress,
    };
  }
}
