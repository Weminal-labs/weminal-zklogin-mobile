import 'dart:convert';

import 'package:zklogin/zk_login_store.dart';
import 'package:zklogin/model/request_proof_model.dart';
import 'package:zklogin/wenimal_nonce.dart';
import 'package:http/http.dart' as http;

Map<String, String> headers = {
  "Content-Type": "application/json",
  "Accept": "application/json",
};

// final String urlGetProof =
//     'http://192.168.1.15:3000/api/v1/contract/getZkProof';
const String urlGetProof = 'https://prover-dev.mystenlabs.com/v1';

const int NONCE_LENGTH = 27; //27

Future<Map<String, dynamic>> getRequestProofInput() async {
  var nonce = await generateNonce();
  var extendedEphemeralPublicKey =
      toBigIntBE(ZkLoginStore.ephemeralKey.getPublicKey().toSuiBytes())
          .toString();

  RequestProofModel requestProofModel = RequestProofModel(
      extendedEphemeralPublicKey: extendedEphemeralPublicKey,
      maxEpoch: ZkLoginStore.maxEpoch.toString(),
      jwtRandomness: ZkLoginStore.randomness.toString(),
      salt: '255873485666802367946136116146407409355',
      keyClaimName: 'sub');
  return {'requestProofModel': requestProofModel, 'nonce': nonce};
}

Future<Map<String, dynamic>> getProof(
    RequestProofModel requestProofModel) async {
  var res = await http.post(Uri.parse(urlGetProof),
      headers: headers, body: jsonEncode(requestProofModel.toJson()));
  if (res.statusCode == 200) {
    Map<String, dynamic> response = jsonDecode(res.body);
    return response;
  } else {
    throw Exception("Load page fail ${res.statusCode}, ${res.body}");
  }
}
