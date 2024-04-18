import 'package:flutter_test/flutter_test.dart';
import 'package:zklogin/wenimal_nonce.dart';
import 'package:zklogin/wenimal_proof.dart';

void main() {
  test('test get proof input', () async {
    // generate nonce, randomness, maxEpoch
    await generateNonce();
    //
    var proofRequestInfo = await getRequestProofInput();
    print('proofRequestInfo: $proofRequestInfo');
  });

  test('test get proof', () async {
    // generate nonce, randomness, maxEpoch
    await generateNonce();
    //
    var res = await getRequestProofInput();
    String id_token =
        ''; // you need a jwt token which have nonce field match with your generateNonce
    // you can try it in demo;
    var proofRequestInfo = res['requestProofModel'];

    proofRequestInfo.jwt = id_token;
    var proof = await getProof(proofRequestInfo);
    print(proof);
  });
}
