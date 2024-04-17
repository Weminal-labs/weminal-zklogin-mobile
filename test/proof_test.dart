import 'package:flutter_test/flutter_test.dart';
import 'package:zklogin/model/request_proof_model.dart';
import 'package:zklogin/provider/login_provider.dart';
import 'package:zklogin/wenimal_nonce.dart';
import 'package:zklogin/wenimal_proof.dart';

void main() {
  test('test get proof input', () async {
    // generate nonce, randomness, maxEpoch
    await generateNonce();
    //
    RequestProofModel proofRequestInfo = await getRequestProofInput();
    print('proofRequestInfo: $proofRequestInfo');
  });

  test('test get proof', () async {
    // generate nonce, randomness, maxEpoch
    await generateNonce();
    //
    RequestProofModel proofRequestInfo = await getRequestProofInput();
    String id_token =
        'eyJhbGciOiJSUzI1NiIsImtpZCI6IjZjZTExYWVjZjllYjE0MDI0YTQ0YmJmZDFiY2Y4YjMyYTEyMjg3ZmEiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI1NzMxMjAwNzA4NzEtMGs3Z2E2bnM3OWllMGpwZzFlaTZpcDV2amUyb3N0dDYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI1NzMxMjAwNzA4NzEtMGs3Z2E2bnM3OWllMGpwZzFlaTZpcDV2amUyb3N0dDYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTAzMDYwNDcxNzExMjA1NDc4NjYiLCJub25jZSI6IjZGZ05GSkViR3ZEZWctaUtQZXJvZ0NmcTdIWSIsIm5iZiI6MTcxMzMzNTM3MywiaWF0IjoxNzEzMzM1NjczLCJleHAiOjE3MTMzMzkyNzMsImp0aSI6ImVjMGU5MjFlYTcxOTg4NGMwZTRkNDk0MWFlMGRiZGU3OTc2NWIyNGEifQ.ISIsN3scBi_BkGrjwy1oQdu2sUNQSbEdkV7zPjRUIpaUCyrrq4N5nO0OzbvzsLsIoLCYZICnl-h-ggfB11PC2W3rupBuswtePxxkL5PBVzEeXUQuQRVMzrhJyMAsGENfviFudY7Hpq-vZUcrJ05A6c7FaukhnhLnj_5lGOND1nrRxnaaruGvg8YwezPmCfvl8_S4spNiTKLSzNGNXLE-36aPcSGhxmM3k5hUuTKn0LM2o--HhXYc8arghwMr80j6ddv_iTc6FPfw3Am2_KFiD-_aNFOiLYqEVMOP5_wPPZl9DeyI7jlZQcwo2GgALn5UED1Ski1vujXPlM0BdTkcTg';
    proofRequestInfo.jwt = id_token;
    var proof = await LoginProvider().getProof(proofRequestInfo);
    print(proof);
  });
  test('test old get proof', () async {
    var res = await getInfoRequestProof();
    RequestProofModel requestProofModel = RequestProofModel(
      extendedEphemeralPublicKey: res['extendedEphemeralPublicKey']!,
      maxEpoch: res['maxEpoch']!.toString().replaceAll('.0', ''),
      jwtRandomness: res['jwtRandomness']!,
      salt: res['salt']!,
    );
    String id_token =
        'eyJhbGciOiJSUzI1NiIsImtpZCI6IjZjZTExYWVjZjllYjE0MDI0YTQ0YmJmZDFiY2Y4YjMyYTEyMjg3ZmEiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI1NzMxMjAwNzA4NzEtMGs3Z2E2bnM3OWllMGpwZzFlaTZpcDV2amUyb3N0dDYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI1NzMxMjAwNzA4NzEtMGs3Z2E2bnM3OWllMGpwZzFlaTZpcDV2amUyb3N0dDYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTAzMDYwNDcxNzExMjA1NDc4NjYiLCJub25jZSI6IjZGZ05GSkViR3ZEZWctaUtQZXJvZ0NmcTdIWSIsIm5iZiI6MTcxMzMzNTM3MywiaWF0IjoxNzEzMzM1NjczLCJleHAiOjE3MTMzMzkyNzMsImp0aSI6ImVjMGU5MjFlYTcxOTg4NGMwZTRkNDk0MWFlMGRiZGU3OTc2NWIyNGEifQ.ISIsN3scBi_BkGrjwy1oQdu2sUNQSbEdkV7zPjRUIpaUCyrrq4N5nO0OzbvzsLsIoLCYZICnl-h-ggfB11PC2W3rupBuswtePxxkL5PBVzEeXUQuQRVMzrhJyMAsGENfviFudY7Hpq-vZUcrJ05A6c7FaukhnhLnj_5lGOND1nrRxnaaruGvg8YwezPmCfvl8_S4spNiTKLSzNGNXLE-36aPcSGhxmM3k5hUuTKn0LM2o--HhXYc8arghwMr80j6ddv_iTc6FPfw3Am2_KFiD-_aNFOiLYqEVMOP5_wPPZl9DeyI7jlZQcwo2GgALn5UED1Ski1vujXPlM0BdTkcTg';

    requestProofModel.jwt = id_token;

    var proof = await LoginProvider().getProof(RequestProofModel(
        jwt: requestProofModel.jwt,
        extendedEphemeralPublicKey:
            requestProofModel.extendedEphemeralPublicKey,
        maxEpoch: requestProofModel.maxEpoch,
        jwtRandomness: requestProofModel.jwtRandomness,
        salt: requestProofModel.salt,
        keyClaimName: requestProofModel.keyClaimName));
    print(proof);
  });
}
