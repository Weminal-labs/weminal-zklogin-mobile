// To parse this JSON data, do
//
//     final requestProofModel = requestProofModelFromJson(jsonString);

import 'dart:convert';

RequestProofModel requestProofModelFromJson(String str) =>
    RequestProofModel.fromJson(json.decode(str));

String requestProofModelToJson(RequestProofModel data) =>
    json.encode(data.toJson());

class RequestProofModel {
  String? jwt;
  String extendedEphemeralPublicKey;
  String maxEpoch;
  String jwtRandomness;
  String salt;
  String keyClaimName;

  RequestProofModel({
    this.jwt,
    required this.extendedEphemeralPublicKey,
    required this.maxEpoch,
    required this.jwtRandomness,
    required this.salt,
    this.keyClaimName = 'sub',
  });

  RequestProofModel copyWith({
    String? jwt,
    String? extendedEphemeralPublicKey,
    String? maxEpoch,
    String? jwtRandomness,
    String? salt,
    String? keyClaimName,
  }) =>
      RequestProofModel(
        jwt: jwt ?? this.jwt,
        extendedEphemeralPublicKey:
            extendedEphemeralPublicKey ?? this.extendedEphemeralPublicKey,
        maxEpoch: maxEpoch ?? this.maxEpoch,
        jwtRandomness: jwtRandomness ?? this.jwtRandomness,
        salt: salt ?? this.salt,
        keyClaimName: keyClaimName ?? this.keyClaimName,
      );

  factory RequestProofModel.fromJson(Map<String, dynamic> json) =>
      RequestProofModel(
        jwt: json["jwt"],
        extendedEphemeralPublicKey: json["extendedEphemeralPublicKey"],
        maxEpoch: json["maxEpoch"],
        jwtRandomness: json["jwtRandomness"],
        salt: json["salt"],
        keyClaimName: json["keyClaimName"],
      );

  Map<String, dynamic> toJson() => {
        "jwt": jwt,
        "extendedEphemeralPublicKey": extendedEphemeralPublicKey,
        "maxEpoch": maxEpoch,
        "jwtRandomness": jwtRandomness,
        "salt": salt,
        "keyClaimName": keyClaimName,
      };
}
