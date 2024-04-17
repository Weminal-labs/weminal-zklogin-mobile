import 'dart:convert';
import 'dart:typed_data';

import 'package:bcs/hex.dart';
import 'package:jwt_decoder/jwt_decoder.dart';
import 'package:sui/cryptography/signature.dart';
import 'package:sui/types/common.dart';
import 'package:sui/utils/sha.dart';

import 'weminal_utils.dart';

const MAX_HEADER_LEN_B64 = 248;
const MAX_PADDED_UNSIGNED_JWT_LEN = 64 * 25;

String computeZkLoginAddressFromSeed(BigInt addressSeed, String iss) {
  final addressSeedBytesBigEndian = toBigEndianBytes(addressSeed, 32);
  if (iss == 'accounts.google.com') {
    iss = 'https://accounts.google.com';
  }
  final addressParamBytes = utf8.encode(iss);
  final tmp = Uint8List(
      2 + addressSeedBytesBigEndian.length + addressParamBytes.length);

  tmp.setAll(0, [SIGNATURE_SCHEME_TO_FLAG.ZkLogin]);
  tmp.setAll(1, [addressParamBytes.length]);
  tmp.setAll(2, addressParamBytes);
  tmp.setAll(2 + addressParamBytes.length, addressSeedBytesBigEndian);

  return normalizeSuiAddress(
    Hex.encode(blake2b(tmp)).substring(0, SUI_ADDRESS_LENGTH * 2),
  );
}

String jwtToAddress(String jwt, BigInt userSalt) {
  lengthChecks(jwt);

  final decodedJWT = JwtDecoder.decode(jwt);
  if (decodedJWT['sub'] == null ||
      decodedJWT['iss'] == null ||
      decodedJWT['aud'] == null) {
    throw Exception('Missing jwt data');
  }

  if (decodedJWT['aud'] is List) {
    throw Exception('Not supported aud. Aud is an array, string was expected.');
  }

  return computeZkLoginAddress(
    userSalt: userSalt,
    claimName: 'sub',
    claimValue: decodedJWT['sub'],
    aud: decodedJWT['aud'],
    iss: decodedJWT['iss'],
  );
}

String computeZkLoginAddress({
  required String claimName,
  required String claimValue,
  required BigInt userSalt,
  required String iss,
  required String aud,
}) {
  return computeZkLoginAddressFromSeed(
    genAddressSeed(userSalt, claimName, claimValue, aud),
    iss,
  );
}

void lengthChecks(String jwt) {
  List<String> parts = jwt.split('.');
  final header = parts[0];
  final payload = parts[1];
  // Is the header small enough
  if (header.length > MAX_HEADER_LEN_B64) {
    throw Exception('Header is too long');
  }

  // Is the combined length of (header, payload, SHA2 padding) small enough?
  // unsigned_jwt = header + '.' + payload;
  int L = (header.length + 1 + payload.length) * 8;
  int K = (512 + 448 - ((L % 512) + 1)) % 512;

  // The SHA2 padding is 1 followed by K zeros, followed by the length of the message
  int paddedUnsignedJwtLen = (L + 1 + K + 64) ~/ 8;

  // The padded unsigned JWT must be less than the max_padded_unsigned_jwt_len
  if (paddedUnsignedJwtLen > MAX_PADDED_UNSIGNED_JWT_LEN) {
    throw Exception('JWT is too long');
  }
}
