import 'package:sui/cryptography/ed25519_keypair.dart';

class ZkLoginStore {
  static late Ed25519Keypair ephemeralKey;
  static late int maxEpoch;
  static late BigInt randomness;
}
