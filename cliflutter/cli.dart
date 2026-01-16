import 'dart:typed_data';
import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:hex/hex.dart';
import 'package:web3dart/web3dart.dart';
import 'package:web3dart/crypto.dart'; // Contains keccak256

class SethClient {
  final String baseUrl;

  SethClient(String host, int port)
      : baseUrl = 'http://$host:$port/transaction';

  /// Convert int to 8-byte Little Endian
  /// Corresponds to C++: std::string((char*)&val, sizeof(uint64))
  Uint8List _uint64ToBytesLE(int value) {
    var bdata = ByteData(8);
    bdata.setUint64(0, value, Endian.little);
    return bdata.buffer.asUint8List();
  }

  /// Compute Hash (Strictly replicates C++ GetTxMessageHash)
  Uint8List computeHash({
    required int nonce,
    required String pubKeyHex,
    required String toHex,
    required int amount,
    required int gasLimit,
    required int gasPrice,
    required int step,
    String? contractCode,
    String? inputHex,
    int prepayment = 0,
    String? key,
    String? val,
  }) {
    // Use BytesBuilder to concatenate byte streams
    final builder = BytesBuilder();

    // 1. nonce (uint64 LE)
    builder.add(_uint64ToBytesLE(nonce));

    // 2. pubkey (raw bytes) - C++ receives HexDecoded data
    builder.add(HEX.decode(pubKeyHex));

    // 3. to (raw bytes)
    builder.add(HEX.decode(toHex));

    // 4. amount (uint64 LE)
    builder.add(_uint64ToBytesLE(amount));

    // 5. gas_limit (uint64 LE)
    builder.add(_uint64ToBytesLE(gasLimit));

    // 6. gas_price (uint64 LE)
    builder.add(_uint64ToBytesLE(gasPrice));

    // 7. step (uint64 LE)
    // Key Point: C++ server casts uint32 step to uint64 before serialization
    builder.add(_uint64ToBytesLE(step));

    // 8. contract_code (raw bytes)
    if (contractCode != null && contractCode.isNotEmpty) {
      builder.add(HEX.decode(contractCode));
    }

    // 9. input (raw bytes)
    if (inputHex != null && inputHex.isNotEmpty) {
      builder.add(HEX.decode(inputHex));
    }

    // 10. prepayment (uint64 LE)
    if (prepayment > 0) {
      builder.add(_uint64ToBytesLE(prepayment));
    }

    // 11. key & val (UTF-8 bytes)
    // C++ appends string directly, corresponds to UTF-8
    if (key != null && key.isNotEmpty) {
      builder.add(utf8.encode(key));
      if (val != null && val.isNotEmpty) {
        builder.add(utf8.encode(val));
      }
    }

    // Compute Keccak256 Hash
    return keccak256(builder.toBytes());
  }

  Future<void> sendTransaction({
    required String privateKeyHex,
    required String toHex,
    int amount = 0,
    int nonce = 1,
    int gasLimit = 50000,
    int gasPrice = 1,
    int step = 0,
    int shardId = 0,
    String? contractCode,
    String? inputHex,
    int prepayment = 0,
    String? key,
    String? val,
  }) async {
    try {
      // 1. Handle Private Key
      EthPrivateKey credentials = EthPrivateKey.fromHex(privateKeyHex);

      // 2. Derive Public Key (Uncompressed format: 04 + X + Y)
      // web3dart handles this well, but check for '04' prefix
      // encodedPublicKey returns Uint8List, usually includes prefix
      Uint8List pubKeyBytes = credentials.encodedPublicKey;
      String pubKeyHex = HEX.encode(pubKeyBytes);

      // If the server expects 64 bytes (removing '04'), uncomment below:
      // if (pubKeyHex.startsWith('04')) {
      //   pubKeyHex = pubKeyHex.substring(2);
      // }

      // 3. Compute Hash
      // Note: Pass the HEX encoded pubKey string here, no '0x' needed
      Uint8List txHash = computeHash(
        nonce: nonce,
        pubKeyHex: pubKeyHex,
        toHex: toHex,
        amount: amount,
        gasLimit: gasLimit,
        gasPrice: gasPrice,
        step: step,
        contractCode: contractCode,
        inputHex: inputHex,
        prepayment: prepayment,
        key: key,
        val: val,
      );

      print("Computed Hash: ${HEX.encode(txHash)}");

      // 4. Sign
      // Using `signToSignature` hashes the payload first.
      // Since we already did Keccak256 in `computeHash`, we need to sign the hash directly.
      // If we use `credentials.signToSignature(txHash)`, it will do Hash(Hash(msg)), causing an error.
      
      // Solution: Use the low-level `sign` method from `web3dart/crypto.dart`
      // which accepts a pre-calculated digest.
      MsgSignature signature = sign(txHash, credentials.privateKeyInt);

      // 5. Handle V Value
      // Ethereum V = 27 or 28.
      // C++ native libsecp256k1 V = 0 or 1.
      int v = signature.v - 27;

      // 6. Construct HTTP Parameters
      var requestParams = {
        'nonce': nonce.toString(),
        'pubkey': pubKeyHex,
        'to': toHex,
        'amount': amount.toString(),
        'gas_limit': gasLimit.toString(),
        'gas_price': gasPrice.toString(),
        'shard_id': shardId.toString(),
        'type': step.toString(), // Parameter name is 'type'
        'sign_r': HEX.encode(intToBytes(signature.r)),
        'sign_s': HEX.encode(intToBytes(signature.s)),
        'sign_v': v.toString(),
      };

      if (contractCode != null) requestParams['bytes_code'] = contractCode;
      if (inputHex != null) requestParams['input'] = inputHex;
      if (prepayment > 0) requestParams['pepay'] = prepayment.toString();
      if (key != null) requestParams['key'] = key;
      if (val != null) requestParams['val'] = val;

      print("Sending Request: $requestParams");

      var response = await http.post(
        Uri.parse(baseUrl),
        body: requestParams, // http package automatically handles x-www-form-urlencoded
      );

      print("Response Status: ${response.statusCode}");
      print("Response Body: ${response.body}");

    } catch (e) {
      print("Error: $e");
    }
  }
}

// Helper: BigInt to 32-byte Uint8List
Uint8List intToBytes(BigInt number) {
  var hex = number.toRadixString(16);
  if (hex.length % 2 != 0) hex = '0$hex';
  var bytes = HEX.decode(hex);
  if (bytes.length < 32) {
    var list =  Uint8List(32)..setAll(32 - bytes.length, bytes);
    return list;
  }
  return Uint8List.fromList(bytes);
}

// ==========================================
// Usage Example (main function)
// ==========================================
void main() async {
  // Config
  String host = "127.0.0.1";
  int port = 8888;
  
  // Test Account
  String privateKey = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  String toAddr = "1234567890abcdef1234567890abcdef12345678"; // 40 chars hex

  var client = SethClient(host, port);

  await client.sendTransaction(
    privateKeyHex: privateKey,
    toHex: toAddr,
    amount: 1000,
    nonce: 1,
    gasLimit: 50000,
    gasPrice: 1,
    inputHex: "aabbcc", // Optional
  );
}