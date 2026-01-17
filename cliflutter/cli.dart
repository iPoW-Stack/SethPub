import 'dart:convert';
import 'dart:typed_data';
import 'package:http/http.dart' as http;
import 'package:hex/hex.dart';
import 'package:web3dart/web3dart.dart';
import 'package:web3dart/crypto.dart'; // Contains keccak256 and sign

class SethClient {
  final String baseUrl;

  SethClient(String host, int port) : baseUrl = 'http://$host:$port';

  /// Helper: Convert int to 8-byte Little Endian Uint8List
  /// Corresponds to C++: std::string((char*)&val, sizeof(uint64))
  Uint8List _uint64ToBytesLE(int value) {
    var bdata = ByteData(8);
    bdata.setUint64(0, value, Endian.little);
    return bdata.buffer.asUint8List();
  }

  /// Query account info and get the latest Nonce
  Future<int> getLatestNonce(String addressHex) async {
    print("[Client] Querying nonce for address: $addressHex");
    try {
      var response = await http.post(
        Uri.parse('$baseUrl/query_account'),
        body: {'address': addressHex},
      );

      if (response.statusCode == 200) {
        // Parse JSON
        // Example: {"nonce": 5, "balance": ...}
        var json = jsonDecode(response.body);
        if (json is Map && json.containsKey('nonce')) {
          var nonce = json['nonce'];
          if (nonce is int) return nonce;
          if (nonce is String) return int.tryParse(nonce) ?? 0;
        }
      }
    } catch (e) {
      print("[Warning] Failed to query nonce: $e");
    }
    return 0; // Default to 0
  }

  /// Strictly replicates the serialization logic of C++ GetTxMessageHash
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
    final builder = BytesBuilder();

    // 1. nonce (uint64 LE)
    builder.add(_uint64ToBytesLE(nonce));

    // 2. pubkey (raw bytes)
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
    // Important: Cast uint32 to uint64 for serialization
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
    if (key != null && key.isNotEmpty) {
      builder.add(utf8.encode(key));
      if (val != null && val.isNotEmpty) {
        builder.add(utf8.encode(val));
      }
    }

    // Compute Keccak256
    return keccak256(builder.toBytes());
  }

  /// Internal method to sign and send
  Future<bool> _signAndSend(
    Uint8List txHash,
    BigInt privateKeyInt,
    Map<String, String> params,
    int vOverride,
  ) async {
    // Sign (ECDSA)
    // Use low-level `sign` to sign the digest directly (no extra hashing)
    MsgSignature signature = sign(txHash, privateKeyInt);

    // Native V (0/1) calculation
    // Web3dart returns Ethereum V (27 or 28), subtract 27
    int v = signature.v - 27;

    // Apply Override
    if (vOverride != -1) {
      v = vOverride;
    }

    // Add signature to params
    var finalParams = Map<String, String>.from(params);
    finalParams['sign_r'] = HEX.encode(_intToBytes(signature.r));
    finalParams['sign_s'] = HEX.encode(_intToBytes(signature.s));
    finalParams['sign_v'] = v.toString();

    print("[Client] Sending Transaction with V=$v...");

    try {
      var response = await http.post(
        Uri.parse('$baseUrl/transaction'),
        body: finalParams,
      );

      print("[Server Response] ${response.statusCode}: ${response.body}");
      return response.statusCode == 200 && response.body.contains("ok");
    } catch (e) {
      print("[Error] Network error: $e");
      return false;
    }
  }

  /// Automatic Workflow
  Future<void> sendTransactionAuto({
    required String privateKeyHex,
    required String toHex,
    int amount = 0,
    String? inputHex,
  }) async {
    // 1. Prepare Keys
    EthPrivateKey credentials = EthPrivateKey.fromHex(privateKeyHex);

    // Get Full Public Key (65 bytes: 04 + X + Y)
    Uint8List pubKeyBytes = credentials.encodedPublicKey;
    String pubKeyHex = HEX.encode(pubKeyBytes);

    // Derive Address (Standard Ethereum Logic)
    // web3dart provides extraction from credentials
    EthereumAddress myAddress = await credentials.extractAddress();
    // remove '0x' prefix
    String myAddressHex = myAddress.hex.substring(2);

    // 2. Get and Increment Nonce
    int currentNonce = await getLatestNonce(myAddressHex);
    int nextNonce = currentNonce + 1;
    print("[Client] Using Next Nonce: $nextNonce");

    // Base Params
    int gasLimit = 50000;
    int gasPrice = 1;
    int step = 0;
    int shardId = 0;
    String contractCode = "";
    int prepayment = 0;
    String key = "";
    String val = "";

    // 3. Compute Hash
    Uint8List txHash = computeHash(
      nonce: nextNonce,
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

    print("[Client] Computed Hash: ${HEX.encode(txHash)}");

    // Prepare Params Map
    var params = {
      'nonce': nextNonce.toString(),
      'pubkey': pubKeyHex,
      'to': toHex,
      'amount': amount.toString(),
      'gas_limit': gasLimit.toString(),
      'gas_price': gasPrice.toString(),
      'shard_id': shardId.toString(),
      'type': step.toString(),
    };
    if (inputHex != null) params['input'] = inputHex;

    // 4. Sign and Send (First attempt)
    bool success = await _signAndSend(txHash, credentials.privateKeyInt, params, -1);

    // 5. Auto Retry Logic
    if (!success) {
      print("[Client] Transaction failed (likely V mismatch). Retrying with forced V=1...");
      await _signAndSend(txHash, credentials.privateKeyInt, params, 1);
    }
  }

  // Helper: BigInt to 32-byte Uint8List
  Uint8List _intToBytes(BigInt number) {
    var hex = number.toRadixString(16);
    if (hex.length % 2 != 0) hex = '0$hex';
    var bytes = HEX.decode(hex);
    if (bytes.length < 32) {
      var list = Uint8List(32)..setAll(32 - bytes.length, bytes);
      return list;
    }
    return Uint8List.fromList(bytes);
  }
}

// ==========================================
// Main Entry Point
// ==========================================
void main() async {
  String host = "35.184.150.163";
  int port = 23001;

  String privateKey =
      "cefc2c33064ea7691aee3e5e4f7842935d26f3ad790d81cf015e79b78958e848";
  String toAddr = "1234567890abcdef1234567890abcdef12345678"; // 40 chars hex

  var client = SethClient(host, port);

  // Execute Auto Flow
  await client.sendTransactionAuto(
    privateKeyHex: privateKey,
    toHex: toAddr,
    amount: 5000,
    inputHex: "112233",
  );
}