import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import trinsic.okapi.DidException;
import trinsic.okapi.hashing.v1.Hashing;

public class HashingTest {
    private static final byte[] data = {0, 1, 2};
    private static final String key = "whats the Elvish word for friend";
    private static final String context = "BLAKE3 2019-12-27 16:29:52 test vectors context";
    private static final String hash = "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f5b49b82f805a538c68915c1ae8035c900fd1d4b13902920fd05e1450822f36de9454b7e9996de4900c8e723512883f93f4345f8a58bfe64ee38d3ad71ab027765d25cdd0e448328a8e7a683b9a6af8b0af94fa09010d9186890b096a08471e4230a134";
    private static final String keyedHash = "39e67b76b5a007d4921969779fe666da67b5213b096084ab674742f0d5ec62b9b9142d0fab08e1b161efdbb28d18afc64d8f72160c958e53a950cdecf91c1a1bbab1a9c0f01def762a77e2e8545d4dec241e98a89b6db2e9a5b070fc110caae2622690bd7b76c02ab60750a3ea75426a6bb8803c370ffe465f07fb57def95df772c39f";
    private static final String deriveKey = "440aba35cb006b61fc17c0529255de438efc06a8c9ebf3f2ddac3b5a86705797f27e2e914574f4d87ec04c379e12789eccbfbc15892626042707802dbe4e97c3ff59dca80c1e54246b6d055154f7348a39b7d098b2b4824ebe90e104e763b2a447512132cede16243484a55a4e40a85790038bb0dcf762e8c053cabae41bbe22a5bff7";

    @Test
    void testBlake3Hash() throws DidException, InvalidProtocolBufferException {
        var request = Hashing.Blake3HashRequest.newBuilder().setData(ByteString.copyFrom(data)).build();
        var response = trinsic.okapi.Hashing.blake3_hash(request);
        Assertions.assertTrue(hash.startsWith(Hex.bytesToHex(response.getDigest().toByteArray())));
    }

    @Test
    void testBlake3KeyedHash() throws DidException, InvalidProtocolBufferException {
        var request = Hashing.Blake3KeyedHashRequest.newBuilder().setData(ByteString.copyFrom(data)).setKey(ByteString.copyFromUtf8(key)).build();
        var response = trinsic.okapi.Hashing.blake3_keyed_hash(request);
        Assertions.assertTrue(keyedHash.startsWith(Hex.bytesToHex(response.getDigest().toByteArray())));
    }

    @Test
    void testBlake3DeriveKey() throws DidException, InvalidProtocolBufferException {
        var request = Hashing.Blake3DeriveKeyRequest.newBuilder().setKeyMaterial(ByteString.copyFrom(data)).setContext(ByteString.copyFromUtf8(context)).build();
        var response = trinsic.okapi.Hashing.blake3_derive_key(request);
        Assertions.assertTrue(deriveKey.startsWith(Hex.bytesToHex(response.getDigest().toByteArray())));
    }

    @Test
    void testSHA256() throws DidException, InvalidProtocolBufferException {
        var request = Hashing.SHA256HashRequest.newBuilder().setData(ByteString.copyFromUtf8("4113")).build();
        var response = trinsic.okapi.Hashing.sha256_hash(request);
        Assertions.assertEquals("71b3af35d9d53d24e7462177da41b8acd5e2ef4afc333dd9272cb2ab8743b3db", Hex.bytesToHex(response.getDigest().toByteArray()));
    }
}
