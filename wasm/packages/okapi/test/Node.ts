import test from "ava";
import {
    DIDKey,
    GenerateKeyRequest,
    CreateOberonKeyRequest,
    CreateOberonTokenRequest,
    CreateOberonProofRequest,
    VerifyOberonProofRequest,
    KeyType,
    Oberon,
} from "../src"

test("generate bls key", async (t) => {
    const response = await DIDKey.generate(new GenerateKeyRequest().setKeyType(KeyType.KEY_TYPE_BLS12381G1G2));

    t.not(null, response);
    t.not(undefined, response);
});

test("create and verify oberon token", async (t) => {
    const key = await Oberon.createKey(new CreateOberonKeyRequest());
    const id = Buffer.from("me@example.com");
    const nonce = Buffer.from("123");

    const token = await Oberon.createToken(new CreateOberonTokenRequest().setData(id).setSk(key.getSk()));
    t.not(null, token);

    const proof = await Oberon.createProof(
        new CreateOberonProofRequest().setToken(token.getToken()).setData(id).setNonce(nonce)
    );

    t.is(256, proof.getProof_asU8().length);

    const result = await Oberon.verifyProof(
        new VerifyOberonProofRequest().setData(id).setNonce(nonce).setProof(proof.getProof()).setPk(key.getPk())
    );

    t.true(result.getValid());
});
