﻿using Google.Protobuf;
using Okapi.Examples.V1;
using Okapi.Keys.V1;
using Okapi.Transport;
using Okapi.Transport.V1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace Okapi.Tests;

public class DIDComTests
{
    [Fact]
    public void TestPack()
    {
        BasicMessage message = new BasicMessage { Text = "Hello world" };

        var encryptedMessage = DIDComm.Pack(new PackRequest { Plaintext = message.ToByteString(), SenderKey = Alice.SecretKey, ReceiverKey = Bob.PublicKey });

        Assert.NotNull(encryptedMessage);
    }
}

// From Greeter example
public static class Alice
{
    const string KeyId = "did:key:z6LSskw3r3441B8YnhcB1LKxmRqpEiyZH3Prpb6No1fHTze6#z6LSskw3r3441B8YnhcB1LKxmRqpEiyZH3Prpb6No1fHTze6";
    public static JsonWebKey SecretKey = new JsonWebKey
    {
        Kid = KeyId,
        Kty = "OKP",
        Crv = "X25519",
        D = "oLio1cRmNIgQePHHJFeCdw0-j4ZtJBH0HVQU8fXahVs"
    };
    public static JsonWebKey PublicKey = new JsonWebKey
    {
        Kid = KeyId,
        Kty = "OKP",
        Crv = "X25519",
        X = "7vLvUiaXEUgajINpIomBTwQtQCnf-r7cptpKTEWHzjs"
    };
}

public static class Bob
{
    const string KeyId = "did:key:z6LSgKhoYDRJJaJ84wHjnW67r8RTaLExHhzrFZgd3Hh1md7j#z6LSgKhoYDRJJaJ84wHjnW67r8RTaLExHhzrFZgd3Hh1md7j";

    public static JsonWebKey SecretKey = new JsonWebKey
    {
        Kid = KeyId,
        Kty = "OKP",
        Crv = "X25519",
        D = "cLH0xA7mdSp5zcxSOVepnMuFtJSWZtRI0PoR2cET420"
    };
    public static JsonWebKey PublicKey = new JsonWebKey
    {
        Kid = KeyId,
        Kty = "OKP",
        Crv = "X25519",
        X = "RQvhX5wPpmHdd97FxvC_xK3GB0VpyLhN5xQN45EwjXY"
    };
}
