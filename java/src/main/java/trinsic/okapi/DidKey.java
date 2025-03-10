package trinsic.okapi;

import com.google.protobuf.InvalidProtocolBufferException;
import trinsic.okapi.keys.v1.Keys;

public class DidKey extends OkapiNative {
    public static Keys.GenerateKeyResponse generate(Keys.GenerateKeyRequest request) throws DidException, InvalidProtocolBufferException {
        OkapiByteBuffer.ByValue requestBuffer = messageToBuffer(request);
        OkapiByteBuffer responseBuffer = new OkapiByteBuffer();
        ExternError errBuffer = new ExternError();
        var result = getNativeLibrary().didkey_generate(requestBuffer, responseBuffer, errBuffer);
        errBuffer.raiseError(result);
        return Keys.GenerateKeyResponse.parseFrom(bufferToByteArray(responseBuffer));
    }

    public static Keys.ResolveResponse resolve(Keys.ResolveRequest request) throws DidException, InvalidProtocolBufferException {
        OkapiByteBuffer.ByValue requestBuffer = messageToBuffer(request);
        OkapiByteBuffer responseBuffer = new OkapiByteBuffer();
        ExternError errBuffer = new ExternError();
        var result = getNativeLibrary().didkey_resolve(requestBuffer, responseBuffer, errBuffer);
        errBuffer.raiseError(result);
        return Keys.ResolveResponse.parseFrom(bufferToByteArray(responseBuffer));
    }
}

