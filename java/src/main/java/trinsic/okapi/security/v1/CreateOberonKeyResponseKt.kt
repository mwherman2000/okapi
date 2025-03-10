//Generated by the protocol buffer compiler. DO NOT EDIT!
// source: okapi/security/v1/security.proto

package trinsic.okapi.security.v1;

@kotlin.jvm.JvmSynthetic
public inline fun createOberonKeyResponse(block: trinsic.okapi.security.v1.CreateOberonKeyResponseKt.Dsl.() -> kotlin.Unit): trinsic.okapi.security.v1.Security.CreateOberonKeyResponse =
  trinsic.okapi.security.v1.CreateOberonKeyResponseKt.Dsl._create(trinsic.okapi.security.v1.Security.CreateOberonKeyResponse.newBuilder()).apply { block() }._build()
public object CreateOberonKeyResponseKt {
  @kotlin.OptIn(com.google.protobuf.kotlin.OnlyForUseByGeneratedProtoCode::class)
  @com.google.protobuf.kotlin.ProtoDslMarker
  public class Dsl private constructor(
    private val _builder: trinsic.okapi.security.v1.Security.CreateOberonKeyResponse.Builder
  ) {
    public companion object {
      @kotlin.jvm.JvmSynthetic
      @kotlin.PublishedApi
      internal fun _create(builder: trinsic.okapi.security.v1.Security.CreateOberonKeyResponse.Builder): Dsl = Dsl(builder)
    }

    @kotlin.jvm.JvmSynthetic
    @kotlin.PublishedApi
    internal fun _build(): trinsic.okapi.security.v1.Security.CreateOberonKeyResponse = _builder.build()

    /**
     * <pre>
     * raw secret key bytes
     * </pre>
     *
     * <code>bytes sk = 2;</code>
     */
    public var sk: com.google.protobuf.ByteString
      @JvmName("getSk")
      get() = _builder.getSk()
      @JvmName("setSk")
      set(value) {
        _builder.setSk(value)
      }
    /**
     * <pre>
     * raw secret key bytes
     * </pre>
     *
     * <code>bytes sk = 2;</code>
     */
    public fun clearSk() {
      _builder.clearSk()
    }

    /**
     * <pre>
     * raw public key bytes
     * </pre>
     *
     * <code>bytes pk = 3;</code>
     */
    public var pk: com.google.protobuf.ByteString
      @JvmName("getPk")
      get() = _builder.getPk()
      @JvmName("setPk")
      set(value) {
        _builder.setPk(value)
      }
    /**
     * <pre>
     * raw public key bytes
     * </pre>
     *
     * <code>bytes pk = 3;</code>
     */
    public fun clearPk() {
      _builder.clearPk()
    }
  }
}
@kotlin.jvm.JvmSynthetic
public inline fun trinsic.okapi.security.v1.Security.CreateOberonKeyResponse.copy(block: trinsic.okapi.security.v1.CreateOberonKeyResponseKt.Dsl.() -> kotlin.Unit): trinsic.okapi.security.v1.Security.CreateOberonKeyResponse =
  trinsic.okapi.security.v1.CreateOberonKeyResponseKt.Dsl._create(this.toBuilder()).apply { block() }._build()
