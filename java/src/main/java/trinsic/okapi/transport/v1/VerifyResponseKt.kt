//Generated by the protocol buffer compiler. DO NOT EDIT!
// source: okapi/transport/v1/transport.proto

package trinsic.okapi.transport.v1;

@kotlin.jvm.JvmSynthetic
public inline fun verifyResponse(block: trinsic.okapi.transport.v1.VerifyResponseKt.Dsl.() -> kotlin.Unit): trinsic.okapi.transport.v1.Transport.VerifyResponse =
  trinsic.okapi.transport.v1.VerifyResponseKt.Dsl._create(trinsic.okapi.transport.v1.Transport.VerifyResponse.newBuilder()).apply { block() }._build()
public object VerifyResponseKt {
  @kotlin.OptIn(com.google.protobuf.kotlin.OnlyForUseByGeneratedProtoCode::class)
  @com.google.protobuf.kotlin.ProtoDslMarker
  public class Dsl private constructor(
    private val _builder: trinsic.okapi.transport.v1.Transport.VerifyResponse.Builder
  ) {
    public companion object {
      @kotlin.jvm.JvmSynthetic
      @kotlin.PublishedApi
      internal fun _create(builder: trinsic.okapi.transport.v1.Transport.VerifyResponse.Builder): Dsl = Dsl(builder)
    }

    @kotlin.jvm.JvmSynthetic
    @kotlin.PublishedApi
    internal fun _build(): trinsic.okapi.transport.v1.Transport.VerifyResponse = _builder.build()

    /**
     * <code>bool is_valid = 1;</code>
     */
    public var isValid: kotlin.Boolean
      @JvmName("getIsValid")
      get() = _builder.getIsValid()
      @JvmName("setIsValid")
      set(value) {
        _builder.setIsValid(value)
      }
    /**
     * <code>bool is_valid = 1;</code>
     */
    public fun clearIsValid() {
      _builder.clearIsValid()
    }
  }
}
@kotlin.jvm.JvmSynthetic
public inline fun trinsic.okapi.transport.v1.Transport.VerifyResponse.copy(block: trinsic.okapi.transport.v1.VerifyResponseKt.Dsl.() -> kotlin.Unit): trinsic.okapi.transport.v1.Transport.VerifyResponse =
  trinsic.okapi.transport.v1.VerifyResponseKt.Dsl._create(this.toBuilder()).apply { block() }._build()
