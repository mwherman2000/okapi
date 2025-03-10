// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: okapi/examples/v1/examples.proto

package trinsic.okapi.examples.v1;

public final class Examples {
  private Examples() {}
  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistryLite registry) {
  }

  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistry registry) {
    registerAllExtensions(
        (com.google.protobuf.ExtensionRegistryLite) registry);
  }
  public interface BasicMessageOrBuilder extends
      // @@protoc_insertion_point(interface_extends:okapi.examples.v1.BasicMessage)
      com.google.protobuf.MessageOrBuilder {

    /**
     * <code>string text = 1;</code>
     * @return The text.
     */
    java.lang.String getText();
    /**
     * <code>string text = 1;</code>
     * @return The bytes for text.
     */
    com.google.protobuf.ByteString
        getTextBytes();
  }
  /**
   * Protobuf type {@code okapi.examples.v1.BasicMessage}
   */
  public static final class BasicMessage extends
      com.google.protobuf.GeneratedMessageV3 implements
      // @@protoc_insertion_point(message_implements:okapi.examples.v1.BasicMessage)
      BasicMessageOrBuilder {
  private static final long serialVersionUID = 0L;
    // Use BasicMessage.newBuilder() to construct.
    private BasicMessage(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
      super(builder);
    }
    private BasicMessage() {
      text_ = "";
    }

    @java.lang.Override
    @SuppressWarnings({"unused"})
    protected java.lang.Object newInstance(
        UnusedPrivateParameter unused) {
      return new BasicMessage();
    }

    @java.lang.Override
    public final com.google.protobuf.UnknownFieldSet
    getUnknownFields() {
      return this.unknownFields;
    }
    private BasicMessage(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      this();
      if (extensionRegistry == null) {
        throw new java.lang.NullPointerException();
      }
      com.google.protobuf.UnknownFieldSet.Builder unknownFields =
          com.google.protobuf.UnknownFieldSet.newBuilder();
      try {
        boolean done = false;
        while (!done) {
          int tag = input.readTag();
          switch (tag) {
            case 0:
              done = true;
              break;
            case 10: {
              java.lang.String s = input.readStringRequireUtf8();

              text_ = s;
              break;
            }
            default: {
              if (!parseUnknownField(
                  input, unknownFields, extensionRegistry, tag)) {
                done = true;
              }
              break;
            }
          }
        }
      } catch (com.google.protobuf.InvalidProtocolBufferException e) {
        throw e.setUnfinishedMessage(this);
      } catch (java.io.IOException e) {
        throw new com.google.protobuf.InvalidProtocolBufferException(
            e).setUnfinishedMessage(this);
      } finally {
        this.unknownFields = unknownFields.build();
        makeExtensionsImmutable();
      }
    }
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return trinsic.okapi.examples.v1.Examples.internal_static_okapi_examples_v1_BasicMessage_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return trinsic.okapi.examples.v1.Examples.internal_static_okapi_examples_v1_BasicMessage_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              trinsic.okapi.examples.v1.Examples.BasicMessage.class, trinsic.okapi.examples.v1.Examples.BasicMessage.Builder.class);
    }

    public static final int TEXT_FIELD_NUMBER = 1;
    private volatile java.lang.Object text_;
    /**
     * <code>string text = 1;</code>
     * @return The text.
     */
    @java.lang.Override
    public java.lang.String getText() {
      java.lang.Object ref = text_;
      if (ref instanceof java.lang.String) {
        return (java.lang.String) ref;
      } else {
        com.google.protobuf.ByteString bs = 
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        text_ = s;
        return s;
      }
    }
    /**
     * <code>string text = 1;</code>
     * @return The bytes for text.
     */
    @java.lang.Override
    public com.google.protobuf.ByteString
        getTextBytes() {
      java.lang.Object ref = text_;
      if (ref instanceof java.lang.String) {
        com.google.protobuf.ByteString b = 
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        text_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }

    private byte memoizedIsInitialized = -1;
    @java.lang.Override
    public final boolean isInitialized() {
      byte isInitialized = memoizedIsInitialized;
      if (isInitialized == 1) return true;
      if (isInitialized == 0) return false;

      memoizedIsInitialized = 1;
      return true;
    }

    @java.lang.Override
    public void writeTo(com.google.protobuf.CodedOutputStream output)
                        throws java.io.IOException {
      if (!com.google.protobuf.GeneratedMessageV3.isStringEmpty(text_)) {
        com.google.protobuf.GeneratedMessageV3.writeString(output, 1, text_);
      }
      unknownFields.writeTo(output);
    }

    @java.lang.Override
    public int getSerializedSize() {
      int size = memoizedSize;
      if (size != -1) return size;

      size = 0;
      if (!com.google.protobuf.GeneratedMessageV3.isStringEmpty(text_)) {
        size += com.google.protobuf.GeneratedMessageV3.computeStringSize(1, text_);
      }
      size += unknownFields.getSerializedSize();
      memoizedSize = size;
      return size;
    }

    @java.lang.Override
    public boolean equals(final java.lang.Object obj) {
      if (obj == this) {
       return true;
      }
      if (!(obj instanceof trinsic.okapi.examples.v1.Examples.BasicMessage)) {
        return super.equals(obj);
      }
      trinsic.okapi.examples.v1.Examples.BasicMessage other = (trinsic.okapi.examples.v1.Examples.BasicMessage) obj;

      if (!getText()
          .equals(other.getText())) return false;
      if (!unknownFields.equals(other.unknownFields)) return false;
      return true;
    }

    @java.lang.Override
    public int hashCode() {
      if (memoizedHashCode != 0) {
        return memoizedHashCode;
      }
      int hash = 41;
      hash = (19 * hash) + getDescriptor().hashCode();
      hash = (37 * hash) + TEXT_FIELD_NUMBER;
      hash = (53 * hash) + getText().hashCode();
      hash = (29 * hash) + unknownFields.hashCode();
      memoizedHashCode = hash;
      return hash;
    }

    public static trinsic.okapi.examples.v1.Examples.BasicMessage parseFrom(
        java.nio.ByteBuffer data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static trinsic.okapi.examples.v1.Examples.BasicMessage parseFrom(
        java.nio.ByteBuffer data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static trinsic.okapi.examples.v1.Examples.BasicMessage parseFrom(
        com.google.protobuf.ByteString data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static trinsic.okapi.examples.v1.Examples.BasicMessage parseFrom(
        com.google.protobuf.ByteString data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static trinsic.okapi.examples.v1.Examples.BasicMessage parseFrom(byte[] data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static trinsic.okapi.examples.v1.Examples.BasicMessage parseFrom(
        byte[] data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static trinsic.okapi.examples.v1.Examples.BasicMessage parseFrom(java.io.InputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input);
    }
    public static trinsic.okapi.examples.v1.Examples.BasicMessage parseFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input, extensionRegistry);
    }
    public static trinsic.okapi.examples.v1.Examples.BasicMessage parseDelimitedFrom(java.io.InputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseDelimitedWithIOException(PARSER, input);
    }
    public static trinsic.okapi.examples.v1.Examples.BasicMessage parseDelimitedFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
    }
    public static trinsic.okapi.examples.v1.Examples.BasicMessage parseFrom(
        com.google.protobuf.CodedInputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input);
    }
    public static trinsic.okapi.examples.v1.Examples.BasicMessage parseFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input, extensionRegistry);
    }

    @java.lang.Override
    public Builder newBuilderForType() { return newBuilder(); }
    public static Builder newBuilder() {
      return DEFAULT_INSTANCE.toBuilder();
    }
    public static Builder newBuilder(trinsic.okapi.examples.v1.Examples.BasicMessage prototype) {
      return DEFAULT_INSTANCE.toBuilder().mergeFrom(prototype);
    }
    @java.lang.Override
    public Builder toBuilder() {
      return this == DEFAULT_INSTANCE
          ? new Builder() : new Builder().mergeFrom(this);
    }

    @java.lang.Override
    protected Builder newBuilderForType(
        com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
      Builder builder = new Builder(parent);
      return builder;
    }
    /**
     * Protobuf type {@code okapi.examples.v1.BasicMessage}
     */
    public static final class Builder extends
        com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
        // @@protoc_insertion_point(builder_implements:okapi.examples.v1.BasicMessage)
        trinsic.okapi.examples.v1.Examples.BasicMessageOrBuilder {
      public static final com.google.protobuf.Descriptors.Descriptor
          getDescriptor() {
        return trinsic.okapi.examples.v1.Examples.internal_static_okapi_examples_v1_BasicMessage_descriptor;
      }

      @java.lang.Override
      protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
          internalGetFieldAccessorTable() {
        return trinsic.okapi.examples.v1.Examples.internal_static_okapi_examples_v1_BasicMessage_fieldAccessorTable
            .ensureFieldAccessorsInitialized(
                trinsic.okapi.examples.v1.Examples.BasicMessage.class, trinsic.okapi.examples.v1.Examples.BasicMessage.Builder.class);
      }

      // Construct using trinsic.okapi.examples.v1.Examples.BasicMessage.newBuilder()
      private Builder() {
        maybeForceBuilderInitialization();
      }

      private Builder(
          com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
        super(parent);
        maybeForceBuilderInitialization();
      }
      private void maybeForceBuilderInitialization() {
        if (com.google.protobuf.GeneratedMessageV3
                .alwaysUseFieldBuilders) {
        }
      }
      @java.lang.Override
      public Builder clear() {
        super.clear();
        text_ = "";

        return this;
      }

      @java.lang.Override
      public com.google.protobuf.Descriptors.Descriptor
          getDescriptorForType() {
        return trinsic.okapi.examples.v1.Examples.internal_static_okapi_examples_v1_BasicMessage_descriptor;
      }

      @java.lang.Override
      public trinsic.okapi.examples.v1.Examples.BasicMessage getDefaultInstanceForType() {
        return trinsic.okapi.examples.v1.Examples.BasicMessage.getDefaultInstance();
      }

      @java.lang.Override
      public trinsic.okapi.examples.v1.Examples.BasicMessage build() {
        trinsic.okapi.examples.v1.Examples.BasicMessage result = buildPartial();
        if (!result.isInitialized()) {
          throw newUninitializedMessageException(result);
        }
        return result;
      }

      @java.lang.Override
      public trinsic.okapi.examples.v1.Examples.BasicMessage buildPartial() {
        trinsic.okapi.examples.v1.Examples.BasicMessage result = new trinsic.okapi.examples.v1.Examples.BasicMessage(this);
        result.text_ = text_;
        onBuilt();
        return result;
      }

      @java.lang.Override
      public Builder clone() {
        return super.clone();
      }
      @java.lang.Override
      public Builder setField(
          com.google.protobuf.Descriptors.FieldDescriptor field,
          java.lang.Object value) {
        return super.setField(field, value);
      }
      @java.lang.Override
      public Builder clearField(
          com.google.protobuf.Descriptors.FieldDescriptor field) {
        return super.clearField(field);
      }
      @java.lang.Override
      public Builder clearOneof(
          com.google.protobuf.Descriptors.OneofDescriptor oneof) {
        return super.clearOneof(oneof);
      }
      @java.lang.Override
      public Builder setRepeatedField(
          com.google.protobuf.Descriptors.FieldDescriptor field,
          int index, java.lang.Object value) {
        return super.setRepeatedField(field, index, value);
      }
      @java.lang.Override
      public Builder addRepeatedField(
          com.google.protobuf.Descriptors.FieldDescriptor field,
          java.lang.Object value) {
        return super.addRepeatedField(field, value);
      }
      @java.lang.Override
      public Builder mergeFrom(com.google.protobuf.Message other) {
        if (other instanceof trinsic.okapi.examples.v1.Examples.BasicMessage) {
          return mergeFrom((trinsic.okapi.examples.v1.Examples.BasicMessage)other);
        } else {
          super.mergeFrom(other);
          return this;
        }
      }

      public Builder mergeFrom(trinsic.okapi.examples.v1.Examples.BasicMessage other) {
        if (other == trinsic.okapi.examples.v1.Examples.BasicMessage.getDefaultInstance()) return this;
        if (!other.getText().isEmpty()) {
          text_ = other.text_;
          onChanged();
        }
        this.mergeUnknownFields(other.unknownFields);
        onChanged();
        return this;
      }

      @java.lang.Override
      public final boolean isInitialized() {
        return true;
      }

      @java.lang.Override
      public Builder mergeFrom(
          com.google.protobuf.CodedInputStream input,
          com.google.protobuf.ExtensionRegistryLite extensionRegistry)
          throws java.io.IOException {
        trinsic.okapi.examples.v1.Examples.BasicMessage parsedMessage = null;
        try {
          parsedMessage = PARSER.parsePartialFrom(input, extensionRegistry);
        } catch (com.google.protobuf.InvalidProtocolBufferException e) {
          parsedMessage = (trinsic.okapi.examples.v1.Examples.BasicMessage) e.getUnfinishedMessage();
          throw e.unwrapIOException();
        } finally {
          if (parsedMessage != null) {
            mergeFrom(parsedMessage);
          }
        }
        return this;
      }

      private java.lang.Object text_ = "";
      /**
       * <code>string text = 1;</code>
       * @return The text.
       */
      public java.lang.String getText() {
        java.lang.Object ref = text_;
        if (!(ref instanceof java.lang.String)) {
          com.google.protobuf.ByteString bs =
              (com.google.protobuf.ByteString) ref;
          java.lang.String s = bs.toStringUtf8();
          text_ = s;
          return s;
        } else {
          return (java.lang.String) ref;
        }
      }
      /**
       * <code>string text = 1;</code>
       * @return The bytes for text.
       */
      public com.google.protobuf.ByteString
          getTextBytes() {
        java.lang.Object ref = text_;
        if (ref instanceof String) {
          com.google.protobuf.ByteString b = 
              com.google.protobuf.ByteString.copyFromUtf8(
                  (java.lang.String) ref);
          text_ = b;
          return b;
        } else {
          return (com.google.protobuf.ByteString) ref;
        }
      }
      /**
       * <code>string text = 1;</code>
       * @param value The text to set.
       * @return This builder for chaining.
       */
      public Builder setText(
          java.lang.String value) {
        if (value == null) {
    throw new NullPointerException();
  }
  
        text_ = value;
        onChanged();
        return this;
      }
      /**
       * <code>string text = 1;</code>
       * @return This builder for chaining.
       */
      public Builder clearText() {
        
        text_ = getDefaultInstance().getText();
        onChanged();
        return this;
      }
      /**
       * <code>string text = 1;</code>
       * @param value The bytes for text to set.
       * @return This builder for chaining.
       */
      public Builder setTextBytes(
          com.google.protobuf.ByteString value) {
        if (value == null) {
    throw new NullPointerException();
  }
  checkByteStringIsUtf8(value);
        
        text_ = value;
        onChanged();
        return this;
      }
      @java.lang.Override
      public final Builder setUnknownFields(
          final com.google.protobuf.UnknownFieldSet unknownFields) {
        return super.setUnknownFields(unknownFields);
      }

      @java.lang.Override
      public final Builder mergeUnknownFields(
          final com.google.protobuf.UnknownFieldSet unknownFields) {
        return super.mergeUnknownFields(unknownFields);
      }


      // @@protoc_insertion_point(builder_scope:okapi.examples.v1.BasicMessage)
    }

    // @@protoc_insertion_point(class_scope:okapi.examples.v1.BasicMessage)
    private static final trinsic.okapi.examples.v1.Examples.BasicMessage DEFAULT_INSTANCE;
    static {
      DEFAULT_INSTANCE = new trinsic.okapi.examples.v1.Examples.BasicMessage();
    }

    public static trinsic.okapi.examples.v1.Examples.BasicMessage getDefaultInstance() {
      return DEFAULT_INSTANCE;
    }

    private static final com.google.protobuf.Parser<BasicMessage>
        PARSER = new com.google.protobuf.AbstractParser<BasicMessage>() {
      @java.lang.Override
      public BasicMessage parsePartialFrom(
          com.google.protobuf.CodedInputStream input,
          com.google.protobuf.ExtensionRegistryLite extensionRegistry)
          throws com.google.protobuf.InvalidProtocolBufferException {
        return new BasicMessage(input, extensionRegistry);
      }
    };

    public static com.google.protobuf.Parser<BasicMessage> parser() {
      return PARSER;
    }

    @java.lang.Override
    public com.google.protobuf.Parser<BasicMessage> getParserForType() {
      return PARSER;
    }

    @java.lang.Override
    public trinsic.okapi.examples.v1.Examples.BasicMessage getDefaultInstanceForType() {
      return DEFAULT_INSTANCE;
    }

  }

  private static final com.google.protobuf.Descriptors.Descriptor
    internal_static_okapi_examples_v1_BasicMessage_descriptor;
  private static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_okapi_examples_v1_BasicMessage_fieldAccessorTable;

  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static  com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    java.lang.String[] descriptorData = {
      "\n okapi/examples/v1/examples.proto\022\021okap" +
      "i.examples.v1\032\024pbmse/v1/pbmse.proto\"\034\n\014B" +
      "asicMessage\022\014\n\004text\030\001 \001(\t2\244\001\n\024SecureExam" +
      "pleService\022?\n\005Unary\022\032.pbmse.v1.Encrypted" +
      "Message\032\032.pbmse.v1.EncryptedMessage\022K\n\017S" +
      "erverStreaming\022\032.pbmse.v1.EncryptedMessa" +
      "ge\032\032.pbmse.v1.EncryptedMessage0\001BQ\n\031trin" +
      "sic.okapi.examples.v1Z github.com/trinsi" +
      "c-id/okapiproto\252\002\021Okapi.Examples.V1b\006pro" +
      "to3"
    };
    descriptor = com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
          trinsic.okapi.pbmse.v1.Pbmse.getDescriptor(),
        });
    internal_static_okapi_examples_v1_BasicMessage_descriptor =
      getDescriptor().getMessageTypes().get(0);
    internal_static_okapi_examples_v1_BasicMessage_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_okapi_examples_v1_BasicMessage_descriptor,
        new java.lang.String[] { "Text", });
    trinsic.okapi.pbmse.v1.Pbmse.getDescriptor();
  }

  // @@protoc_insertion_point(outer_class_scope)
}
