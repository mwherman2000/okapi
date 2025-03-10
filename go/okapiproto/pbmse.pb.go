// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.19.1
// source: pbmse/v1/pbmse.proto

package okapiproto

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type EncryptionMode int32

const (
	EncryptionMode_ENCRYPTION_MODE_UNSPECIFIED            EncryptionMode = 0
	EncryptionMode_ENCRYPTION_MODE_DIRECT                 EncryptionMode = 1
	EncryptionMode_ENCRYPTION_MODE_CONTENT_ENCRYPTION_KEY EncryptionMode = 2
)

// Enum value maps for EncryptionMode.
var (
	EncryptionMode_name = map[int32]string{
		0: "ENCRYPTION_MODE_UNSPECIFIED",
		1: "ENCRYPTION_MODE_DIRECT",
		2: "ENCRYPTION_MODE_CONTENT_ENCRYPTION_KEY",
	}
	EncryptionMode_value = map[string]int32{
		"ENCRYPTION_MODE_UNSPECIFIED":            0,
		"ENCRYPTION_MODE_DIRECT":                 1,
		"ENCRYPTION_MODE_CONTENT_ENCRYPTION_KEY": 2,
	}
)

func (x EncryptionMode) Enum() *EncryptionMode {
	p := new(EncryptionMode)
	*p = x
	return p
}

func (x EncryptionMode) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (EncryptionMode) Descriptor() protoreflect.EnumDescriptor {
	return file_pbmse_v1_pbmse_proto_enumTypes[0].Descriptor()
}

func (EncryptionMode) Type() protoreflect.EnumType {
	return &file_pbmse_v1_pbmse_proto_enumTypes[0]
}

func (x EncryptionMode) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use EncryptionMode.Descriptor instead.
func (EncryptionMode) EnumDescriptor() ([]byte, []int) {
	return file_pbmse_v1_pbmse_proto_rawDescGZIP(), []int{0}
}

type EncryptionAlgorithm int32

const (
	EncryptionAlgorithm_ENCRYPTION_ALGORITHM_UNSPECIFIED       EncryptionAlgorithm = 0
	EncryptionAlgorithm_ENCRYPTION_ALGORITHM_XCHACHA20POLY1305 EncryptionAlgorithm = 1
	EncryptionAlgorithm_ENCRYPTION_ALGORITHM_AES_GCM           EncryptionAlgorithm = 2
)

// Enum value maps for EncryptionAlgorithm.
var (
	EncryptionAlgorithm_name = map[int32]string{
		0: "ENCRYPTION_ALGORITHM_UNSPECIFIED",
		1: "ENCRYPTION_ALGORITHM_XCHACHA20POLY1305",
		2: "ENCRYPTION_ALGORITHM_AES_GCM",
	}
	EncryptionAlgorithm_value = map[string]int32{
		"ENCRYPTION_ALGORITHM_UNSPECIFIED":       0,
		"ENCRYPTION_ALGORITHM_XCHACHA20POLY1305": 1,
		"ENCRYPTION_ALGORITHM_AES_GCM":           2,
	}
)

func (x EncryptionAlgorithm) Enum() *EncryptionAlgorithm {
	p := new(EncryptionAlgorithm)
	*p = x
	return p
}

func (x EncryptionAlgorithm) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (EncryptionAlgorithm) Descriptor() protoreflect.EnumDescriptor {
	return file_pbmse_v1_pbmse_proto_enumTypes[1].Descriptor()
}

func (EncryptionAlgorithm) Type() protoreflect.EnumType {
	return &file_pbmse_v1_pbmse_proto_enumTypes[1]
}

func (x EncryptionAlgorithm) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use EncryptionAlgorithm.Descriptor instead.
func (EncryptionAlgorithm) EnumDescriptor() ([]byte, []int) {
	return file_pbmse_v1_pbmse_proto_rawDescGZIP(), []int{1}
}

// JWS
// Protocol buffer message signing and encryption
type SignedMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Payload    []byte       `protobuf:"bytes,1,opt,name=payload,proto3" json:"payload,omitempty"`
	Signatures []*Signature `protobuf:"bytes,2,rep,name=signatures,proto3" json:"signatures,omitempty"`
}

func (x *SignedMessage) Reset() {
	*x = SignedMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pbmse_v1_pbmse_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignedMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignedMessage) ProtoMessage() {}

func (x *SignedMessage) ProtoReflect() protoreflect.Message {
	mi := &file_pbmse_v1_pbmse_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignedMessage.ProtoReflect.Descriptor instead.
func (*SignedMessage) Descriptor() ([]byte, []int) {
	return file_pbmse_v1_pbmse_proto_rawDescGZIP(), []int{0}
}

func (x *SignedMessage) GetPayload() []byte {
	if x != nil {
		return x.Payload
	}
	return nil
}

func (x *SignedMessage) GetSignatures() []*Signature {
	if x != nil {
		return x.Signatures
	}
	return nil
}

type Signature struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Header    []byte `protobuf:"bytes,1,opt,name=header,proto3" json:"header,omitempty"`
	Signature []byte `protobuf:"bytes,3,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (x *Signature) Reset() {
	*x = Signature{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pbmse_v1_pbmse_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Signature) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Signature) ProtoMessage() {}

func (x *Signature) ProtoReflect() protoreflect.Message {
	mi := &file_pbmse_v1_pbmse_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Signature.ProtoReflect.Descriptor instead.
func (*Signature) Descriptor() ([]byte, []int) {
	return file_pbmse_v1_pbmse_proto_rawDescGZIP(), []int{1}
}

func (x *Signature) GetHeader() []byte {
	if x != nil {
		return x.Header
	}
	return nil
}

func (x *Signature) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

type SignatureHeader struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Algorithm string `protobuf:"bytes,1,opt,name=algorithm,proto3" json:"algorithm,omitempty"`
	KeyId     string `protobuf:"bytes,2,opt,name=key_id,json=keyId,proto3" json:"key_id,omitempty"`
}

func (x *SignatureHeader) Reset() {
	*x = SignatureHeader{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pbmse_v1_pbmse_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignatureHeader) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignatureHeader) ProtoMessage() {}

func (x *SignatureHeader) ProtoReflect() protoreflect.Message {
	mi := &file_pbmse_v1_pbmse_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignatureHeader.ProtoReflect.Descriptor instead.
func (*SignatureHeader) Descriptor() ([]byte, []int) {
	return file_pbmse_v1_pbmse_proto_rawDescGZIP(), []int{2}
}

func (x *SignatureHeader) GetAlgorithm() string {
	if x != nil {
		return x.Algorithm
	}
	return ""
}

func (x *SignatureHeader) GetKeyId() string {
	if x != nil {
		return x.KeyId
	}
	return ""
}

type EncryptedMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Iv         []byte                 `protobuf:"bytes,1,opt,name=iv,proto3" json:"iv,omitempty"`
	Aad        []byte                 `protobuf:"bytes,2,opt,name=aad,proto3" json:"aad,omitempty"`
	Ciphertext []byte                 `protobuf:"bytes,3,opt,name=ciphertext,proto3" json:"ciphertext,omitempty"`
	Tag        []byte                 `protobuf:"bytes,4,opt,name=tag,proto3" json:"tag,omitempty"`
	Recipients []*EncryptionRecipient `protobuf:"bytes,5,rep,name=recipients,proto3" json:"recipients,omitempty"`
}

func (x *EncryptedMessage) Reset() {
	*x = EncryptedMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pbmse_v1_pbmse_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EncryptedMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EncryptedMessage) ProtoMessage() {}

func (x *EncryptedMessage) ProtoReflect() protoreflect.Message {
	mi := &file_pbmse_v1_pbmse_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EncryptedMessage.ProtoReflect.Descriptor instead.
func (*EncryptedMessage) Descriptor() ([]byte, []int) {
	return file_pbmse_v1_pbmse_proto_rawDescGZIP(), []int{3}
}

func (x *EncryptedMessage) GetIv() []byte {
	if x != nil {
		return x.Iv
	}
	return nil
}

func (x *EncryptedMessage) GetAad() []byte {
	if x != nil {
		return x.Aad
	}
	return nil
}

func (x *EncryptedMessage) GetCiphertext() []byte {
	if x != nil {
		return x.Ciphertext
	}
	return nil
}

func (x *EncryptedMessage) GetTag() []byte {
	if x != nil {
		return x.Tag
	}
	return nil
}

func (x *EncryptedMessage) GetRecipients() []*EncryptionRecipient {
	if x != nil {
		return x.Recipients
	}
	return nil
}

type EncryptionHeader struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Mode        EncryptionMode      `protobuf:"varint,1,opt,name=mode,json=enc,proto3,enum=pbmse.v1.EncryptionMode" json:"mode,omitempty"`
	Algorithm   EncryptionAlgorithm `protobuf:"varint,2,opt,name=algorithm,json=alg,proto3,enum=pbmse.v1.EncryptionAlgorithm" json:"algorithm,omitempty"`
	KeyId       string              `protobuf:"bytes,3,opt,name=key_id,json=kid,proto3" json:"key_id,omitempty"`
	SenderKeyId string              `protobuf:"bytes,4,opt,name=sender_key_id,json=skid,proto3" json:"sender_key_id,omitempty"`
}

func (x *EncryptionHeader) Reset() {
	*x = EncryptionHeader{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pbmse_v1_pbmse_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EncryptionHeader) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EncryptionHeader) ProtoMessage() {}

func (x *EncryptionHeader) ProtoReflect() protoreflect.Message {
	mi := &file_pbmse_v1_pbmse_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EncryptionHeader.ProtoReflect.Descriptor instead.
func (*EncryptionHeader) Descriptor() ([]byte, []int) {
	return file_pbmse_v1_pbmse_proto_rawDescGZIP(), []int{4}
}

func (x *EncryptionHeader) GetMode() EncryptionMode {
	if x != nil {
		return x.Mode
	}
	return EncryptionMode_ENCRYPTION_MODE_UNSPECIFIED
}

func (x *EncryptionHeader) GetAlgorithm() EncryptionAlgorithm {
	if x != nil {
		return x.Algorithm
	}
	return EncryptionAlgorithm_ENCRYPTION_ALGORITHM_UNSPECIFIED
}

func (x *EncryptionHeader) GetKeyId() string {
	if x != nil {
		return x.KeyId
	}
	return ""
}

func (x *EncryptionHeader) GetSenderKeyId() string {
	if x != nil {
		return x.SenderKeyId
	}
	return ""
}

type EncryptionRecipient struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Header               *EncryptionHeader `protobuf:"bytes,1,opt,name=header,json=unprotected,proto3" json:"header,omitempty"`
	ContentEncryptionKey []byte            `protobuf:"bytes,2,opt,name=content_encryption_key,json=cek,proto3" json:"content_encryption_key,omitempty"`
}

func (x *EncryptionRecipient) Reset() {
	*x = EncryptionRecipient{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pbmse_v1_pbmse_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EncryptionRecipient) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EncryptionRecipient) ProtoMessage() {}

func (x *EncryptionRecipient) ProtoReflect() protoreflect.Message {
	mi := &file_pbmse_v1_pbmse_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EncryptionRecipient.ProtoReflect.Descriptor instead.
func (*EncryptionRecipient) Descriptor() ([]byte, []int) {
	return file_pbmse_v1_pbmse_proto_rawDescGZIP(), []int{5}
}

func (x *EncryptionRecipient) GetHeader() *EncryptionHeader {
	if x != nil {
		return x.Header
	}
	return nil
}

func (x *EncryptionRecipient) GetContentEncryptionKey() []byte {
	if x != nil {
		return x.ContentEncryptionKey
	}
	return nil
}

var File_pbmse_v1_pbmse_proto protoreflect.FileDescriptor

var file_pbmse_v1_pbmse_proto_rawDesc = []byte{
	0x0a, 0x14, 0x70, 0x62, 0x6d, 0x73, 0x65, 0x2f, 0x76, 0x31, 0x2f, 0x70, 0x62, 0x6d, 0x73, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x08, 0x70, 0x62, 0x6d, 0x73, 0x65, 0x2e, 0x76, 0x31,
	0x22, 0x5e, 0x0a, 0x0d, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67,
	0x65, 0x12, 0x18, 0x0a, 0x07, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x07, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x12, 0x33, 0x0a, 0x0a, 0x73,
	0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x13, 0x2e, 0x70, 0x62, 0x6d, 0x73, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x69, 0x67, 0x6e, 0x61,
	0x74, 0x75, 0x72, 0x65, 0x52, 0x0a, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73,
	0x22, 0x41, 0x0a, 0x09, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x12, 0x16, 0x0a,
	0x06, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x68,
	0x65, 0x61, 0x64, 0x65, 0x72, 0x12, 0x1c, 0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75,
	0x72, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74,
	0x75, 0x72, 0x65, 0x22, 0x46, 0x0a, 0x0f, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65,
	0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x12, 0x1c, 0x0a, 0x09, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69,
	0x74, 0x68, 0x6d, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x61, 0x6c, 0x67, 0x6f, 0x72,
	0x69, 0x74, 0x68, 0x6d, 0x12, 0x15, 0x0a, 0x06, 0x6b, 0x65, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6b, 0x65, 0x79, 0x49, 0x64, 0x22, 0xa5, 0x01, 0x0a, 0x10,
	0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
	0x12, 0x0e, 0x0a, 0x02, 0x69, 0x76, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x69, 0x76,
	0x12, 0x10, 0x0a, 0x03, 0x61, 0x61, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03, 0x61,
	0x61, 0x64, 0x12, 0x1e, 0x0a, 0x0a, 0x63, 0x69, 0x70, 0x68, 0x65, 0x72, 0x74, 0x65, 0x78, 0x74,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0a, 0x63, 0x69, 0x70, 0x68, 0x65, 0x72, 0x74, 0x65,
	0x78, 0x74, 0x12, 0x10, 0x0a, 0x03, 0x74, 0x61, 0x67, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x03, 0x74, 0x61, 0x67, 0x12, 0x3d, 0x0a, 0x0a, 0x72, 0x65, 0x63, 0x69, 0x70, 0x69, 0x65, 0x6e,
	0x74, 0x73, 0x18, 0x05, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1d, 0x2e, 0x70, 0x62, 0x6d, 0x73, 0x65,
	0x2e, 0x76, 0x31, 0x2e, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65,
	0x63, 0x69, 0x70, 0x69, 0x65, 0x6e, 0x74, 0x52, 0x0a, 0x72, 0x65, 0x63, 0x69, 0x70, 0x69, 0x65,
	0x6e, 0x74, 0x73, 0x22, 0xa8, 0x01, 0x0a, 0x10, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69,
	0x6f, 0x6e, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x12, 0x2b, 0x0a, 0x04, 0x6d, 0x6f, 0x64, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x18, 0x2e, 0x70, 0x62, 0x6d, 0x73, 0x65, 0x2e, 0x76,
	0x31, 0x2e, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x4d, 0x6f, 0x64, 0x65,
	0x52, 0x03, 0x65, 0x6e, 0x63, 0x12, 0x35, 0x0a, 0x09, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74,
	0x68, 0x6d, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x1d, 0x2e, 0x70, 0x62, 0x6d, 0x73, 0x65,
	0x2e, 0x76, 0x31, 0x2e, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x41, 0x6c,
	0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x52, 0x03, 0x61, 0x6c, 0x67, 0x12, 0x13, 0x0a, 0x06,
	0x6b, 0x65, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x69,
	0x64, 0x12, 0x1b, 0x0a, 0x0d, 0x73, 0x65, 0x6e, 0x64, 0x65, 0x72, 0x5f, 0x6b, 0x65, 0x79, 0x5f,
	0x69, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x73, 0x6b, 0x69, 0x64, 0x22, 0x73,
	0x0a, 0x13, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x63, 0x69,
	0x70, 0x69, 0x65, 0x6e, 0x74, 0x12, 0x37, 0x0a, 0x06, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x70, 0x62, 0x6d, 0x73, 0x65, 0x2e, 0x76, 0x31,
	0x2e, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x48, 0x65, 0x61, 0x64, 0x65,
	0x72, 0x52, 0x0b, 0x75, 0x6e, 0x70, 0x72, 0x6f, 0x74, 0x65, 0x63, 0x74, 0x65, 0x64, 0x12, 0x23,
	0x0a, 0x16, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x5f, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03,
	0x63, 0x65, 0x6b, 0x2a, 0x79, 0x0a, 0x0e, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f,
	0x6e, 0x4d, 0x6f, 0x64, 0x65, 0x12, 0x1f, 0x0a, 0x1b, 0x45, 0x4e, 0x43, 0x52, 0x59, 0x50, 0x54,
	0x49, 0x4f, 0x4e, 0x5f, 0x4d, 0x4f, 0x44, 0x45, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49,
	0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x1a, 0x0a, 0x16, 0x45, 0x4e, 0x43, 0x52, 0x59, 0x50,
	0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x4d, 0x4f, 0x44, 0x45, 0x5f, 0x44, 0x49, 0x52, 0x45, 0x43, 0x54,
	0x10, 0x01, 0x12, 0x2a, 0x0a, 0x26, 0x45, 0x4e, 0x43, 0x52, 0x59, 0x50, 0x54, 0x49, 0x4f, 0x4e,
	0x5f, 0x4d, 0x4f, 0x44, 0x45, 0x5f, 0x43, 0x4f, 0x4e, 0x54, 0x45, 0x4e, 0x54, 0x5f, 0x45, 0x4e,
	0x43, 0x52, 0x59, 0x50, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x4b, 0x45, 0x59, 0x10, 0x02, 0x2a, 0x89,
	0x01, 0x0a, 0x13, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x41, 0x6c, 0x67,
	0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x12, 0x24, 0x0a, 0x20, 0x45, 0x4e, 0x43, 0x52, 0x59, 0x50,
	0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x41, 0x4c, 0x47, 0x4f, 0x52, 0x49, 0x54, 0x48, 0x4d, 0x5f, 0x55,
	0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x2a, 0x0a, 0x26,
	0x45, 0x4e, 0x43, 0x52, 0x59, 0x50, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x41, 0x4c, 0x47, 0x4f, 0x52,
	0x49, 0x54, 0x48, 0x4d, 0x5f, 0x58, 0x43, 0x48, 0x41, 0x43, 0x48, 0x41, 0x32, 0x30, 0x50, 0x4f,
	0x4c, 0x59, 0x31, 0x33, 0x30, 0x35, 0x10, 0x01, 0x12, 0x20, 0x0a, 0x1c, 0x45, 0x4e, 0x43, 0x52,
	0x59, 0x50, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x41, 0x4c, 0x47, 0x4f, 0x52, 0x49, 0x54, 0x48, 0x4d,
	0x5f, 0x41, 0x45, 0x53, 0x5f, 0x47, 0x43, 0x4d, 0x10, 0x02, 0x42, 0x3a, 0x0a, 0x16, 0x74, 0x72,
	0x69, 0x6e, 0x73, 0x69, 0x63, 0x2e, 0x6f, 0x6b, 0x61, 0x70, 0x69, 0x2e, 0x70, 0x62, 0x6d, 0x73,
	0x65, 0x2e, 0x76, 0x31, 0x5a, 0x20, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x74, 0x72, 0x69, 0x6e, 0x73, 0x69, 0x63, 0x2d, 0x69, 0x64, 0x2f, 0x6f, 0x6b, 0x61, 0x70,
	0x69, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_pbmse_v1_pbmse_proto_rawDescOnce sync.Once
	file_pbmse_v1_pbmse_proto_rawDescData = file_pbmse_v1_pbmse_proto_rawDesc
)

func file_pbmse_v1_pbmse_proto_rawDescGZIP() []byte {
	file_pbmse_v1_pbmse_proto_rawDescOnce.Do(func() {
		file_pbmse_v1_pbmse_proto_rawDescData = protoimpl.X.CompressGZIP(file_pbmse_v1_pbmse_proto_rawDescData)
	})
	return file_pbmse_v1_pbmse_proto_rawDescData
}

var file_pbmse_v1_pbmse_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_pbmse_v1_pbmse_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_pbmse_v1_pbmse_proto_goTypes = []interface{}{
	(EncryptionMode)(0),         // 0: pbmse.v1.EncryptionMode
	(EncryptionAlgorithm)(0),    // 1: pbmse.v1.EncryptionAlgorithm
	(*SignedMessage)(nil),       // 2: pbmse.v1.SignedMessage
	(*Signature)(nil),           // 3: pbmse.v1.Signature
	(*SignatureHeader)(nil),     // 4: pbmse.v1.SignatureHeader
	(*EncryptedMessage)(nil),    // 5: pbmse.v1.EncryptedMessage
	(*EncryptionHeader)(nil),    // 6: pbmse.v1.EncryptionHeader
	(*EncryptionRecipient)(nil), // 7: pbmse.v1.EncryptionRecipient
}
var file_pbmse_v1_pbmse_proto_depIdxs = []int32{
	3, // 0: pbmse.v1.SignedMessage.signatures:type_name -> pbmse.v1.Signature
	7, // 1: pbmse.v1.EncryptedMessage.recipients:type_name -> pbmse.v1.EncryptionRecipient
	0, // 2: pbmse.v1.EncryptionHeader.mode:type_name -> pbmse.v1.EncryptionMode
	1, // 3: pbmse.v1.EncryptionHeader.algorithm:type_name -> pbmse.v1.EncryptionAlgorithm
	6, // 4: pbmse.v1.EncryptionRecipient.header:type_name -> pbmse.v1.EncryptionHeader
	5, // [5:5] is the sub-list for method output_type
	5, // [5:5] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_pbmse_v1_pbmse_proto_init() }
func file_pbmse_v1_pbmse_proto_init() {
	if File_pbmse_v1_pbmse_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_pbmse_v1_pbmse_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignedMessage); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pbmse_v1_pbmse_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Signature); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pbmse_v1_pbmse_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignatureHeader); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pbmse_v1_pbmse_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EncryptedMessage); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pbmse_v1_pbmse_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EncryptionHeader); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pbmse_v1_pbmse_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EncryptionRecipient); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_pbmse_v1_pbmse_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_pbmse_v1_pbmse_proto_goTypes,
		DependencyIndexes: file_pbmse_v1_pbmse_proto_depIdxs,
		EnumInfos:         file_pbmse_v1_pbmse_proto_enumTypes,
		MessageInfos:      file_pbmse_v1_pbmse_proto_msgTypes,
	}.Build()
	File_pbmse_v1_pbmse_proto = out.File
	file_pbmse_v1_pbmse_proto_rawDesc = nil
	file_pbmse_v1_pbmse_proto_goTypes = nil
	file_pbmse_v1_pbmse_proto_depIdxs = nil
}
