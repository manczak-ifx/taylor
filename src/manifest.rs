use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

#[derive(Debug, Deserialize)]
pub struct SuitEnvelope {
    pub auth_block: SuitAuthentication,
    pub manifest: SuitManifest,
}

#[derive(Debug, Deserialize)]
pub struct SuitAuthentication {
    pub digest: SuitDigest,
    pub auth_blocks: Vec<SuitAuthenticationBlock>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SuitAuthenticationBlock {
    pub algorithm: COSEAuthBlockEnum,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum COSEAuthBlockEnum {
    COSESignTagged,
    COSESign1Tagged,
    COSEMacTagged,
    COSEMac0Tagged,
}

#[derive(Debug, Deserialize)]
pub struct SuitManifest {
    pub version: usize,
    pub sequence_number: usize,
    pub suit_common: SuitCommon,
    pub sequence: Vec<SuitCommandSequence>,
}

#[derive(Debug, Deserialize)]
pub struct SuitCommon {
    pub components: Vec<Vec<ByteBuf>>,
    pub shared_sequence: Vec<SuitCommand>,
}

#[derive(Debug, Deserialize)]
pub struct SuitCommand {
    pub ident: SuitCommandEnum,
}

/// u64 payloads are a SUIT_Rep_Policy bitmask, except for set-component-index (IndexArg).
#[derive(Debug, Deserialize)]
pub enum SuitCommandEnum {
    SuitConditionVendorIdentifier(u64),
    SuitConditionClassIdentifier(u64),
    SuitConditionDeviceIdentifier(u64),
    SuitConditionImageMatch(u64),
    SuitConditionCheckContent(u64),
    SuitConditionComponentSlot(u64),
    SuitConditionAbort(u64),
    SuitDirectiveSetComponentIndex(u64),
    SuitDirectiveTryEach(Vec<Vec<SuitCommand>>, bool),
    SuitDirectiveOverrideParameters(Vec<SuitParameter>),
    SuitDirectiveFetch(u64),
    SuitDirectiveCopy(u64),
    SuitDirectiveWrite(u64),
    SuitDirectiveInvoke(u64),
    SuitDirectiveRunSequence(Vec<SuitCommand>),
    SuitDirectiveSwap(u64),
    // Not spec-conformant: custom commands need a per-command vendor-defined nint code,
    // which conflicts with the no-vendor-lock-in requirement. Kept minimal, out of scope.
    SuitCommandCustom(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SuitCommandSequenceEnum {
    SuitPayloadFetch,
    SuitInstall,
    SuitValidate,
    SuitLoad,
    SuitInvoke,
}

#[derive(Debug, Deserialize)]
pub struct SuitCommandSequence {
    pub sequence: SuitCommandSequenceEnum,
    pub actions: Vec<SuitCommand>,
}

#[derive(Debug, Deserialize)]
pub struct SuitParameter {
    pub ident: SuitParametersEnum,
}

#[derive(Debug, Deserialize)]
pub struct SuitDigest {
    pub algorithm: String,
    pub digest: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub enum SuitParametersEnum {
    SuitVendorID(Vec<u8>),
    SuitClassID(Vec<u8>),
    SuitImageDigest(SuitDigest),
    SuitComponentSlot(u64),
    SuitStrictOrder(bool),
    SuitSoftFailure(bool),
    SuitImageSize(u64),
    SuitContent(Vec<u8>),
    SuitURI(String),
    SuitSourceComponent(u64),
    SuitInvokeArgs(Vec<u8>),
    SuitDeviceID(Vec<u8>),
    SuitFetchArguments(Vec<u8>),
}
