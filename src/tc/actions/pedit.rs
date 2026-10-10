// SPDX-License-Identifier: MIT

/// Pedit action
///
/// The pedit action allows to rewrite arbitrary bytes of a packet header
/// or payload.
use std::mem::size_of;

use netlink_packet_core::{
    emit_u16, parse_u16, DecodeError, DefaultNla, Emitable, ErrorContext, Nla,
    NlaBuffer, NlasIterator, Parseable,
};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use super::{TcActionGeneric, TcActionGenericBuffer, Tcf, TcfBuffer};

/// Traffic control action used to rewrite packet header fields.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct TcActionPedit {}
impl TcActionPedit {
    /// The `TcActionAttribute::Kind` of this action.
    pub const KIND: &'static str = "pedit";
}

const TCA_PEDIT_TM: u16 = 1;
const TCA_PEDIT_PARMS: u16 = 2;
const TCA_PEDIT_PARMS_EX: u16 = 4;
const TCA_PEDIT_KEYS_EX: u16 = 5;
const TCA_PEDIT_KEY_EX: u16 = 6;

/// Options for the `TcActionPedit` action.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum TcActionPeditOption {
    /// Rule installation and usage time
    Tm(Tcf),
    /// Parameters for the pedit action.
    Parms(TcPedit),
    /// Parameters for the pedit action in extended form.
    ParmsEx(TcPedit),
    /// Header type and command of each key of the extended form.
    KeysEx(Vec<TcPeditKeyEx>),
    /// Other attributes unknown at the time of writing.
    Other(DefaultNla),
}

impl Nla for TcActionPeditOption {
    fn value_len(&self) -> usize {
        match self {
            Self::Tm(_) => size_of::<TcfBuffer>(),
            Self::Parms(v) | Self::ParmsEx(v) => v.buffer_len(),
            Self::KeysEx(v) => v.as_slice().buffer_len(),
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Tm(p) => p.emit(buffer),
            Self::Parms(p) | Self::ParmsEx(p) => p.emit(buffer),
            Self::KeysEx(v) => v.as_slice().emit(buffer),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }
    fn kind(&self) -> u16 {
        match self {
            Self::Tm(_) => TCA_PEDIT_TM,
            Self::Parms(_) => TCA_PEDIT_PARMS,
            Self::ParmsEx(_) => TCA_PEDIT_PARMS_EX,
            Self::KeysEx(_) => TCA_PEDIT_KEYS_EX,
            Self::Other(nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for TcActionPeditOption
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            TCA_PEDIT_TM => Self::Tm(Tcf::parse(payload)?),
            TCA_PEDIT_PARMS => Self::Parms(TcPedit::parse(payload)?),
            TCA_PEDIT_PARMS_EX => Self::ParmsEx(TcPedit::parse(payload)?),
            TCA_PEDIT_KEYS_EX => {
                let mut nlas = vec![];
                for nla in NlasIterator::new(payload) {
                    let nla = nla.context("invalid TCA_PEDIT_KEYS_EX")?;
                    nlas.push(
                        TcPeditKeyEx::parse(&nla)
                            .context("failed to parse TCA_PEDIT_KEYS_EX")?,
                    );
                }
                Self::KeysEx(nlas)
            }
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}

/// Extended information of a single pedit key.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum TcPeditKeyEx {
    /// Header type and command of one key.
    Key(Vec<TcPeditKeyExOption>),
    /// Other attributes unknown at the time of writing.
    Other(DefaultNla),
}

impl Nla for TcPeditKeyEx {
    fn value_len(&self) -> usize {
        match self {
            Self::Key(attr) => attr.as_slice().buffer_len(),
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Key(attr) => attr.as_slice().emit(buffer),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Key(_) => TCA_PEDIT_KEY_EX,
            Self::Other(attr) => attr.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for TcPeditKeyEx {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        Ok(match buf.kind() {
            TCA_PEDIT_KEY_EX => {
                let mut nlas = vec![];
                for nla in NlasIterator::new(buf.value()) {
                    let nla = nla.context("invalid TCA_PEDIT_KEY_EX")?;
                    nlas.push(
                        TcPeditKeyExOption::parse(&nla)
                            .context("failed to parse TCA_PEDIT_KEY_EX")?,
                    );
                }
                Self::Key(nlas)
            }
            _ => Self::Other(
                DefaultNla::parse(buf)
                    .context("failed to parse pedit key ex nla")?,
            ),
        })
    }
}

const TCA_PEDIT_KEY_EX_HTYPE: u16 = 1;
const TCA_PEDIT_KEY_EX_CMD: u16 = 2;

/// Attributes of the extended information of a pedit key.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum TcPeditKeyExOption {
    /// Header the offset of the key is relative to.
    HeaderType(TcPeditHeaderType),
    /// Operation applied on the key.
    Cmd(TcPeditCmd),
    /// Other attributes unknown at the time of writing.
    Other(DefaultNla),
}

impl Nla for TcPeditKeyExOption {
    fn value_len(&self) -> usize {
        match self {
            Self::HeaderType(_) | Self::Cmd(_) => 2,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::HeaderType(v) => emit_u16(buffer, (*v).into()).unwrap(),
            Self::Cmd(v) => emit_u16(buffer, (*v).into()).unwrap(),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::HeaderType(_) => TCA_PEDIT_KEY_EX_HTYPE,
            Self::Cmd(_) => TCA_PEDIT_KEY_EX_CMD,
            Self::Other(attr) => attr.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for TcPeditKeyExOption
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            TCA_PEDIT_KEY_EX_HTYPE => Self::HeaderType(
                parse_u16(payload)
                    .context("failed to parse TCA_PEDIT_KEY_EX_HTYPE")?
                    .into(),
            ),
            TCA_PEDIT_KEY_EX_CMD => Self::Cmd(
                parse_u16(payload)
                    .context("failed to parse TCA_PEDIT_KEY_EX_CMD")?
                    .into(),
            ),
            _ => Self::Other(
                DefaultNla::parse(buf)
                    .context("failed to parse pedit key ex option nla")?,
            ),
        })
    }
}

const TCA_PEDIT_KEY_EX_HDR_TYPE_NETWORK: u16 = 0;
const TCA_PEDIT_KEY_EX_HDR_TYPE_ETH: u16 = 1;
const TCA_PEDIT_KEY_EX_HDR_TYPE_IP4: u16 = 2;
const TCA_PEDIT_KEY_EX_HDR_TYPE_IP6: u16 = 3;
const TCA_PEDIT_KEY_EX_HDR_TYPE_TCP: u16 = 4;
const TCA_PEDIT_KEY_EX_HDR_TYPE_UDP: u16 = 5;

/// Header a pedit key offset is relative to.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
#[non_exhaustive]
pub enum TcPeditHeaderType {
    /// The offset is relative to the start of the network header.
    #[default]
    Network,
    /// The offset is relative to the start of the ethernet header.
    Eth,
    /// The offset is relative to the start of the IPv4 header.
    Ip4,
    /// The offset is relative to the start of the IPv6 header.
    Ip6,
    /// The offset is relative to the start of the TCP header.
    Tcp,
    /// The offset is relative to the start of the UDP header.
    Udp,
    /// Other header type unknown at the time of writing.
    Other(u16),
}

impl From<u16> for TcPeditHeaderType {
    fn from(d: u16) -> Self {
        match d {
            TCA_PEDIT_KEY_EX_HDR_TYPE_NETWORK => Self::Network,
            TCA_PEDIT_KEY_EX_HDR_TYPE_ETH => Self::Eth,
            TCA_PEDIT_KEY_EX_HDR_TYPE_IP4 => Self::Ip4,
            TCA_PEDIT_KEY_EX_HDR_TYPE_IP6 => Self::Ip6,
            TCA_PEDIT_KEY_EX_HDR_TYPE_TCP => Self::Tcp,
            TCA_PEDIT_KEY_EX_HDR_TYPE_UDP => Self::Udp,
            _ => Self::Other(d),
        }
    }
}

impl From<TcPeditHeaderType> for u16 {
    fn from(v: TcPeditHeaderType) -> u16 {
        match v {
            TcPeditHeaderType::Network => TCA_PEDIT_KEY_EX_HDR_TYPE_NETWORK,
            TcPeditHeaderType::Eth => TCA_PEDIT_KEY_EX_HDR_TYPE_ETH,
            TcPeditHeaderType::Ip4 => TCA_PEDIT_KEY_EX_HDR_TYPE_IP4,
            TcPeditHeaderType::Ip6 => TCA_PEDIT_KEY_EX_HDR_TYPE_IP6,
            TcPeditHeaderType::Tcp => TCA_PEDIT_KEY_EX_HDR_TYPE_TCP,
            TcPeditHeaderType::Udp => TCA_PEDIT_KEY_EX_HDR_TYPE_UDP,
            TcPeditHeaderType::Other(d) => d,
        }
    }
}

const TCA_PEDIT_KEY_EX_CMD_SET: u16 = 0;
const TCA_PEDIT_KEY_EX_CMD_ADD: u16 = 1;

/// Operation applied on a pedit key.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
#[non_exhaustive]
pub enum TcPeditCmd {
    /// Replace the masked bits with the value of the key.
    #[default]
    Set,
    /// Add the value of the key to the masked bits.
    Add,
    /// Other command unknown at the time of writing.
    Other(u16),
}

impl From<u16> for TcPeditCmd {
    fn from(d: u16) -> Self {
        match d {
            TCA_PEDIT_KEY_EX_CMD_SET => Self::Set,
            TCA_PEDIT_KEY_EX_CMD_ADD => Self::Add,
            _ => Self::Other(d),
        }
    }
}

impl From<TcPeditCmd> for u16 {
    fn from(v: TcPeditCmd) -> u16 {
        match v {
            TcPeditCmd::Set => TCA_PEDIT_KEY_EX_CMD_SET,
            TcPeditCmd::Add => TCA_PEDIT_KEY_EX_CMD_ADD,
            TcPeditCmd::Other(d) => d,
        }
    }
}

/// Parameters for the pedit action.
#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct TcPedit {
    /// Generic action parameters.
    pub generic: TcActionGeneric,
    /// Number of keys carried by this action.
    pub nkeys: u8,
    /// Flags of the pedit action.
    pub flags: u8,
    /// The keys describing the rewrite operations.
    pub keys: Vec<TcPeditKey>,
}

/// Kernel struct `tc_pedit_sel` without its trailing `keys` array.
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(C, packed)]
pub struct TcPeditBuffer {
    generic: TcActionGenericBuffer,
    nkeys: u8,
    flags: u8,
    pad: u16,
}

impl TcPedit {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, key_payload) = TcPeditBuffer::ref_from_prefix(payload)
            .map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<TcPeditBuffer>(),
                )
            })?;
        let (raw_keys, _) = <[TcPeditKeyBuffer]>::ref_from_prefix_with_elems(
            key_payload,
            raw.nkeys.into(),
        )
        .map_err(|_| {
            DecodeError::buffer_too_small(
                payload.len(),
                size_of::<TcPeditBuffer>()
                    + usize::from(raw.nkeys) * size_of::<TcPeditKeyBuffer>(),
            )
        })?;
        Ok(Self {
            generic: TcActionGeneric::parse(
                &payload[..size_of::<TcActionGenericBuffer>()],
            )?,
            nkeys: raw.nkeys,
            flags: raw.flags,
            keys: raw_keys.iter().map(TcPeditKey::from).collect(),
        })
    }
}

impl From<&TcPedit> for TcPeditBuffer {
    fn from(pedit: &TcPedit) -> Self {
        Self {
            generic: TcActionGenericBuffer::from(&pedit.generic),
            nkeys: pedit.nkeys,
            flags: pedit.flags,
            pad: 0,
        }
    }
}

impl Emitable for TcPedit {
    fn buffer_len(&self) -> usize {
        size_of::<TcPeditBuffer>()
            + usize::from(self.nkeys) * size_of::<TcPeditKeyBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let (sel, keys) = buffer.split_at_mut(size_of::<TcPeditBuffer>());
        sel.copy_from_slice(TcPeditBuffer::from(self).as_bytes());
        for (k, chunk) in self
            .keys
            .iter()
            .zip(keys.chunks_exact_mut(size_of::<TcPeditKeyBuffer>()))
        {
            k.emit(chunk);
        }
    }
}

/// A single rewrite operation of the pedit action.
#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct TcPeditKey {
    /// Bits of the selected word which are preserved.
    pub mask: u32,
    /// Value written to the bits not covered by `mask`.
    pub val: u32,
    /// Offset of the word to rewrite, relative to the header type.
    pub off: u32,
    /// Offset of the byte holding the dynamic offset, relative to the
    /// header the rewrite applies to.
    pub at: u32,
    /// Mask applied to the byte read at `at` to compute a dynamic offset.
    pub offmask: u32,
    /// Shift applied to the dynamic offset.
    pub shift: u32,
}

/// Kernel struct `tc_pedit_key`.
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(C, packed)]
pub struct TcPeditKeyBuffer {
    mask: u32,
    val: u32,
    off: u32,
    at: u32,
    offmask: u32,
    shift: u32,
}

impl From<&TcPeditKeyBuffer> for TcPeditKey {
    fn from(raw: &TcPeditKeyBuffer) -> Self {
        Self {
            mask: raw.mask,
            val: raw.val,
            off: raw.off,
            at: raw.at,
            offmask: raw.offmask,
            shift: raw.shift,
        }
    }
}

impl From<&TcPeditKey> for TcPeditKeyBuffer {
    fn from(key: &TcPeditKey) -> Self {
        Self {
            mask: key.mask,
            val: key.val,
            off: key.off,
            at: key.at,
            offmask: key.offmask,
            shift: key.shift,
        }
    }
}

impl Emitable for TcPeditKey {
    fn buffer_len(&self) -> usize {
        size_of::<TcPeditKeyBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(TcPeditKeyBuffer::from(self).as_bytes());
    }
}
