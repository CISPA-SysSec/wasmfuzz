use std::{borrow::Cow, mem::size_of};

use libafl::{
    Error, HasMetadata,
    corpus::Corpus,
    inputs::{BytesInput, HasMutatorBytes},
    mutators::{MutationResult, Mutator},
    state::{HasCorpus, HasMaxSize, HasRand},
};
use libafl_bolts::{HasLen, Named, rands::Rand};

#[derive(Debug, Clone, Hash, PartialEq, Eq, speedy::Readable, speedy::Writable)]
#[repr(u8)]
pub enum CmpLog {
    U16(u16, u16),
    U32(u32, u32),
    U64(u64, u64),
    Memcmp(Box<[u8]>, Box<[u8]>),
}

#[derive(Debug, Default, Clone, Hash, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SpeedyVec<T> {
    data: Vec<u8>,
    offsets: Vec<u32>,
    _t: std::marker::PhantomData<T>,
}

impl<T: speedy::Writable<speedy::LittleEndian>> SpeedyVec<T> {
    pub fn push(&mut self, value: T) {
        let off: u32 = self.data.len().try_into().unwrap();
        self.offsets.push(off);
        value.write_to_stream(&mut self.data).unwrap();
    }

    pub fn get<'a>(&'a self, idx: usize) -> T
    where
        T: speedy::Readable<'a, speedy::LittleEndian>,
    {
        let pos = self.offsets[idx] as usize;
        T::read_from_buffer(&self.data[pos..]).unwrap()
    }

    // This allows retrieving a &[u8] from a SpeedyVec<Box<[u8]>>
    // Take care to only call with types that serialize the same
    fn get_as_unchecked<'a, O>(&'a self, idx: usize) -> O
    where
        O: speedy::Readable<'a, speedy::LittleEndian>,
    {
        let pos = self.offsets[idx] as usize;
        O::read_from_buffer(&self.data[pos..]).unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.offsets.is_empty()
    }

    pub fn len(&self) -> usize {
        self.offsets.len()
    }
}

#[test]
fn speedy_vec_get_as_unchecked() {
    let mut vec = SpeedyVec::<Box<[u8]>>::default();
    vec.push(b"hello".to_vec().into_boxed_slice());
    vec.push(b"world".to_vec().into_boxed_slice());
    let bytes: &[u8] = vec.get_as_unchecked(0);
    assert_eq!(bytes, b"hello");
    let bytes: &[u8] = vec.get_as_unchecked(1);
    assert_eq!(bytes, b"world");
}

impl CmpLog {
    pub fn test_input(&self, input: &[u8]) -> bool {
        enum V<'a> {
            U16(u16),
            U32(u32),
            U64(u64),
            Bytes(&'a [u8]),
        }
        impl V<'_> {
            fn to_needles(&self) -> Vec<Vec<u8>> {
                match self {
                    V::U16(v) => vec![v.to_le_bytes().to_vec(), v.to_be_bytes().to_vec()],
                    V::U32(v) => vec![v.to_le_bytes().to_vec(), v.to_be_bytes().to_vec()],
                    V::U64(v) => vec![v.to_le_bytes().to_vec(), v.to_be_bytes().to_vec()],
                    V::Bytes(v) => vec![v.to_vec()],
                }
            }
        }
        let mut needles = Vec::new();
        match self {
            CmpLog::U16(a, b) => {
                needles.push(V::U16(*a));
                needles.push(V::U16(*b));
            }
            CmpLog::U32(a, b) => {
                needles.push(V::U32(*a));
                needles.push(V::U32(*b));
            }
            CmpLog::U64(a, b) => {
                needles.push(V::U64(*a));
                needles.push(V::U64(*b));
            }
            CmpLog::Memcmp(a, b) => {
                needles.push(V::Bytes(a));
                needles.push(V::Bytes(b));
            }
        }
        let needles = needles
            .into_iter()
            .flat_map(|x| x.to_needles())
            .collect::<Vec<_>>();
        needles
            .iter()
            .any(|needle| memchr::memmem::find(input, needle).is_some())
    }
}

/// A state metadata holding a list of values logged from comparisons.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct CmplogStore {
    u16s: SpeedyVec<(u16, u16)>,
    u32s: SpeedyVec<(u32, u32)>,
    u64s: SpeedyVec<(u64, u64)>,
    #[expect(clippy::type_complexity)]
    memcmps: SpeedyVec<(Box<[u8]>, Box<[u8]>)>,
}
libafl_bolts::impl_serdeany!(CmplogStore);

impl CmplogStore {
    pub fn new(values: impl Iterator<Item = CmpLog>) -> Self {
        let mut res = Self::default();
        for value in values {
            res.push(value);
        }
        res
    }
    fn push(&mut self, value: CmpLog) {
        match value {
            CmpLog::U16(a, b) => self.u16s.push((a, b)),
            CmpLog::U32(a, b) => self.u32s.push((a, b)),
            CmpLog::U64(a, b) => self.u64s.push((a, b)),
            CmpLog::Memcmp(a, b) => self.memcmps.push((a, b)),
        }
    }
    pub fn get(&self, mut idx: usize) -> CmpLog {
        if idx < self.u16s.len() {
            let (a, b) = self.u16s.get(idx);
            return CmpLog::U16(a, b);
        }
        idx -= self.u16s.len();
        if idx < self.u32s.len() {
            let (a, b) = self.u32s.get(idx);
            return CmpLog::U32(a, b);
        }
        idx -= self.u32s.len();
        if idx < self.u64s.len() {
            let (a, b) = self.u64s.get(idx);
            return CmpLog::U64(a, b);
        }
        idx -= self.u64s.len();
        if idx < self.memcmps.len() {
            let (a, b) = self.memcmps.get(idx);
            return CmpLog::Memcmp(a, b);
        }
        panic!("index out of bounds");
    }
    pub fn is_empty(&self) -> bool {
        self.u16s.is_empty()
            && self.u32s.is_empty()
            && self.u64s.is_empty()
            && self.memcmps.is_empty()
    }
    pub fn len(&self) -> usize {
        self.u16s.len() + self.u32s.len() + self.u64s.len() + self.memcmps.len()
    }
}

impl lod::CmplogSource for CmplogStore {
    fn count(&self, kind: lod::CmpKind) -> usize {
        use lod::CmpKind::*;
        match kind {
            U16 => self.u16s.len(),
            U32 => self.u32s.len(),
            U64 => self.u64s.len(),
            Bytes => self.memcmps.len(),
            U8 | U128 => 0,
        }
    }

    fn with(&self, kind: lod::CmpKind, idx: usize, f: &mut dyn FnMut(lod::CmpPairRef<'_>)) {
        use lod::{CmpKind, CmpPairRef};
        let (bytes_a, bytes_b);
        let cmp_ref = match kind {
            CmpKind::U16 => {
                let (a, b) = self.u16s.get(idx);
                CmpPairRef::U16(a, b)
            }
            CmpKind::U32 => {
                let (a, b) = self.u32s.get(idx);
                CmpPairRef::U32(a, b)
            }
            CmpKind::U64 => {
                let (a, b) = self.u64s.get(idx);
                CmpPairRef::U64(a, b)
            }
            CmpKind::Bytes => {
                (bytes_a, bytes_b) = self.memcmps.get_as_unchecked(idx);
                CmpPairRef::Bytes(bytes_a, bytes_b)
            }
            CmpKind::U8 | CmpKind::U128 => return,
        };
        f(cmp_ref);
    }

    fn is_empty(&self) -> bool {
        CmplogStore::is_empty(self)
    }
}

/// A `I2SRandReplace` [`Mutator`] replaces a random matching input-2-state comparison operand with the other.
/// It needs a valid [`CmpValuesMetadata`] in the state.
#[derive(Debug, Default)]
pub(crate) struct I2SRandReplace;

impl<I, S> Mutator<I, S> for I2SRandReplace
where
    S: HasCorpus<BytesInput> + HasMetadata + HasRand + HasMaxSize,
    I: HasMutatorBytes,
{
    #[expect(clippy::too_many_lines)]
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        if input.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        let size = input.mutator_bytes().len().try_into().unwrap();

        let cmps_len = {
            let &Some(id) = state.corpus().current() else {
                return Ok(MutationResult::Skipped);
            };
            let inp_testcase = state.corpus().get(id).unwrap();
            let _meta = inp_testcase.borrow();
            let meta: &CmplogStore = match _meta.metadata::<CmplogStore>().ok() {
                Some(meta) => meta,
                None => return Ok(MutationResult::Skipped),
            };

            if meta.is_empty() {
                return Ok(MutationResult::Skipped);
            }
            meta.len().try_into().unwrap()
        };
        let idx = state.rand_mut().below(cmps_len);

        let off = state.rand_mut().below(size);
        let len = input.mutator_bytes().len();
        let bytes = input.mutator_bytes_mut();

        let &Some(id) = state.corpus().current() else {
            return Ok(MutationResult::Skipped);
        };
        let inp_testcase = state.corpus().get(id).unwrap();
        let _meta = inp_testcase.borrow();
        let meta = match _meta.metadata::<CmplogStore>().ok() {
            Some(meta) => meta,
            None => return Ok(MutationResult::Skipped),
        };

        let cmp_values = &meta.get(idx);

        let mut result = MutationResult::Skipped;
        match cmp_values {
            &CmpLog::U16(a, b) => {
                if len >= size_of::<u16>() {
                    for i in off..len - (size_of::<u16>() - 1) {
                        let val =
                            u16::from_ne_bytes(bytes[i..i + size_of::<u16>()].try_into().unwrap());
                        if val == a {
                            let new_bytes = b.to_ne_bytes();
                            bytes[i..i + size_of::<u16>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val.swap_bytes() == a {
                            let new_bytes = b.swap_bytes().to_ne_bytes();
                            bytes[i..i + size_of::<u16>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val == b {
                            let new_bytes = a.to_ne_bytes();
                            bytes[i..i + size_of::<u16>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val.swap_bytes() == b {
                            let new_bytes = a.swap_bytes().to_ne_bytes();
                            bytes[i..i + size_of::<u16>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        }
                    }
                }
            }
            &CmpLog::U32(a, b) => {
                if len >= size_of::<u32>() {
                    for i in off..len - (size_of::<u32>() - 1) {
                        let val =
                            u32::from_ne_bytes(bytes[i..i + size_of::<u32>()].try_into().unwrap());
                        if val == a {
                            let new_bytes = b.to_ne_bytes();
                            bytes[i..i + size_of::<u32>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val.swap_bytes() == a {
                            let new_bytes = b.swap_bytes().to_ne_bytes();
                            bytes[i..i + size_of::<u32>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val == b {
                            let new_bytes = a.to_ne_bytes();
                            bytes[i..i + size_of::<u32>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val.swap_bytes() == b {
                            let new_bytes = a.swap_bytes().to_ne_bytes();
                            bytes[i..i + size_of::<u32>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        }
                    }
                }
            }
            &CmpLog::U64(a, b) => {
                if len >= size_of::<u64>() {
                    for i in off..len - (size_of::<u64>() - 1) {
                        let val =
                            u64::from_ne_bytes(bytes[i..i + size_of::<u64>()].try_into().unwrap());
                        if val == a {
                            let new_bytes = b.to_ne_bytes();
                            bytes[i..i + size_of::<u64>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val.swap_bytes() == a {
                            let new_bytes = b.swap_bytes().to_ne_bytes();
                            bytes[i..i + size_of::<u64>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val == b {
                            let new_bytes = a.to_ne_bytes();
                            bytes[i..i + size_of::<u64>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val.swap_bytes() == b {
                            let new_bytes = a.swap_bytes().to_ne_bytes();
                            bytes[i..i + size_of::<u64>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        }
                    }
                }
            }
            CmpLog::Memcmp(a, b) => {
                'outer: for i in off..len {
                    let mut size = core::cmp::min(a.len(), len - i);
                    while size != 0 {
                        if a[0..size] == input.mutator_bytes()[i..i + size] {
                            input.mutator_bytes_mut()[i..i + size].copy_from_slice(&b[0..size]);
                            result = MutationResult::Mutated;
                            break 'outer;
                        }
                        size -= 1;
                    }
                    size = core::cmp::min(b.len(), len - i);
                    while size != 0 {
                        if b[0..size] == input.mutator_bytes()[i..i + size] {
                            input.mutator_bytes_mut()[i..i + size].copy_from_slice(&b[0..size]);
                            result = MutationResult::Mutated;
                            break 'outer;
                        }
                        size -= 1;
                    }
                }
            }
        }

        Ok(result)
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _new_corpus_id: Option<libafl::corpus::CorpusId>,
    ) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for I2SRandReplace {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("I2SRandReplace")
    }
}
