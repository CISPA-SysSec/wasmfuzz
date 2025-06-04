use std::{borrow::Cow, mem::size_of};

use libafl::{
    corpus::Corpus,
    inputs::{BytesInput, HasMutatorBytes},
    mutators::{MutationResult, Mutator},
    observers::{CmpValues, CmpValuesMetadata},
    state::{HasCorpus, HasMaxSize, HasRand},
    Error, HasMetadata,
};
use libafl_bolts::{rands::Rand, AsSlice, HasLen, Named};

/// A `I2SRandReplace` [`Mutator`] replaces a random matching input-2-state comparison operand with the other.
/// It needs a valid [`CmpValuesMetadata`] in the state.
#[derive(Debug, Default)]
pub(crate) struct I2SRandReplace;

impl<I, S> Mutator<I, S> for I2SRandReplace
where
    S: HasCorpus<BytesInput> + HasMetadata + HasRand + HasMaxSize,
    I: HasMutatorBytes,
{
    #[allow(clippy::too_many_lines)]
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
            let meta: &CmpValuesMetadata = match _meta.metadata::<CmpValuesMetadata>().ok() {
                Some(meta) => meta,
                None => return Ok(MutationResult::Skipped),
            };

            if meta.list.is_empty() {
                return Ok(MutationResult::Skipped);
            }
            meta.list.len().try_into().unwrap()
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
        let meta = match _meta.metadata::<CmpValuesMetadata>().ok() {
            Some(meta) => meta,
            None => return Ok(MutationResult::Skipped),
        };

        if meta.list.is_empty() {
            return Ok(MutationResult::Skipped);
        }

        let cmp_values = &meta.list[idx];

        let mut result = MutationResult::Skipped;
        match cmp_values {
            CmpValues::U8(v) => {
                for byte in bytes.iter_mut().take(len).skip(off) {
                    if *byte == v.0 {
                        *byte = v.1;
                        result = MutationResult::Mutated;
                        break;
                    } else if *byte == v.1 {
                        *byte = v.0;
                        result = MutationResult::Mutated;
                        break;
                    }
                }
            }
            CmpValues::U16(v) => {
                if len >= size_of::<u16>() {
                    for i in off..len - (size_of::<u16>() - 1) {
                        let val =
                            u16::from_ne_bytes(bytes[i..i + size_of::<u16>()].try_into().unwrap());
                        if val == v.0 {
                            let new_bytes = v.1.to_ne_bytes();
                            bytes[i..i + size_of::<u16>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val.swap_bytes() == v.0 {
                            let new_bytes = v.1.swap_bytes().to_ne_bytes();
                            bytes[i..i + size_of::<u16>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val == v.1 {
                            let new_bytes = v.0.to_ne_bytes();
                            bytes[i..i + size_of::<u16>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val.swap_bytes() == v.1 {
                            let new_bytes = v.0.swap_bytes().to_ne_bytes();
                            bytes[i..i + size_of::<u16>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        }
                    }
                }
            }
            CmpValues::U32(v) => {
                if len >= size_of::<u32>() {
                    for i in off..len - (size_of::<u32>() - 1) {
                        let val =
                            u32::from_ne_bytes(bytes[i..i + size_of::<u32>()].try_into().unwrap());
                        if val == v.0 {
                            let new_bytes = v.1.to_ne_bytes();
                            bytes[i..i + size_of::<u32>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val.swap_bytes() == v.0 {
                            let new_bytes = v.1.swap_bytes().to_ne_bytes();
                            bytes[i..i + size_of::<u32>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val == v.1 {
                            let new_bytes = v.0.to_ne_bytes();
                            bytes[i..i + size_of::<u32>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val.swap_bytes() == v.1 {
                            let new_bytes = v.0.swap_bytes().to_ne_bytes();
                            bytes[i..i + size_of::<u32>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        }
                    }
                }
            }
            CmpValues::U64(v) => {
                if len >= size_of::<u64>() {
                    for i in off..len - (size_of::<u64>() - 1) {
                        let val =
                            u64::from_ne_bytes(bytes[i..i + size_of::<u64>()].try_into().unwrap());
                        if val == v.0 {
                            let new_bytes = v.1.to_ne_bytes();
                            bytes[i..i + size_of::<u64>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val.swap_bytes() == v.0 {
                            let new_bytes = v.1.swap_bytes().to_ne_bytes();
                            bytes[i..i + size_of::<u64>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val == v.1 {
                            let new_bytes = v.0.to_ne_bytes();
                            bytes[i..i + size_of::<u64>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val.swap_bytes() == v.1 {
                            let new_bytes = v.0.swap_bytes().to_ne_bytes();
                            bytes[i..i + size_of::<u64>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        }
                    }
                }
            }
            CmpValues::Bytes(v) => {
                'outer: for i in off..len {
                    let mut size = core::cmp::min(v.0.len(), len - i);
                    while size != 0 {
                        if v.0.as_slice()[0..size] == input.mutator_bytes()[i..i + size] {
                            input.mutator_bytes_mut()[i..i + size]
                                .copy_from_slice(&v.1.as_slice()[0..size]);
                            result = MutationResult::Mutated;
                            break 'outer;
                        }
                        size -= 1;
                    }
                    size = core::cmp::min(v.1.len(), len - i);
                    while size != 0 {
                        if v.1.as_slice()[0..size] == input.mutator_bytes()[i..i + size] {
                            input.mutator_bytes_mut()[i..i + size]
                                .copy_from_slice(&v.1.as_slice()[0..size]);
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
