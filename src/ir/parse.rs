use crate::{HashMap, HashSet};
use bitvec::prelude::*;
use std::fmt;

use wasmparser::{
    BinaryReaderError, CompositeInnerType, KnownCustom, Naming, Operator, Parser, Payload, ValType,
};

use super::parse_cfg::{FuncCFG, StackEntry};
use super::{InsnIdx, Value};
use crate::ir::heuristics::recognize_libfunc;

use super::heuristics::Libfunc;
use super::operators::{op_to_const, translate_operator};
use super::ControlInstruction;
use super::WFOperator;

pub(crate) struct FuncSpec {
    pub locals: Vec<wasmparser::ValType>,
    pub operators: Vec<WFOperator>,
    pub basic_block_starts: Vec<InsnIdx>,
    pub operator_basic_block: Vec<InsnIdx>,
    pub critical_insn_edges: HashSet<(InsnIdx, InsnIdx)>,
    pub is_bb_start: BitVec,
    pub ty: wasmparser::FuncType,
    pub idx: u32,
    #[allow(unused)]
    pub idx_in_code_section: u32,
    pub symbol: String,
    pub _symbol: Option<String>,
    pub is_stub: bool,
    pub known_libfunc: Option<Libfunc>,
    // map WFOperators to wasm source file byte locations
    pub operators_wasm_bin_offset_base: usize,
    pub operator_offset_rel: Vec<u32>,
}

pub(crate) struct ModuleSpec {
    pub filename: String,
    pub wasm_binary: Vec<u8>,
    types: Vec<wasmparser::FuncType>,
    func_tyidxs: Vec<u32>,
    pub exported_funcs: HashMap<String, u32>,
    pub functions: Vec<FuncSpec>,
    pub memory_initializers: Vec<(Vec<u8>, usize)>,
    pub scuffed_func_table_initializers: Vec<(Vec<u32>, usize)>,
    pub globals: Vec<Value>,
    pub initial_mem_pages: usize,
    pub start_func: Option<u32>,
}

impl fmt::Debug for ModuleSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ModuleSpec")
            .field("filename", &self.filename)
            .finish_non_exhaustive()
    }
}

impl ModuleSpec {
    fn parse_types(module_binary: &[u8]) -> Result<Vec<wasmparser::FuncType>, BinaryReaderError> {
        Parser::new(0)
            .parse_all(module_binary)
            .try_fold(Vec::new(), |mut acc, el| {
                if let Payload::TypeSection(types) = el? {
                    for rec_group in types {
                        for type_ in rec_group?.types() {
                            match &type_.composite_type.inner {
                                CompositeInnerType::Func(func_ty) => acc.push(func_ty.clone()),
                                _ => unimplemented!(),
                            }
                        }
                    }
                };
                Ok(acc)
            })
    }

    fn parse_func_tyidxs(module_binary: &[u8]) -> Result<Vec<u32>, BinaryReaderError> {
        Parser::new(0)
            .parse_all(module_binary)
            .try_fold(Vec::new(), |mut acc, el| {
                if let Payload::FunctionSection(functions) = el? {
                    for function in functions {
                        acc.push(function?);
                    }
                }
                Ok(acc)
            })
    }

    fn parse_func_names(module_binary: &[u8]) -> Result<HashMap<u32, String>, BinaryReaderError> {
        Parser::new(0)
            .parse_all(module_binary)
            .try_fold(HashMap::default(), |mut acc, el| {
                if let Payload::CustomSection(reader) = el? {
                    let KnownCustom::Name(result) = reader.as_known() else {
                        return Ok(acc);
                    };
                    for el in result.into_iter().flatten() {
                        if let wasmparser::Name::Function(names) = el {
                            for name in names.into_iter() {
                                let Naming { index, name } = name.unwrap();
                                let name = rustc_demangle::demangle(name).to_string();
                                assert!(!acc.contains_key(&index));
                                acc.insert(index, name);
                            }
                        }
                    }
                }
                Ok(acc)
            })
    }

    fn parse_import_names(module_binary: &[u8]) -> Result<Vec<String>, BinaryReaderError> {
        Parser::new(0)
            .parse_all(module_binary)
            .try_fold(Vec::new(), |mut acc, el| {
                if let Payload::ImportSection(imports) = el? {
                    for import in imports {
                        let import = import?;
                        let name = format!("{}::{}", import.module, import.name);
                        acc.push(name);
                    }
                }
                Ok(acc)
            })
    }

    fn parse_import_tyidxs(module_binary: &[u8]) -> Result<Vec<u32>, BinaryReaderError> {
        Parser::new(0)
            .parse_all(module_binary)
            .try_fold(Vec::new(), |mut acc, el| {
                if let Payload::ImportSection(imports) = el? {
                    for import in imports {
                        let import = import?;
                        if let wasmparser::TypeRef::Func(tyidx) = import.ty {
                            acc.push(tyidx);
                        } else {
                            unimplemented!()
                        }
                    }
                }
                Ok(acc)
            })
    }

    fn parse_func(
        spec: &Self,
        idx_in_code_section: u32,
        func_names: &HashMap<u32, String>,
        body: wasmparser::FunctionBody,
    ) -> Result<FuncSpec, BinaryReaderError> {
        let idx = spec.functions.len() as u32;
        let cfg = FuncCFG::parse_func(body.clone(), idx, func_names.get(&idx).map(|x| x.as_str()))?;
        let mut func = FuncSpec {
            locals: Vec::new(),
            operators: Vec::new(),
            ty: spec.types[spec.func_tyidxs[idx as usize] as usize].clone(),
            idx,
            idx_in_code_section,
            symbol: func_names
                .get(&idx)
                .map(|name| format!("_{idx:>03}_{name}"))
                .unwrap_or_else(|| format!("_{idx:>03}")),
            _symbol: func_names.get(&idx).cloned(),
            is_stub: false,
            known_libfunc: None,
            basic_block_starts: cfg.bb_starts,
            operator_basic_block: Vec::new(),
            is_bb_start: BitVec::new(),
            critical_insn_edges: cfg.critical_insn_edges,
            operators_wasm_bin_offset_base: body
                .get_operators_reader()
                .unwrap()
                .original_position()
                .saturating_sub(3), // this matches up with debug info
            operator_offset_rel: Vec::new(),
        };
        for elem in body.get_locals_reader()? {
            let (count, ty) = elem?;
            for _ in 0..count {
                func.locals.push(ty);
            }
        }

        /*
        let end_ip = func
            .basic_block_starts
            .pop()
            .expect("remove function termiator bb");
        if end_ip.0 == 1 {
            func.basic_block_starts.remove(0);
            assert!(func.basic_block_starts.is_empty());
        }
        */
        let block_ty = |block_ty: &wasmparser::BlockType| match block_ty {
            wasmparser::BlockType::FuncType(idx) => {
                spec.types[spec.func_tyidxs[*idx as usize] as usize].clone()
            }
            wasmparser::BlockType::Empty => wasmparser::FuncType::new([], []),
            wasmparser::BlockType::Type(ty) => wasmparser::FuncType::new(
                [],
                match ty {
                    ValType::I32 | ValType::I64 | ValType::F32 | ValType::F64 => [*ty],
                    _ => unreachable!(),
                },
            ),
        };
        let mut current_bb = InsnIdx(0);
        for (ip, el) in body
            .get_operators_reader()?
            .into_iter_with_offsets()
            .enumerate()
        {
            let ip = InsnIdx(ip as u32);
            let (op, src_byte_pos) = el?;
            // eprintln!("{} | {:?}", func.symbol, op);
            let wfop = match op {
                Operator::If { blockty } => WFOperator::Control(ControlInstruction::If {
                    ty: block_ty(&blockty),
                    else_operator_index: cfg.if_elses.get(&ip).cloned(),
                    end_operator_index: cfg.if_ends[&ip],
                }),
                Operator::Br { .. } | Operator::BrIf { .. } => {
                    let cfg_target = cfg
                        .br_blocks
                        .get(&ip)
                        .map(|block| cfg.block_ends[block].inc())
                        .or_else(|| cfg.br_loops.get(&ip).copied())
                        .unwrap();
                    let target_params = cfg
                        .end_tys
                        .get(&cfg_target)
                        .map(|ty| {
                            wasmparser::FuncType::new(block_ty(ty).results().iter().cloned(), [])
                        })
                        .unwrap_or_else(|| wasmparser::FuncType::new([], []));
                    match op {
                        Operator::Br { relative_depth: _ } => {
                            WFOperator::Control(ControlInstruction::Br {
                                cfg_target,
                                target_params,
                                // relative_depth,
                            })
                        }
                        Operator::BrIf { relative_depth: _ } => {
                            WFOperator::Control(ControlInstruction::BrIf {
                                cfg_target,
                                target_params,
                                // relative_depth,
                            })
                        }
                        _ => unreachable!(),
                    }
                }
                Operator::BrTable { .. } => {
                    let targets = cfg.br_table_insns.get(&ip).unwrap();
                    let mut targets = targets
                        .iter()
                        .map(|e| match *e {
                            StackEntry::Block(idx) => cfg.block_ends[&idx].inc(),
                            StackEntry::Loop(idx) => idx,
                            _ => unreachable!(),
                        })
                        .collect::<Vec<_>>();
                    let default = targets.pop().unwrap();
                    WFOperator::Control(ControlInstruction::BrTable { targets, default })
                }
                Operator::Loop { blockty } => WFOperator::Control(ControlInstruction::Loop {
                    ty: block_ty(&blockty),
                }),
                Operator::Block { blockty } => WFOperator::Control(ControlInstruction::Block {
                    ty: block_ty(&blockty),
                }),
                Operator::Return => WFOperator::Control(ControlInstruction::Return),
                Operator::End => {
                    if ip == cfg.end_idx {
                        continue;
                    }
                    let block_ty = block_ty(&cfg.end_tys[&ip]);
                    let starts_new_block = !cfg.block_starts.contains(&ip.inc());
                    WFOperator::Control(ControlInstruction::End {
                        block_ty,
                        starts_new_block,
                    })
                }
                Operator::Nop => WFOperator::Control(ControlInstruction::Nop),
                Operator::Unreachable => WFOperator::Control(ControlInstruction::Unreachable),
                Operator::Else => WFOperator::Control(ControlInstruction::Else {
                    if_operator_index: cfg.else_ifs[&ip],
                    end_operator_index: cfg.if_ends[&cfg.else_ifs[&ip]],
                    target_params: cfg
                        .end_tys
                        .get(&cfg.if_ends[&cfg.else_ifs[&ip]])
                        .map(|ty| {
                            wasmparser::FuncType::new(block_ty(ty).results().iter().cloned(), [])
                        })
                        .unwrap_or_else(|| wasmparser::FuncType::new([], [])),
                }),
                Operator::Call { function_index } => {
                    let ty_index = spec.func_tyidxs[function_index as usize];
                    let function_ty = spec.types[ty_index as usize].clone();
                    WFOperator::Control(ControlInstruction::Call {
                        function_index,
                        function_ty,
                    })
                }
                Operator::CallIndirect {
                    type_index,
                    table_index,
                } => {
                    let function_ty = spec.types[type_index as usize].clone();
                    WFOperator::Control(ControlInstruction::CallIndirect {
                        function_ty,
                        table_index,
                    })
                }
                _ => translate_operator(op),
            };

            func.operators.push(wfop);
            func.operator_offset_rel.push(
                (src_byte_pos - func.operators_wasm_bin_offset_base)
                    .try_into()
                    .unwrap(),
            );
            func.is_bb_start.push(func.basic_block_starts.contains(&ip));
            if func.is_bb_start[ip.i()] {
                current_bb = ip;
            }
            func.operator_basic_block.push(current_bb);
        }
        func.known_libfunc = recognize_libfunc(&func);
        Ok(func)
    }

    pub(crate) fn parse(filename: &str, module_binary: &[u8]) -> Result<Self, BinaryReaderError> {
        tracyrs::zone!("ModuleSpec::parse");
        let func_names = Self::parse_func_names(module_binary)?;

        let mut func_tyidxs = Self::parse_import_tyidxs(module_binary)?;
        func_tyidxs.extend(Self::parse_func_tyidxs(module_binary)?);

        let types = Self::parse_types(module_binary)?;

        let import_funcs = Self::parse_import_names(module_binary)?
            .into_iter()
            .zip(Self::parse_import_tyidxs(module_binary)?)
            .enumerate()
            .map(|(idx, (name, tyidx))| {
                make_import_stub(idx as u32, name, types[tyidx as usize].clone())
            })
            .collect::<Vec<_>>();

        let mut spec = Self {
            filename: filename.into(),
            wasm_binary: module_binary.to_vec(),
            types,
            func_tyidxs,
            exported_funcs: HashMap::default(),
            functions: import_funcs, // will be extended later
            initial_mem_pages: 0,
            memory_initializers: Vec::new(),
            scuffed_func_table_initializers: Vec::new(),
            globals: Vec::new(),
            start_func: None,
        };

        let mut idx_in_code_section = 0;
        for payload in Parser::new(0).parse_all(module_binary) {
            match payload? {
                Payload::Version { .. } => {}
                Payload::End(_) => {}
                Payload::TypeSection(_) | Payload::FunctionSection(_) => { /* handled in scan 1 */ }
                Payload::CodeSectionStart { .. } => {}
                Payload::CodeSectionEntry(body) => {
                    let func = Self::parse_func(&spec, idx_in_code_section, &func_names, body)?;
                    spec.functions.push(func);
                    idx_in_code_section += 1;
                }
                Payload::CustomSection { .. } => {}
                Payload::DataCountSection { .. } => {}
                Payload::DataSection(datas) => {
                    for data in datas {
                        let data = data?;
                        match data.kind {
                            wasmparser::DataKind::Active {
                                memory_index,
                                offset_expr,
                            } => {
                                assert_eq!(memory_index, 0);
                                let mut ops = offset_expr.get_operators_reader();
                                let expr = ops.read()?;
                                assert!(matches!(ops.read()?, Operator::End));
                                let offset = op_to_const(expr);
                                spec.memory_initializers
                                    .push((data.data.to_vec(), offset.as_i32() as usize));
                            }
                            wasmparser::DataKind::Passive => panic!(),
                        }
                    }
                }
                Payload::ElementSection(_elements) => {
                    for el in _elements {
                        let el = el?;
                        match el.kind {
                            wasmparser::ElementKind::Active {
                                table_index,
                                offset_expr,
                            } => {
                                assert_eq!(table_index, None);
                                let mut r = offset_expr.get_operators_reader();
                                let val = op_to_const(r.read()?);
                                assert!(matches!(r.read()?, wasmparser::Operator::End));
                                let offset = val.as_i32();
                                spec.scuffed_func_table_initializers
                                    .push((Vec::new(), offset as usize));
                            }
                            wasmparser::ElementKind::Declared => {}
                            wasmparser::ElementKind::Passive => {}
                        }
                        match el.items {
                            wasmparser::ElementItems::Functions(reader) => {
                                for func_index in reader.into_iter() {
                                    spec.scuffed_func_table_initializers[0]
                                        .0
                                        .push(func_index.unwrap());
                                }
                            }
                            wasmparser::ElementItems::Expressions(..) => unimplemented!(),
                        }
                    }
                    // for funcref tables? not implemented
                }
                Payload::ExportSection(exports) => {
                    for export in exports {
                        let export = export?;
                        if export.kind == wasmparser::ExternalKind::Func {
                            spec.exported_funcs
                                .insert(export.name.to_owned(), export.index);
                        }
                    }
                }
                Payload::GlobalSection(globals) => {
                    for global in globals {
                        let global = global?;
                        let mut r = global.init_expr.get_operators_reader();
                        let val = op_to_const(r.read()?);
                        assert!(matches!(r.read()?, wasmparser::Operator::End));
                        spec.globals.push(val);
                    }
                }
                Payload::ImportSection(_) => {}
                Payload::TableSection(tables) => {
                    for table in tables {
                        let _table = table?;
                    }
                }
                Payload::MemorySection(memories) => {
                    for memory in memories {
                        spec.initial_mem_pages = memory?.initial as usize;
                    }
                }
                Payload::StartSection { func, .. } => {
                    spec.start_func = Some(func);
                }
                payload => {
                    unimplemented!("{:?}", payload);
                }
            }
        }
        Ok(spec)
    }

    pub(crate) fn format_location(&self, loc: crate::ir::Location) -> String {
        format!(
            "{}+{}",
            self.functions[loc.function as usize].symbol, loc.index
        )
    }
}

pub(crate) fn make_import_stub(idx: u32, name: String, ty: wasmparser::FuncType) -> FuncSpec {
    use crate::ir::VariableInstruction;
    use WFOperator as WFOp;
    // stub for arbitrary imports, replace ::Builtin call later for stubbed ones
    let mut ops = Vec::new();
    for idx in 0..ty.params().len() as u32 {
        ops.push(WFOp::Variable(VariableInstruction::LocalGet(idx)));
    }
    ops.push(WFOp::Builtin {
        name: name.clone(),
        ty: ty.clone(),
    });

    let mut fspec = FuncSpec {
        _symbol: Some(name.clone()),
        symbol: format!("_{idx}_{name}"),
        locals: Vec::new(),
        ty,
        idx,
        idx_in_code_section: u32::MAX,
        is_stub: true,
        known_libfunc: None,
        basic_block_starts: vec![InsnIdx(0)],
        operator_basic_block: Vec::new(),
        is_bb_start: BitVec::new(),
        critical_insn_edges: HashSet::default(),
        operators_wasm_bin_offset_base: 0,
        operator_offset_rel: vec![0; ops.len()],
        operators: ops,
    };
    fspec.operator_basic_block = vec![InsnIdx(0); fspec.operators.len()];
    fspec.is_bb_start = BitVec::repeat(false, fspec.operators.len());
    fspec.is_bb_start.set(0, true);
    fspec
}
