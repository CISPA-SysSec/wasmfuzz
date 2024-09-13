use crate::{HashMap, HashSet};

use wasmparser::{BinaryReaderError, BlockType, Operator};

use super::InsnIdx;

// cfg analysis
#[derive(Debug, Clone)]
pub(crate) enum StackEntry {
    If(InsnIdx),
    Else {
        if_source: InsnIdx,
        else_source: InsnIdx,
    },
    Block(InsnIdx),
    Loop(InsnIdx),
}

#[allow(unused)] // TODO
pub(crate) struct FuncCFG {
    pub cfg_stack: Vec<StackEntry>,
    pub else_ifs: HashMap<InsnIdx, InsnIdx>,
    pub if_elses: HashMap<InsnIdx, InsnIdx>,
    pub if_ends: HashMap<InsnIdx, InsnIdx>,
    pub else_ends: HashMap<InsnIdx, InsnIdx>,
    pub br_blocks: HashMap<InsnIdx, InsnIdx>,
    pub br_loops: HashMap<InsnIdx, InsnIdx>,
    pub block_ends: HashMap<InsnIdx, InsnIdx>,
    pub loop_ends: HashMap<InsnIdx, InsnIdx>,
    pub br_table_insns: HashMap<InsnIdx, Vec<StackEntry>>,
    pub source_tys: HashMap<InsnIdx, BlockType>,
    pub end_tys: HashMap<InsnIdx, BlockType>,
    pub block_starts: HashSet<InsnIdx>,
    pub bb_starts: Vec<InsnIdx>,
    pub end_idx: InsnIdx,
    pub insn_edges: Vec<(InsnIdx, InsnIdx)>,
    pub insn_call_targets: Vec<(InsnIdx, u32)>,
    pub insn_indirect_call_tables: Vec<(InsnIdx, u32)>,
    pub insn_returns: Vec<InsnIdx>,
    pub insn_unreachable: Vec<InsnIdx>,
    pub block_edges: HashSet<(InsnIdx, InsnIdx)>,
    pub critical_insn_edges: HashSet<(InsnIdx, InsnIdx)>,
}

impl FuncCFG {
    pub fn parse_func(
        body: wasmparser::FunctionBody,
        idx: u32,
        symbol: Option<&str>,
    ) -> Result<Self, BinaryReaderError> {
        let mut cfg_stack = Vec::new();
        let mut else_ifs = HashMap::default();
        let mut if_elses = HashMap::default();
        let mut if_ends = HashMap::default();
        let mut else_ends = HashMap::default();
        let mut br_blocks = HashMap::default();
        let mut br_loops = HashMap::default();
        let mut block_ends = HashMap::default();
        let mut loop_ends = HashMap::default();
        let mut br_table_insns = HashMap::default();
        let mut source_tys = HashMap::default();
        let mut end_tys = HashMap::default();
        let mut block_starts = HashSet::default();
        let mut eof = false;
        let mut end_idx = InsnIdx(0);
        for (ip, op) in body.get_operators_reader()?.into_iter().enumerate() {
            let ip = InsnIdx(ip.try_into().unwrap());
            if eof {
                panic!("cfg analysis borked");
            }
            let op = op?;
            match op {
                Operator::If { blockty } => {
                    cfg_stack.push(StackEntry::If(ip));
                    source_tys.insert(ip, blockty);
                }
                Operator::Loop { blockty } => {
                    cfg_stack.push(StackEntry::Loop(ip));
                    source_tys.insert(ip, blockty);
                    block_starts.insert(ip);
                }
                Operator::Block { blockty } => {
                    cfg_stack.push(StackEntry::Block(ip));
                    source_tys.insert(ip, blockty);
                    block_starts.insert(ip);
                }
                Operator::Br { relative_depth } | Operator::BrIf { relative_depth } => {
                    match cfg_stack[cfg_stack.len() - 1 - relative_depth as usize] {
                        StackEntry::Block(source) => {
                            br_blocks.insert(ip, source);
                        }
                        StackEntry::Loop(source) => {
                            br_loops.insert(ip, source);
                        }
                        _ => unreachable!(),
                    }
                }
                Operator::Else => {
                    match cfg_stack.pop() {
                        Some(StackEntry::If(source)) => {
                            cfg_stack.push(StackEntry::Else {
                                if_source: source,
                                else_source: ip,
                            });
                            if_elses.insert(source, ip);
                            else_ifs.insert(ip, source);
                        }
                        _ => unreachable!(),
                    };
                }
                Operator::End => {
                    if !cfg_stack.is_empty() {
                        block_starts.insert(ip);
                    }
                    match cfg_stack.pop() {
                        Some(StackEntry::If(source)) => {
                            if_ends.insert(source, ip);
                            if let Some(el) = source_tys.remove(&source) {
                                end_tys.insert(ip, el);
                            }
                        }
                        Some(StackEntry::Else {
                            if_source,
                            else_source,
                        }) => {
                            if_ends.insert(if_source, ip);
                            else_ends.insert(else_source, ip);
                            if let Some(el) = source_tys.remove(&if_source) {
                                end_tys.insert(ip, el);
                            }
                        }
                        Some(StackEntry::Block(source)) => {
                            block_ends.insert(source, ip);
                            if let Some(el) = source_tys.remove(&source) {
                                end_tys.insert(ip, el);
                            }
                        }
                        Some(StackEntry::Loop(source)) => {
                            loop_ends.insert(source, ip);
                            if let Some(el) = source_tys.remove(&source) {
                                end_tys.insert(ip, el);
                            }
                        }
                        None => {
                            eof = true;
                            end_idx = ip;
                        }
                    }
                }
                Operator::Return => {}
                Operator::BrTable { targets } => {
                    let mut table = Vec::new();
                    for target in targets.targets() {
                        let depth = target?;
                        table.push(cfg_stack[cfg_stack.len() - depth as usize - 1].clone());
                    }
                    table.push(cfg_stack[cfg_stack.len() - targets.default() as usize - 1].clone());
                    br_table_insns.insert(ip, table);
                }
                _ => {}
            }
        }

        assert!(cfg_stack.is_empty());
        let mut bb_starts = HashSet::default();
        bb_starts.insert(InsnIdx(0));
        for (ip, op) in body.get_operators_reader()?.into_iter().enumerate() {
            let op = op?;
            match op {
                Operator::Block { .. } | Operator::Loop { .. } => {
                    bb_starts.insert(InsnIdx(ip as u32));
                }
                Operator::If { .. } | Operator::BrIf { .. } | Operator::Else => {
                    bb_starts.insert(InsnIdx(ip as u32 + 1));
                }
                Operator::End | Operator::Return => {
                    if ip != end_idx.i() {
                        bb_starts.insert(InsnIdx(ip as u32 + 1));
                    }
                }
                _ => {}
            }
        }

        // determine basic blocks and control flow
        let mut insn_basic_block = Vec::new();
        let mut current_bb = InsnIdx(0);
        for (ip, _op) in body.get_operators_reader()?.into_iter().enumerate() {
            let idx = InsnIdx(ip as u32);
            if bb_starts.contains(&idx) {
                current_bb = idx;
            }
            insn_basic_block.push(current_bb);
        }

        let mut bb_starts: Vec<InsnIdx> = bb_starts.into_iter().collect();
        bb_starts.sort();

        let mut insn_edges: Vec<(InsnIdx, InsnIdx)> = Vec::new();
        let mut insn_call_targets: Vec<(InsnIdx, u32)> = Vec::new();
        let mut insn_indirect_call_tables: Vec<(InsnIdx, u32)> = Vec::new();
        let mut insn_returns: Vec<InsnIdx> = Vec::new();
        let mut insn_unreachable: Vec<InsnIdx> = Vec::new();

        let mut prev_idx = None;
        for (ip, op) in body.get_operators_reader()?.into_iter().enumerate() {
            let idx = InsnIdx(ip as u32);
            let op = op?;
            if let Some(prev_idx) = prev_idx.take() {
                insn_edges.push((prev_idx, idx));
            }
            prev_idx = Some(idx);
            match op {
                Operator::If { .. } => {
                    if let Some(else_idx) = if_elses.get(&idx) {
                        insn_edges.push((idx, *else_idx));
                    }
                    insn_edges.push((idx, if_ends[&idx].inc()));
                }
                Operator::Br { .. } | Operator::BrIf { .. } => {
                    let target = br_blocks
                        .get(&idx)
                        .copied()
                        .map(|block| block_ends[&block].inc())
                        .or_else(|| br_loops.get(&idx).copied())
                        .unwrap();
                    insn_edges.push((idx, target));
                    if matches!(op, Operator::BrIf { .. }) {
                        prev_idx = Some(idx);
                    } else {
                        prev_idx = None;
                    }
                }
                Operator::Else => {
                    let target = if_ends[&else_ifs[&idx]].inc();
                    insn_edges.push((idx, target));
                    prev_idx = None;
                }
                Operator::BrTable { .. } => {
                    let targets = br_table_insns.get(&idx).unwrap();
                    for e in targets {
                        let target = match *e {
                            StackEntry::Block(idx) => block_ends[&idx].inc(),
                            StackEntry::Loop(idx) => idx,
                            _ => unreachable!(),
                        };
                        insn_edges.push((idx, target));
                    }
                    prev_idx = None;
                }
                Operator::Call { function_index } => {
                    insn_call_targets.push((idx, function_index));
                }
                Operator::CallIndirect {
                    type_index: _,
                    table_index,
                } => {
                    insn_indirect_call_tables.push((idx, table_index));
                }
                Operator::Return => {
                    insn_returns.push(idx);
                    prev_idx = None;
                }
                Operator::Unreachable => {
                    insn_unreachable.push(idx);
                    prev_idx = None;
                }
                _ => {}
            }
        }

        let block_edges: HashSet<(InsnIdx, InsnIdx)> = insn_edges
            .iter()
            .flat_map(|(a, b)| {
                let bb_edge = (insn_basic_block[a.i()], insn_basic_block[b.i()]);
                if bb_edge.0 != bb_edge.1 {
                    Some(bb_edge)
                } else if a.0 + 1 != b.0 {
                    assert!(*b == bb_edge.0, "should be back edge to start of bb");
                    Some(bb_edge)
                } else {
                    assert!(a.0 + 1 == b.0);
                    None
                }
            })
            .collect();

        let mut block_in_degree = HashMap::<InsnIdx, usize>::default();
        let mut block_out_degree = HashMap::<InsnIdx, usize>::default();
        for (from, to) in &insn_edges {
            let bb_from = insn_basic_block[from.i()];
            let bb_to = insn_basic_block[to.i()];
            if bb_from == bb_to && from.0 + 1 == to.0 {
                continue; // not an cfg edge
            }
            *block_in_degree.entry(bb_to).or_default() += 1;
            *block_out_degree.entry(bb_from).or_default() += 1;
        }

        // Note: We're not using the canonical definition of _critical edges_, instead we discard
        // edges where the source block has out-degree of one without looking at the target block.
        let critical_insn_edges: HashSet<(InsnIdx, InsnIdx)> = insn_edges
            .iter()
            .copied()
            .filter(|(a, b)| {
                let bb_from = insn_basic_block[a.i()];
                let bb_to = insn_basic_block[b.i()];
                if bb_from == bb_to && a.0 + 1 == b.0 {
                    return false; // not an cfg edge (same basic block, no back loop)
                }
                block_out_degree.get(&bb_from).copied().unwrap_or(0) != 1
                // || block_in_degree.get(&bb_to).copied().unwrap_or(0) != 1
            })
            .collect();

        if std::env::var("DUMP_CFG_DOT").as_deref().unwrap_or("0") == "1" {
            use std::io::Write;
            eprintln!("[DBG] writing /tmp/func_{idx}.dot");
            let mut f = std::fs::File::create(format!("/tmp/func_{idx}.dot")).unwrap();
            writeln!(f, "digraph G {{").unwrap();
            for block in &bb_starts {
                let indeg = block_in_degree.get(block).copied().unwrap_or(0);
                let outdeg = block_out_degree.get(block).copied().unwrap_or(0);
                let label = format!("b{block}\nin:{indeg} out:{outdeg}");
                writeln!(f, "  b{block} [shape=box,label={label:?}];").unwrap();
            }
            // for (from, to) in &block_edges {
            //     writeln!(f, "  b{} -> b{};", from, to).unwrap();
            // }

            for &(from, to) in &insn_edges {
                if critical_insn_edges.contains(&(from, to)) {
                    continue;
                }
                let bb_from = insn_basic_block[from.i()];
                let bb_to = insn_basic_block[to.i()];
                if bb_from == bb_to && from.0 + 1 == to.0 {
                    continue; // not an cfg edge
                }
                let label = format!("i{from} -> i{to}");
                writeln!(f, "  b{bb_from} -> b{bb_to} [label={label:?}];").unwrap();
            }

            writeln!(f, "  edge [color=red];").unwrap();
            for (from, to) in &critical_insn_edges {
                let bb_from = insn_basic_block[from.i()];
                let bb_to = insn_basic_block[to.i()];
                let label = format!("i{from} -> i{to}");
                writeln!(f, "  b{bb_from} -> b{bb_to} [label={label:?}];").unwrap();
            }
            writeln!(f, "}}").unwrap();

            let mut f = std::fs::File::create(format!("/tmp/func_{idx}.txt")).unwrap();
            writeln!(f, "symbol: {symbol:?}").unwrap();

            for (ip, op) in body.get_operators_reader()?.into_iter().enumerate() {
                let op = op?;
                writeln!(f, "{ip:03}: {op:?}").unwrap();
            }
        }

        Ok(Self {
            cfg_stack,
            else_ifs,
            if_elses,
            if_ends,
            else_ends,
            br_blocks,
            br_loops,
            block_ends,
            loop_ends,
            br_table_insns,
            source_tys,
            end_tys,
            block_starts,
            bb_starts,
            end_idx,
            insn_edges,
            insn_call_targets,
            insn_indirect_call_tables,
            insn_returns,
            insn_unreachable,
            block_edges,
            critical_insn_edges,
        })
    }
}
