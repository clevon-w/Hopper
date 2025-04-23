//! Infer context that must not been used
//! e.g API A must not be called before API B.

use eyre::ContextCompat;

use crate::{fuzz::*, fuzzer::*, runtime::*};

impl Fuzzer {
    /// Infer that the crash is due to certain relative/implicit calls
    pub fn infer_broken_contexts(
        &mut self,
        program: &FuzzProgram,
    ) -> eyre::Result<Option<ConstraintSig>> {
        let fail_at = program
            .get_fail_stmt_index()
            .context("fail to get fail index")?
            .get();
        let target_call = if let Some(crash_func) = program.get_call_stmt(fail_at) {
            crash_func
        } else {
            return Ok(None);
        };
        crate::log!(trace, "start infer broken contexts");
        for index in (0..fail_at).rev() {
            let is = &program.stmts[index];
            let FuzzStmt::Call(call) = &is.stmt else {
                continue;
            };
            // we only consider impicit contexts
            if !call.is_implicit() {
                // call.is_relative()
                continue;
            }
            let mut p = program.clone();
            p.delete_stmt(index);
            p.eliminate_invalidatd_contexts();
            crate::log!(
                trace,
                "remove {}, program is: {}",
                is.index.get(),
                p.serialize()?
            );
            let status = self.executor.execute_program(&p)?;
            if !status.is_normal() {
                continue;
            }
            let target_f_name = target_call.fg.f_name;
            let call_f_name = call.fg.f_name;
            let context = CallContext {
                f_name: call_f_name.to_string(),
                related_arg_pos: target_call.has_overlop_arg(program, call),
                kind: ContextKind::Forbidden,
            };
            crate::log!(trace, "function {call_f_name} is likely to broken context");
            if self.observer.op_stat.count_func_infer(call_f_name, program) {
                crate::inspect_function_constraint_mut_with(target_f_name, |fc| {
                    fc.contexts.push(context.clone());
                    log_new_constraint(&format!(
                        "add context on function `{target_f_name}`: {context:?}"
                    ));
                    Ok(())
                })?;
            }
            // just for hints
            let sig = ConstraintSig {
                f_name: target_f_name.to_string(),
                arg_pos: 0,
                fields: LocFields::default(),
                constraint: Constraint::Context { context },
            };
            return Ok(Some(sig));
        }
        Ok(None)
    }

    pub fn infer_preferred_and_required_context(&mut self, program: &FuzzProgram) -> eyre::Result<Vec<ConstraintSig>> {
        let mut new_constraints = vec![];
        crate::log!(trace, "Inferring FuncConstraints.contexts (Preferred / Required contexts)");
        
        // Skip if program has no parent (it's a new seed)
        // TODO: double check that at this point, the parent is filled correctly.
        let Some(parent_id) = program.parent else {
            return Ok(new_constraints);
        };
        
        // Get parent program to compare
        let parent = match self.depot.get_program_by_id(parent_id) {
            Some(p) => p.clone(),
            None => crate::read_input_in_queue(parent_id)?,
        };
        
        // Find new implicit/relative calls that don't exist in parent
        
        // Get the coverage feedback of the original program
        let original_coverage = self.observer.feedback.path.get_list();
        crate::log!(trace, "Original coverage size: {}", original_coverage.len());
        
        // Iterate through new calls from bottom to top
        for call_idx in new_calls.iter().rev() {
            
            // Create modified program without this call
            
            // Execute modified program
            
            // Check if it's a required context (status changed from normal)
            
            // Check if it's a preferred context (coverage decreased)
        }
        
        Ok(new_constraints)
    }
}
