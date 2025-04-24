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

    pub fn infer_preferred_and_required_contexts(&mut self, program: &FuzzProgram) -> eyre::Result<Vec<ConstraintSig>> {
        let mut new_constraints = vec![];
        crate::log!(trace, "Inferring FuncConstraints.contexts (Preferred / Required contexts)");
        crate::log!(trace, "Program being inferred: {}", program.serialize()?);
        
        // Skip if program has no parent (it's a new seed)
        // TODO: double check that at this point, the parent is filled correctly.
        let Some(parent_id) = program.parent else {
            return Ok(new_constraints);
        };
        
        // Step 1: Get parent program to compare
        let parent = match self.depot.get_program_by_id(parent_id) {
            Some(p) => p.clone(),
            None => crate::read_input_in_queue(parent_id)?,
        };
        
        // Step 2: Find new implicit/relative calls that don't exist in parent
        let mut new_calls = Vec::new();
        for (idx, stmt) in program.stmts.iter().enumerate() {
            if let FuzzStmt::Call(call) = &stmt.stmt {
                // Check if this is an implicit or relative call
                if call.is_implicit() || call.is_relative() {
                    // See if this call exists in the parent program
                    let is_new = !parent.stmts.iter().any(|parent_stmt| {
                        if let FuzzStmt::Call(parent_call) = &parent_stmt.stmt {
                            // Compare function names and args to determine if calls are equivalent
                            call.fg.f_name == parent_call.fg.f_name
                        } else {
                            false
                        }
                    });
                    
                    if is_new {
                        crate::log!(trace, "Found new implicit/relative call at index {}: {}", 
                            idx, call.fg.f_name);
                        new_calls.push(idx);
                    }
                }
            }
        }
        
        crate::log!(trace, "Found {} new implicit/relative calls", new_calls.len());
        
        // Step 3: Get the coverage feedback of the original program
        let original_coverage = self.observer.feedback.path.get_list();
        crate::log!(trace, "Original coverage size: {}", original_coverage.len());
        
        // Step 4: Iterate through new calls from bottom to top
        for &call_idx in new_calls.iter().rev() {
            // Create modified program without this call
            let mut modified_program = program.clone();
            modified_program.delete_stmt(call_idx);
            modified_program.eliminate_invalidatd_contexts();
            
            // Get the target function name and call being removed
            let target_call = if let Some(target_call) = program.get_target_stmt() {
                target_call
            } else {
                continue;
            };

            let target_func_name = target_call.fg.f_name;
            
            let removed_call = match &program.stmts[call_idx].stmt {
                FuzzStmt::Call(call) => call,
                _ => continue,
            };
            
            let removed_func_name = removed_call.fg.f_name;
            
            crate::log!(trace, "Testing removal of call at index {}: {} for target function {}", 
                call_idx, removed_func_name, target_func_name);
            
            // Execute modified program
            let status = self.executor.execute_program(&modified_program)?;
            
            // Check if it's a required context (status changed from normal)
            if !status.is_normal() {
                // Get the failure statement index to see which call actually crashed
                let failure_stmt_idx = self.observer.feedback.last_stmt_index();  
                
                // Get the target call statement
                let target_stmt_idx = if let Some(target_stmt_idx) = modified_program.get_target_index() {
                    target_stmt_idx
                } else {
                    crate::log!(trace, "No target statement index found in modified program");
                    continue;
                };

                crate::log!(trace, 
                    "Status changed to {:?} after removing {}, failure at index {} (target at {})", 
                    status, removed_func_name, failure_stmt_idx, target_stmt_idx);
                
                // Only infer required context if the crash occurs at the exact target function
                if failure_stmt_idx == target_stmt_idx {
                    crate::log!(trace, "Crash occurs at target function, inferring required context");
                    
                    let context = CallContext {
                        f_name: removed_func_name.to_string(),
                        related_arg_pos: removed_call.has_overlop_arg(program, target_call),
                        kind: ContextKind::Required,
                    };
                    
                    // Add the constraint
                    if self.observer.op_stat.count_func_infer(&removed_func_name, program) {
                        crate::inspect_function_constraint_mut_with(target_func_name, |fc| {
                            fc.contexts.push(context.clone());
                            log_new_constraint(&format!(
                                "add required context on function `{target_func_name}`: {context:?}"
                            ));
                            Ok(())
                        })?;
                        
                        // Add to result for hints
                        new_constraints.push(ConstraintSig {
                            f_name: target_func_name.to_string(),
                            arg_pos: 0,
                            fields: LocFields::default(),
                            constraint: Constraint::Context { context },
                        });
                    }
                }
                continue;
            }
            
            // Check if it's a preferred context (coverage decreased)
            let modified_coverage = self.observer.feedback.path.get_list();
            if modified_coverage.len() < original_coverage.len() {
                crate::log!(trace, "Coverage decreased from {} to {} after removing {}, this is a preferred context",
                    original_coverage.len(), modified_coverage.len(), removed_func_name);
                
                let context = CallContext {
                    f_name: removed_func_name.to_string(),
                    related_arg_pos: removed_call.has_overlop_arg(program, target_call),
                    kind: ContextKind::Prefered,
                };
                
                // Add the constraint
                if self.observer.op_stat.count_func_infer(&removed_func_name, program) {
                    crate::inspect_function_constraint_mut_with(target_func_name, |fc| {
                        fc.contexts.push(context.clone());
                        log_new_constraint(&format!(
                            "add preferred context on function `{target_func_name}`: {context:?}"
                        ));
                        Ok(())
                    })?;
                    
                    // Add to result for hints
                    new_constraints.push(ConstraintSig {
                        f_name: target_func_name.to_string(),
                        arg_pos: 0,
                        fields: LocFields::default(),
                        constraint: Constraint::Context { context },
                    });
                }
            }
        }
        
        Ok(new_constraints)
    }
}
