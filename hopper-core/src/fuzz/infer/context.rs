//! Infer context that must not been used
//! e.g API A must not be called before API B.

use eyre::ContextCompat;
use crate::{fuzz::*, fuzzer::*, runtime::*, StatusType, FuzzMutPointer};

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

    pub fn infer_preferred_and_required_contexts(&mut self, program: &FuzzProgram, original_status: StatusType) -> eyre::Result<Vec<ConstraintSig>> {
        let mut new_constraints = vec![];
        crate::log!(debug, "Inferring FuncConstraints.contexts (Preferred / Required contexts)");
        crate::log!(debug, "Program being inferred: {}", program.serialize()?);

        // let calculate_quality = |coverage: &[(usize, BucketType)]| -> u64 {
        //     coverage.iter().map(|(_, bucket)| *bucket as u64).sum()
        // };
        
        // Step 1: Get the coverage feedback of the original program
        // let original_uniq_paths = self.observer.get_new_uniq_path(original_status);
        
        let original_path = self.observer.feedback.path.get_list();
        let original_path_len = original_path.len();
        // let original_bucket_quality = calculate_quality(&original_path);
        
        // let original_cmp_count = self.observer.feedback.instrs.cmp_len();

        // let (original_files, original_mem_bytes) = self.observer.feedback.instrs.count_allocated_resources();
        
        // let original_density = self.observer.branches_state.get_coverage_density();

        // Step 2: Find all call statements (not just implicit/relative)
        let mut call_statements = Vec::new();
        for (idx, stmt) in program.stmts.iter().enumerate() {
            if let FuzzStmt::Call(call) = &stmt.stmt {
                // Don't include the target function itself
                if !call.is_target() {
                    crate::log!(debug, "Found call at index {}: {}", idx, call.fg.f_name);
                    call_statements.push(idx);
                }
            }
        }
        
        crate::log!(debug, "Found {} call statements to analyze", call_statements.len());
        
        // Get the target function name
        let target_call = if let Some(target_call) = program.get_target_stmt() {
            target_call
        } else {
            crate::log!(debug, "No target statement found in program");
            return Ok(new_constraints);
        };
        let target_func_name = target_call.fg.f_name;
        
        // Step 3: Iterate through calls from bottom to top
        for &call_idx in call_statements.iter().rev() {
            // Check if the next statement is an assert that depends on this call
            let has_dependent_assert = if call_idx + 1 < program.stmts.len() {
                if let FuzzStmt::Assert(assert_stmt) = &program.stmts[call_idx + 1].stmt {
                    // Check if this assert statement references our call
                    if let Some(weak_idx) = assert_stmt.get_stmt() {
                        if weak_idx.get() == call_idx {
                            crate::log!(debug, "Found dependent assert at index {} for call at index {}", 
                                call_idx + 1, call_idx);
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            };

            // Create a clone of the program to modify
            let mut modified_program = program.clone();
            
            // Store the function name before potentially modifying the statement
            let removed_func_name = if let FuzzStmt::Call(call) = &program.stmts[call_idx].stmt {
                call.fg.f_name.to_string()
            } else {
                continue;
            };
            
            // Check if statement is referenced by later statements using get_ref_used()
            // A reference count of 1 means only self-reference, > 1 means referenced by others
            let is_referenced = program.stmts[call_idx].index.get_ref_used() > 1;
            crate::log!(debug, "Call at index {} has {} references", 
                call_idx, program.stmts[call_idx].index.get_ref_used());
            
            // Choose approach based on whether the statement is referenced
            if is_referenced {
                // If referenced, replace it with a null pointer instead of removing it
                if let FuzzStmt::Call(call) = &program.stmts[call_idx].stmt {
                    // Get the return type either from ret object or from function signature
                    let return_type = if let Some(ret_obj) = &call.ret {
                        Some(ret_obj.type_name())
                    } else if let Some(ret_type) = call.fg.ret_type {
                        // Function has a return type in its signature
                        Some(ret_type)
                    } else {
                        None
                    };
                    
                    if let Some(return_type) = return_type {
                        // Only handle non-void returns
                        let ident = call.ident.clone();
                        
                        // First, remove the assert if it exists
                        if has_dependent_assert {
                            modified_program.delete_stmt(call_idx + 1);
                        }
                        
                        // Create the null pointer statement
                        let mut state = LoadStmt::new_state(&ident, return_type);
                        let null_ptr = FuzzMutPointer::<()>::null(state.as_mut());
                        let value = Box::new(null_ptr) as FuzzObject;
                        let null_stmt = LoadStmt::new(value, state);
                        
                        // Delete the call statement and insert the null statement at the same position
                        modified_program.delete_stmt(call_idx);
                        let _null_index = modified_program.insert_stmt(call_idx, null_stmt);
                        
                        crate::log!(debug, "Replaced call at index {} with a null pointer of type {}", 
                            call_idx, return_type);
                    } else {
                        // Non-returning call (void), just delete the statements
                        if has_dependent_assert {
                            modified_program.delete_stmt(call_idx + 1);
                        }
                        modified_program.delete_stmt(call_idx);
                    }
                }
            } else {
                // Not referenced, safe to delete
                if has_dependent_assert {
                    modified_program.delete_stmt(call_idx + 1); // Remove the assert first
                    modified_program.delete_stmt(call_idx);     // Then remove the call
                } else {
                    modified_program.delete_stmt(call_idx);
                }
            }
            
            modified_program.eliminate_invalidatd_contexts();
            
            crate::log!(debug, "Testing removal/replacement of call at index {}{} for target function {}", 
                call_idx, 
                if has_dependent_assert { " and its dependent assert" } else { "" }, 
                target_func_name);

            crate::log!(debug, "Modified program: {}", modified_program.serialize()?);
            
            // Execute modified program
            let status = self.executor.execute_program(&modified_program)?;
            crate::log!(debug, "Execution status of modified program: {:?}", status);
            
            // Check if it's a required context (status changed from normal)
            if !status.is_normal() {
                // Get the failure statement index to see which call actually crashed
                let failure_stmt_idx = self.observer.feedback.last_stmt_index();  
                
                // Get the target call statement
                let target_stmt_idx = if let Some(target_stmt_idx) = modified_program.get_target_index() {
                    target_stmt_idx
                } else {
                    crate::log!(debug, "No target statement index found in modified program");
                    continue;
                };

                crate::log!(debug, 
                    "Status changed to {:?} after removing {}, failure at index {} (target at {})", 
                    status, removed_func_name, failure_stmt_idx, target_stmt_idx);
                
                // Only infer required context if the crash occurs at the exact target function
                if failure_stmt_idx == target_stmt_idx {
                    crate::log!(debug, "Crash occurs at target function, inferring required context");
                    
                    // Check if this required context already exists
                    let context_exists = filter_function_constraint_with(target_func_name, |fc| {
                        fc.contexts.iter().any(|ctx| {
                            ctx.f_name == removed_func_name && ctx.kind == ContextKind::Required
                        })
                    });
                    
                    if context_exists {
                        crate::log!(debug, "Required context for {} already exists, skipping", removed_func_name);
                        continue;
                    }
                    
                    let removed_call = match &program.stmts[call_idx].stmt {
                        FuzzStmt::Call(call) => call,
                        _ => continue,
                    };
                    
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
                } else {
                    crate::log!(debug, "Failure doesn't occur at target function (idx {} vs target {}), skipping",
                        failure_stmt_idx, target_stmt_idx);
                }
                continue;
            }
            
            // Check if it's a preferred context (coverage decreased)
            if status.is_normal() {
                // let modified_uniq_paths = self.observer.get_new_uniq_path(status);
                
                let modified_path = self.observer.feedback.path.get_list();
                let modified_path_len = modified_path.len();
                // let modified_bucket_quality = calculate_quality(&modified_path);

                // let modified_cmp_count = self.observer.feedback.instrs.cmp_len();
                
                // let (modified_files, modified_mem_bytes) = self.observer.feedback.instrs.count_allocated_resources();
                // let mem_decreased = original_mem_bytes > 0 && modified_mem_bytes < original_mem_bytes;
                // let files_decreased = original_files > 0 && modified_files < original_files;

                // let modified_density = self.observer.branches_state.get_coverage_density();
    

                if modified_path_len < original_path_len {
                    crate::log!(debug, "Coverage decreased from {} to {} after removing {}, this is a preferred context",
                        original_path_len, modified_path_len, removed_func_name);
                    
                    // Check if this preferred context already exists
                    let context_exists = filter_function_constraint_with(target_func_name, |fc| {
                        fc.contexts.iter().any(|ctx| {
                            ctx.f_name == removed_func_name && ctx.kind == ContextKind::Prefered
                        })
                    });
                    
                    if context_exists {
                        crate::log!(debug, "Preferred context for {} already exists, skipping", removed_func_name);
                        continue;
                    }
                    
                    let removed_call = match &program.stmts[call_idx].stmt {
                        FuzzStmt::Call(call) => call,
                        _ => continue,
                    };
                    
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
            } else {
                crate::log!(debug, "Skipping preferred context check for newly generated program");
            }
        }
        
        Ok(new_constraints)
    }
}
