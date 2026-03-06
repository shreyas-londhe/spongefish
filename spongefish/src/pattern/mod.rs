mod interaction;
mod player;

mod checked_prover;
mod checked_verifier;

pub use checked_prover::CheckedProverState;
pub use checked_verifier::CheckedVerifierState;
pub use interaction::{Interaction, InteractionKind, InteractionPattern, PatternBuilder};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_pattern() {
        let pattern = PatternBuilder::new().finalize();
        assert!(pattern.is_empty());
        assert_eq!(pattern.len(), 0);

        let domsep = domain_separator!("empty pattern"; "test").instance(&0u32);
        let prover = CheckedProverState::new(domsep.std_prover(), pattern.clone());
        let inner = prover.check_complete();
        let narg = inner.narg_string().to_vec();

        let verifier = CheckedVerifierState::new(domsep.std_verifier(&narg), pattern);
        assert!(verifier.check_eof().is_ok());
    }

    #[test]
    fn round_trip() {
        let pattern = {
            let mut b = PatternBuilder::new();
            b.public_message::<u32>("instance");
            b.prover_message::<u32>("commitment");
            b.verifier_message::<u32>("challenge");
            b.prover_message::<u32>("response");
            b.finalize()
        };

        let domsep = domain_separator!("pattern round trip"; "test").instance(&0u32);

        let mut prover = CheckedProverState::new(domsep.std_prover(), pattern.clone());
        prover.public_message(&42u32);
        prover.prover_message(&100u32);
        let _challenge: u32 = prover.verifier_message();
        prover.prover_message(&200u32);
        let inner = prover.check_complete();
        let narg = inner.narg_string().to_vec();

        let mut verifier = CheckedVerifierState::new(domsep.std_verifier(&narg), pattern);
        verifier.public_message(&42u32);
        let commitment: u32 = verifier.prover_message().unwrap();
        assert_eq!(commitment, 100);
        let _challenge: u32 = verifier.verifier_message();
        let response: u32 = verifier.prover_message().unwrap();
        assert_eq!(response, 200);
        assert!(verifier.check_eof().is_ok());
    }

    #[test]
    #[should_panic(expected = "pattern violation")]
    fn wrong_kind() {
        let pattern = {
            let mut b = PatternBuilder::new();
            b.prover_message::<u32>("commitment");
            b.finalize()
        };

        let domsep = domain_separator!("wrong kind"; "test").instance(&0u32);
        let mut prover = CheckedProverState::new(domsep.std_prover(), pattern);
        // Should be prover_message, calling verifier_message instead
        let _: u32 = prover.verifier_message();
    }

    #[test]
    #[should_panic(expected = "pattern violation")]
    fn wrong_type() {
        let pattern = {
            let mut b = PatternBuilder::new();
            b.prover_message::<u32>("commitment");
            b.finalize()
        };

        let domsep = domain_separator!("wrong type"; "test").instance(&0u32);
        let mut prover = CheckedProverState::new(domsep.std_prover(), pattern);
        // Pattern expects u32, but we send u64
        prover.prover_message(&0u64);
    }

    #[test]
    #[should_panic(expected = "pattern violation")]
    fn wrong_count() {
        let pattern = {
            let mut b = PatternBuilder::new();
            b.prover_messages::<u32>(3, "commitments");
            b.finalize()
        };

        let domsep = domain_separator!("wrong count"; "test").instance(&0u32);
        let mut prover = CheckedProverState::new(domsep.std_prover(), pattern);
        // Pattern expects 3, but we send 2
        prover.prover_messages(&[1u32, 2u32]);
    }

    #[test]
    #[should_panic(expected = "pattern violation")]
    fn extra_step() {
        let pattern = {
            let mut b = PatternBuilder::new();
            b.prover_message::<u32>("only step");
            b.finalize()
        };

        let domsep = domain_separator!("extra step"; "test").instance(&0u32);
        let mut prover = CheckedProverState::new(domsep.std_prover(), pattern);
        prover.prover_message(&1u32);
        // This second call exceeds the pattern
        prover.prover_message(&2u32);
    }

    #[test]
    #[should_panic(expected = "pattern violation")]
    fn incomplete() {
        let pattern = {
            let mut b = PatternBuilder::new();
            b.prover_message::<u32>("step 1");
            b.prover_message::<u32>("step 2");
            b.prover_message::<u32>("step 3");
            b.finalize()
        };

        let domsep = domain_separator!("incomplete"; "test").instance(&0u32);
        let mut prover = CheckedProverState::new(domsep.std_prover(), pattern);
        prover.prover_message(&1u32);
        prover.prover_message(&2u32);
        // Only 2 of 3 steps done, check_complete should panic
        prover.check_complete();
    }

    #[test]
    fn plural_methods() {
        let pattern = {
            let mut b = PatternBuilder::new();
            b.prover_messages::<u32>(3, "prover batch");
            b.verifier_messages::<u32>(2, "verifier batch");
            b.public_messages::<u32>(2, "public batch");
            b.finalize()
        };

        let domsep = domain_separator!("plural methods"; "test").instance(&0u32);

        let mut prover = CheckedProverState::new(domsep.std_prover(), pattern.clone());
        prover.prover_messages(&[1u32, 2u32, 3u32]);
        let _: [u32; 2] = prover.verifier_messages();
        prover.public_messages(&[10u32, 20u32]);
        let inner = prover.check_complete();
        let narg = inner.narg_string().to_vec();

        // Same pattern for verifier — now possible since CheckedVerifierState
        // has verifier_messages() matching the prover's batch method.
        let mut verifier = CheckedVerifierState::new(domsep.std_verifier(&narg), pattern);
        let msgs: [u32; 3] = verifier.prover_messages().unwrap();
        assert_eq!(msgs, [1, 2, 3]);
        let _: [u32; 2] = verifier.verifier_messages();
        verifier.public_messages(&[10u32, 20u32]);
        assert!(verifier.check_eof().is_ok());
    }

    #[test]
    fn verifier_messages_vec() {
        let pattern = {
            let mut b = PatternBuilder::new();
            b.prover_messages::<u32>(2, "proofs");
            b.verifier_messages::<u32>(3, "challenges");
            b.finalize()
        };

        let domsep = domain_separator!("verifier_messages_vec"; "test").instance(&0u32);

        let mut prover = CheckedProverState::new(domsep.std_prover(), pattern.clone());
        prover.prover_messages(&[1u32, 2u32]);
        let challenges: alloc::vec::Vec<u32> = prover.verifier_messages_vec(3);
        assert_eq!(challenges.len(), 3);
        let inner = prover.check_complete();
        let narg = inner.narg_string().to_vec();

        let mut verifier = CheckedVerifierState::new(domsep.std_verifier(&narg), pattern);
        let msgs = verifier.prover_messages_vec::<u32>(2).unwrap();
        assert_eq!(msgs, [1, 2]);
    }

    #[cfg(feature = "sha3")]
    #[test]
    fn pattern_hash_determinism() {
        let build = || {
            let mut b = PatternBuilder::new();
            b.prover_message::<u32>("commitment");
            b.verifier_message::<u32>("challenge");
            b.finalize()
        };

        let p1 = build();
        let p2 = build();
        assert_eq!(p1.pattern_hash(), p2.pattern_hash());

        // Different pattern should give different hash
        let p3 = {
            let mut b = PatternBuilder::new();
            b.prover_message::<u64>("commitment");
            b.verifier_message::<u32>("challenge");
            b.finalize()
        };
        assert_ne!(p1.pattern_hash(), p3.pattern_hash());
    }

    #[test]
    fn domain_separator_checked_prover() {
        let pattern = {
            let mut b = PatternBuilder::new();
            b.prover_message::<u32>("msg");
            b.finalize()
        };

        let domsep = domain_separator!("domsep integration"; "test").instance(&0u32);
        let mut prover = domsep.checked_prover(&pattern);
        prover.prover_message(&42u32);
        let inner = prover.check_complete();
        let narg = inner.narg_string().to_vec();

        let mut verifier = domsep.checked_verifier(&pattern, &narg);
        let val: u32 = verifier.prover_message().unwrap();
        assert_eq!(val, 42);
        assert!(verifier.check_eof().is_ok());
    }

    #[test]
    fn rng_passthrough() {
        use rand::RngCore;

        let pattern = {
            let mut b = PatternBuilder::new();
            b.prover_message::<u32>("msg");
            b.finalize()
        };

        let domsep = domain_separator!("rng passthrough"; "test").instance(&0u32);
        let mut prover = CheckedProverState::new(domsep.std_prover(), pattern);
        // RNG should work without affecting pattern tracking
        let _val = prover.rng().next_u64();
        prover.prover_message(&1u32);
        let _ = prover.check_complete();
    }

    // --- Composition tests ---

    #[test]
    fn scope_closure_sets_scope() {
        let pattern = {
            let mut b = PatternBuilder::new();
            b.prover_message::<u32>("top-level");
            b.scope("inner", |b| {
                b.prover_message::<u32>("nested");
            });
            b.finalize()
        };

        let steps = pattern.steps();
        assert_eq!(steps[0].scope, "");
        assert_eq!(steps[0].label, "top-level");
        assert_eq!(steps[1].scope, "inner");
        assert_eq!(steps[1].label, "nested");
    }

    #[test]
    fn nested_scopes() {
        let pattern = {
            let mut b = PatternBuilder::new();
            b.scope("outer", |b| {
                b.prover_message::<u32>("a");
                b.scope("middle", |b| {
                    b.scope("inner", |b| {
                        b.verifier_message::<u32>("deep");
                    });
                });
            });
            b.finalize()
        };

        assert_eq!(pattern.steps()[0].scope, "outer");
        assert_eq!(pattern.steps()[1].scope, "outer::middle::inner");
    }

    #[test]
    fn begin_end_scope() {
        let pattern = {
            let mut b = PatternBuilder::new();
            b.begin_scope("round_0");
            b.prover_message::<u32>("L");
            b.prover_message::<u32>("R");
            b.end_scope();
            b.begin_scope("round_1");
            b.prover_message::<u32>("L");
            b.end_scope();
            b.finalize()
        };

        assert_eq!(pattern.steps()[0].scope, "round_0");
        assert_eq!(pattern.steps()[1].scope, "round_0");
        assert_eq!(pattern.steps()[2].scope, "round_1");
    }

    #[test]
    #[should_panic(expected = "unclosed scope")]
    fn finalize_panics_on_unclosed_scope() {
        let mut b = PatternBuilder::new();
        b.begin_scope("oops");
        b.prover_message::<u32>("x");
        let _ = b.finalize();
    }

    #[test]
    #[should_panic(expected = "no open scope")]
    fn end_scope_panics_when_empty() {
        let mut b = PatternBuilder::new();
        b.end_scope();
    }

    #[test]
    fn extend_inlines_sub_pattern() {
        let sub = {
            let mut b = PatternBuilder::new();
            b.prover_message::<u32>("commitment");
            b.verifier_message::<u32>("challenge");
            b.prover_message::<u32>("response");
            b.finalize()
        };

        let pattern = {
            let mut b = PatternBuilder::new();
            b.public_message::<u32>("instance");
            b.extend("sigma", &sub);
            b.finalize()
        };

        assert_eq!(pattern.len(), 4);
        assert_eq!(pattern.steps()[0].scope, "");
        assert_eq!(pattern.steps()[1].scope, "sigma");
        assert_eq!(pattern.steps()[1].label, "commitment");
        assert_eq!(pattern.steps()[2].scope, "sigma");
        assert_eq!(pattern.steps()[3].scope, "sigma");
    }

    #[test]
    fn extend_reuse_sub_pattern() {
        let sub = {
            let mut b = PatternBuilder::new();
            b.prover_message::<u32>("msg");
            b.finalize()
        };

        let pattern = {
            let mut b = PatternBuilder::new();
            b.extend("first", &sub);
            b.extend("second", &sub);
            b.finalize()
        };

        assert_eq!(pattern.len(), 2);
        assert_eq!(pattern.steps()[0].scope, "first");
        assert_eq!(pattern.steps()[1].scope, "second");
    }

    #[test]
    fn extend_composes_nested_scopes() {
        // Sub-pattern with its own internal scope
        let sub = {
            let mut b = PatternBuilder::new();
            b.prover_message::<u32>("top");
            b.scope("inner", |b| {
                b.verifier_message::<u32>("deep");
            });
            b.finalize()
        };

        let pattern = {
            let mut b = PatternBuilder::new();
            b.extend("outer", &sub);
            b.finalize()
        };

        assert_eq!(pattern.steps()[0].scope, "outer");
        assert_eq!(pattern.steps()[0].label, "top");
        assert_eq!(pattern.steps()[1].scope, "outer::inner");
        assert_eq!(pattern.steps()[1].label, "deep");
    }

    #[test]
    fn extend_inside_scope() {
        let sub = {
            let mut b = PatternBuilder::new();
            b.prover_message::<u32>("msg");
            b.finalize()
        };

        let pattern = {
            let mut b = PatternBuilder::new();
            b.scope("protocol", |b| {
                b.extend("sub", &sub);
            });
            b.finalize()
        };

        // extend("sub") inside scope("protocol") → "protocol::sub"
        assert_eq!(pattern.steps()[0].scope, "protocol::sub");
    }

    #[test]
    fn extend_round_trip() {
        let sigma = {
            let mut b = PatternBuilder::new();
            b.prover_message::<u32>("commitment");
            b.verifier_message::<u32>("challenge");
            b.prover_message::<u32>("response");
            b.finalize()
        };

        let pattern = {
            let mut b = PatternBuilder::new();
            b.public_message::<u32>("instance");
            b.extend("sigma", &sigma);
            b.finalize()
        };

        let domsep = domain_separator!("extend round trip"; "test").instance(&0u32);

        let mut prover = CheckedProverState::new(domsep.std_prover(), pattern.clone());
        prover.public_message(&42u32);
        prover.prover_message(&1u32);
        let _: u32 = prover.verifier_message();
        prover.prover_message(&2u32);
        let inner = prover.check_complete();
        let narg = inner.narg_string().to_vec();

        let mut verifier = CheckedVerifierState::new(domsep.std_verifier(&narg), pattern);
        verifier.public_message(&42u32);
        let c: u32 = verifier.prover_message().unwrap();
        assert_eq!(c, 1);
        let _: u32 = verifier.verifier_message();
        let r: u32 = verifier.prover_message().unwrap();
        assert_eq!(r, 2);
        assert!(verifier.check_eof().is_ok());
    }

    #[test]
    fn loop_with_begin_end_scope() {
        let pattern = {
            let mut b = PatternBuilder::new();
            for i in 0..3 {
                b.begin_scope(&alloc::format!("round_{i}"));
                b.prover_message::<u32>("L");
                b.prover_message::<u32>("R");
                b.verifier_message::<u32>("challenge");
                b.end_scope();
            }
            b.finalize()
        };

        assert_eq!(pattern.len(), 9);
        assert_eq!(pattern.steps()[0].scope, "round_0");
        assert_eq!(pattern.steps()[3].scope, "round_1");
        assert_eq!(pattern.steps()[6].scope, "round_2");

        let domsep = domain_separator!("loop scopes"; "test").instance(&0u32);
        let mut prover = CheckedProverState::new(domsep.std_prover(), pattern);
        for _ in 0..3 {
            prover.prover_message(&1u32);
            prover.prover_message(&2u32);
            let _: u32 = prover.verifier_message();
        }
        let _ = prover.check_complete();
    }

    #[test]
    #[should_panic(expected = "in scope \"sigma\"")]
    fn scoped_panic_message_includes_scope() {
        let sub = {
            let mut b = PatternBuilder::new();
            b.prover_message::<u32>("commitment");
            b.finalize()
        };

        let pattern = {
            let mut b = PatternBuilder::new();
            b.extend("sigma", &sub);
            b.finalize()
        };

        let domsep = domain_separator!("scope panic"; "test").instance(&0u32);
        let mut prover = CheckedProverState::new(domsep.std_prover(), pattern);
        // Pattern expects prover_message, calling verifier_message instead
        let _: u32 = prover.verifier_message();
    }
}
