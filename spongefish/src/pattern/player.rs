use core::any::TypeId;

use super::interaction::{InteractionKind, InteractionPattern};

pub struct PatternPlayer {
    pattern: InteractionPattern,
    cursor: usize,
}

impl PatternPlayer {
    pub const fn new(pattern: InteractionPattern) -> Self {
        Self { pattern, cursor: 0 }
    }

    fn expect(
        &mut self,
        expected_kind: InteractionKind,
        type_id: TypeId,
        type_name: &str,
        count: usize,
    ) {
        assert!(
            self.cursor < self.pattern.len(),
            "pattern violation at step {}: expected end of pattern (len {}), \
             but got {expected_kind} of {count}x {type_name}",
            self.cursor,
            self.pattern.len(),
        );

        let step = &self.pattern.steps()[self.cursor];

        assert!(
            step.kind == expected_kind,
            "pattern violation at step {} (label {:?}): \
             expected {}, got {expected_kind}",
            self.cursor,
            step.label,
            step.kind,
        );

        assert!(
            step.type_id == type_id,
            "pattern violation at step {} (label {:?}): \
             expected type {}, got {type_name}",
            self.cursor,
            step.label,
            step.type_name,
        );

        assert!(
            step.count == count,
            "pattern violation at step {} (label {:?}): \
             expected count {}, got {count}",
            self.cursor,
            step.label,
            step.count,
        );

        self.cursor += 1;
    }

    pub fn expect_prover_message<T: 'static + ?Sized>(&mut self) {
        self.expect(
            InteractionKind::ProverMessage,
            TypeId::of::<T>(),
            core::any::type_name::<T>(),
            1,
        );
    }

    pub fn expect_prover_messages<T: 'static + ?Sized>(&mut self, count: usize) {
        self.expect(
            InteractionKind::ProverMessage,
            TypeId::of::<T>(),
            core::any::type_name::<T>(),
            count,
        );
    }

    pub fn expect_verifier_message<T: 'static>(&mut self) {
        self.expect(
            InteractionKind::VerifierMessage,
            TypeId::of::<T>(),
            core::any::type_name::<T>(),
            1,
        );
    }

    pub fn expect_verifier_messages<T: 'static>(&mut self, count: usize) {
        self.expect(
            InteractionKind::VerifierMessage,
            TypeId::of::<T>(),
            core::any::type_name::<T>(),
            count,
        );
    }

    pub fn expect_public_message<T: 'static + ?Sized>(&mut self) {
        self.expect(
            InteractionKind::PublicMessage,
            TypeId::of::<T>(),
            core::any::type_name::<T>(),
            1,
        );
    }

    pub fn expect_public_messages<T: 'static + ?Sized>(&mut self, count: usize) {
        self.expect(
            InteractionKind::PublicMessage,
            TypeId::of::<T>(),
            core::any::type_name::<T>(),
            count,
        );
    }

    pub fn check_complete(&self) {
        assert!(
            self.cursor == self.pattern.len(),
            "pattern violation: pattern has {} steps but only {} were executed",
            self.pattern.len(),
            self.cursor,
        );
    }
}
