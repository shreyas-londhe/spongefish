use alloc::string::String;
use alloc::vec::Vec;
use core::any::TypeId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InteractionKind {
    ProverMessage,
    VerifierMessage,
    PublicMessage,
}

impl core::fmt::Display for InteractionKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ProverMessage => write!(f, "ProverMessage"),
            Self::VerifierMessage => write!(f, "VerifierMessage"),
            Self::PublicMessage => write!(f, "PublicMessage"),
        }
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Interaction {
    pub kind: InteractionKind,
    pub type_id: TypeId,
    pub type_name: &'static str,
    pub label: String,
    pub count: usize,
    pub scope: String,
}

#[derive(Debug, Clone)]
pub struct InteractionPattern {
    steps: Vec<Interaction>,
}

impl InteractionPattern {
    #[must_use]
    pub fn steps(&self) -> &[Interaction] {
        &self.steps
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.steps.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Compute a deterministic 64-byte hash of this pattern.
    ///
    /// The hash covers the kind, type name, scope, label, and count of each
    /// step.  It is deterministic within a single compiler version, but
    /// **not stable across Rust compiler versions** because `type_name` output
    /// is not guaranteed stable.  Do not persist or compare hashes produced
    /// by different builds.
    #[cfg(feature = "sha3")]
    #[must_use]
    pub fn pattern_hash(&self) -> [u8; 64] {
        use crate::DuplexSpongeInterface;

        let mut sponge = crate::StdHash::default();
        // Domain-separate this use of the sponge.
        sponge.absorb(b"spongefish-pattern-hash-v1");
        sponge.absorb(&(self.steps.len() as u64).to_le_bytes());

        for step in &self.steps {
            let kind_byte = match step.kind {
                InteractionKind::ProverMessage => 0u8,
                InteractionKind::VerifierMessage => 1u8,
                InteractionKind::PublicMessage => 2u8,
            };
            sponge.absorb(&[kind_byte]);
            // Length-prefix each string field to prevent collisions.
            sponge.absorb(&(step.type_name.len() as u64).to_le_bytes());
            sponge.absorb(step.type_name.as_bytes());
            sponge.absorb(&(step.scope.len() as u64).to_le_bytes());
            sponge.absorb(step.scope.as_bytes());
            sponge.absorb(&(step.label.len() as u64).to_le_bytes());
            sponge.absorb(step.label.as_bytes());
            sponge.absorb(&step.count.to_le_bytes());
        }
        sponge.squeeze_array()
    }
}

#[derive(Debug, Default)]
pub struct PatternBuilder {
    steps: Vec<Interaction>,
    scope_stack: Vec<String>,
}

impl PatternBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn current_scope(&self) -> String {
        let mut scope = String::new();
        for (i, s) in self.scope_stack.iter().enumerate() {
            if i > 0 {
                scope.push_str("::");
            }
            scope.push_str(s);
        }
        scope
    }

    fn push_step(
        &mut self,
        kind: InteractionKind,
        type_id: TypeId,
        type_name: &'static str,
        label: &str,
        count: usize,
    ) {
        self.steps.push(Interaction {
            kind,
            type_id,
            type_name,
            label: String::from(label),
            count,
            scope: self.current_scope(),
        });
    }

    pub fn prover_message<T: 'static + ?Sized>(&mut self, label: &str) -> &mut Self {
        self.prover_messages::<T>(1, label)
    }

    pub fn prover_messages<T: 'static + ?Sized>(&mut self, count: usize, label: &str) -> &mut Self {
        self.push_step(
            InteractionKind::ProverMessage,
            TypeId::of::<T>(),
            core::any::type_name::<T>(),
            label,
            count,
        );
        self
    }

    pub fn verifier_message<T: 'static>(&mut self, label: &str) -> &mut Self {
        self.verifier_messages::<T>(1, label)
    }

    pub fn verifier_messages<T: 'static>(&mut self, count: usize, label: &str) -> &mut Self {
        self.push_step(
            InteractionKind::VerifierMessage,
            TypeId::of::<T>(),
            core::any::type_name::<T>(),
            label,
            count,
        );
        self
    }

    pub fn public_message<T: 'static + ?Sized>(&mut self, label: &str) -> &mut Self {
        self.public_messages::<T>(1, label)
    }

    pub fn public_messages<T: 'static + ?Sized>(&mut self, count: usize, label: &str) -> &mut Self {
        self.push_step(
            InteractionKind::PublicMessage,
            TypeId::of::<T>(),
            core::any::type_name::<T>(),
            label,
            count,
        );
        self
    }

    /// Enter a named scope. All steps added until the matching `end_scope()`
    /// will have this scope in their diagnostic path.
    ///
    /// # Panics
    ///
    /// `finalize()` panics if any scope is left unclosed.
    pub fn begin_scope(&mut self, name: &str) -> &mut Self {
        assert!(!name.is_empty(), "begin_scope() requires a non-empty name");
        self.scope_stack.push(String::from(name));
        self
    }

    /// Close the most recently opened scope.
    ///
    /// # Panics
    ///
    /// Panics if there is no open scope.
    pub fn end_scope(&mut self) -> &mut Self {
        assert!(
            self.scope_stack.pop().is_some(),
            "end_scope() called with no open scope"
        );
        self
    }

    /// Add steps inside a named scope using a closure. The scope is
    /// automatically opened before and closed after the closure runs.
    pub fn scope(&mut self, name: &str, f: impl FnOnce(&mut Self)) -> &mut Self {
        self.begin_scope(name);
        f(self);
        self.end_scope();
        self
    }

    /// Inline all steps from a pre-built `InteractionPattern` under a named scope.
    /// If the sub-pattern's steps already have scopes, they are nested under the
    /// given name (e.g. sub-pattern scope `"inner"` becomes `"name::inner"`).
    ///
    /// # Panics
    ///
    /// Panics if `name` is empty.
    pub fn extend(&mut self, name: &str, pattern: &InteractionPattern) -> &mut Self {
        assert!(!name.is_empty(), "extend() requires a non-empty scope name");
        self.scope_stack.push(String::from(name));
        let prefix = self.current_scope();
        self.scope_stack.pop();

        for step in pattern.steps() {
            let scope = if step.scope.is_empty() {
                prefix.clone()
            } else {
                alloc::format!("{}::{}", prefix, step.scope)
            };
            self.steps.push(Interaction {
                kind: step.kind,
                type_id: step.type_id,
                type_name: step.type_name,
                label: step.label.clone(),
                count: step.count,
                scope,
            });
        }
        self
    }

    /// Finalize the builder into an immutable `InteractionPattern`.
    ///
    /// # Panics
    ///
    /// Panics if any scope opened with `begin_scope()` was not closed.
    #[must_use]
    pub fn finalize(self) -> InteractionPattern {
        assert!(
            self.scope_stack.is_empty(),
            "finalize() called with {} unclosed scope(s): {:?}",
            self.scope_stack.len(),
            self.scope_stack,
        );
        InteractionPattern { steps: self.steps }
    }
}
