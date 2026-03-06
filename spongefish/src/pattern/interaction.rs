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
pub struct Interaction {
    pub kind: InteractionKind,
    pub type_id: TypeId,
    pub type_name: &'static str,
    pub label: String,
    pub count: usize,
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

    #[cfg(feature = "sha3")]
    #[must_use]
    pub fn pattern_hash(&self) -> [u8; 64] {
        use crate::DuplexSpongeInterface;

        let mut sponge = crate::StdHash::default();
        for step in &self.steps {
            let kind_byte = match step.kind {
                InteractionKind::ProverMessage => 0u8,
                InteractionKind::VerifierMessage => 1u8,
                InteractionKind::PublicMessage => 2u8,
            };
            sponge.absorb(&[kind_byte]);
            sponge.absorb(step.type_name.as_bytes());
            sponge.absorb(step.label.as_bytes());
            sponge.absorb(&step.count.to_le_bytes());
        }
        sponge.squeeze_array()
    }
}

#[derive(Debug, Default)]
pub struct PatternBuilder {
    steps: Vec<Interaction>,
}

impl PatternBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn prover_message<T: 'static + ?Sized>(&mut self, label: &str) -> &mut Self {
        self.prover_messages::<T>(1, label)
    }

    pub fn prover_messages<T: 'static + ?Sized>(&mut self, count: usize, label: &str) -> &mut Self {
        self.steps.push(Interaction {
            kind: InteractionKind::ProverMessage,
            type_id: TypeId::of::<T>(),
            type_name: core::any::type_name::<T>(),
            label: String::from(label),
            count,
        });
        self
    }

    pub fn verifier_message<T: 'static>(&mut self, label: &str) -> &mut Self {
        self.verifier_messages::<T>(1, label)
    }

    pub fn verifier_messages<T: 'static>(&mut self, count: usize, label: &str) -> &mut Self {
        self.steps.push(Interaction {
            kind: InteractionKind::VerifierMessage,
            type_id: TypeId::of::<T>(),
            type_name: core::any::type_name::<T>(),
            label: String::from(label),
            count,
        });
        self
    }

    pub fn public_message<T: 'static + ?Sized>(&mut self, label: &str) -> &mut Self {
        self.public_messages::<T>(1, label)
    }

    pub fn public_messages<T: 'static + ?Sized>(&mut self, count: usize, label: &str) -> &mut Self {
        self.steps.push(Interaction {
            kind: InteractionKind::PublicMessage,
            type_id: TypeId::of::<T>(),
            type_name: core::any::type_name::<T>(),
            label: String::from(label),
            count,
        });
        self
    }

    #[must_use]
    pub fn finalize(self) -> InteractionPattern {
        InteractionPattern { steps: self.steps }
    }
}
