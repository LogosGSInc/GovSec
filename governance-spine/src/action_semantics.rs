//! Server-owned action-plane and completion-criticality semantics.
//!
//! These values are derived — never accepted from a caller — from the exact
//! sealed, hash-bound `ActionEnvelope.tool_name` that `evaluate_strict`
//! already classified. They are NOT part of `ActionEnvelope`'s serialized
//! form or its `action_hash` material (see envelope.rs's `action_hash_material`)
//! — adding this classification does not change `logos.action.v1` bytes or
//! any existing golden hash. The values are instead bound into the
//! decision/capability layer (capability.rs), which has its own, separate
//! signature over its own canonical form.
//!
//! `derive_action_semantics_for_tool` is the single authority for this
//! mapping. It is called once at authorization time (from the sealed
//! envelope) and again at consumption time (from the presented, already
//! action-hash/tool-bound `tool_name`) so a capability's recorded semantics
//! can be reconfirmed rather than trusted blindly across the two calls.

use crate::envelope::ActionEnvelope;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionPlane {
    /// Direct user-facing content or user-initiated action.
    User,
    /// An ordinary consequential tool call (filesystem, shell, browser, ...).
    Tool,
    /// Runtime self-management/telemetry that does not itself produce a
    /// user-visible side effect and is not required for the turn's response
    /// to be considered complete (e.g. heartbeat bookkeeping).
    Control,
    /// GovSec/administrative operations (not used by any tool in this
    /// sprint's vocabulary; reserved so the enum is not User/Tool/Control-only).
    Governance,
}

impl ActionPlane {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Tool => "tool",
            Self::Control => "control",
            Self::Governance => "governance",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletionCriticality {
    /// The turn's response is not safely complete until this action's
    /// outcome (success or explicit denial) is known.
    Required,
    /// The turn's user-visible response can be considered complete
    /// independent of this action's outcome.
    Noncritical,
}

impl CompletionCriticality {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Noncritical => "noncritical",
        }
    }

    pub fn is_required(&self) -> bool {
        matches!(self, Self::Required)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionSemantics {
    pub plane: ActionPlane,
    pub normalized_action: String,
    pub criticality: CompletionCriticality,
}

impl ActionSemantics {
    pub fn required_for_safe_completion(&self) -> bool {
        self.criticality.is_required()
    }
}

/// The one place `heartbeat_respond` (or any future control-plane tool) is
/// mapped to its trusted semantics. Every ordinary tool retains today's
/// implicit semantics: `ActionPlane::Tool`, required for safe completion.
/// This is keyed on `tool_name` alone, which by the time this is called has
/// already been through `ActionEnvelope::seal`/`verify` (hash-bound) or, at
/// consumption, has already been checked equal to the capability's own
/// stored `tool_name` — so a caller cannot make this function see a
/// tool_name it did not actually authorize/present.
pub fn derive_action_semantics_for_tool(tool_name: &str) -> ActionSemantics {
    match tool_name {
        "heartbeat_respond" => ActionSemantics {
            plane: ActionPlane::Control,
            normalized_action: "system.telemetry.heartbeat".to_string(),
            criticality: CompletionCriticality::Noncritical,
        },
        other => ActionSemantics {
            plane: ActionPlane::Tool,
            normalized_action: format!("tool.{other}"),
            criticality: CompletionCriticality::Required,
        },
    }
}

/// Convenience wrapper over a sealed `ActionEnvelope`.
pub fn derive_action_semantics(envelope: &ActionEnvelope) -> ActionSemantics {
    derive_action_semantics_for_tool(&envelope.tool_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_is_control_and_noncritical() {
        let semantics = derive_action_semantics_for_tool("heartbeat_respond");
        assert_eq!(semantics.plane, ActionPlane::Control);
        assert_eq!(semantics.normalized_action, "system.telemetry.heartbeat");
        assert!(!semantics.required_for_safe_completion());
    }

    #[test]
    fn ordinary_tools_stay_tool_plane_and_required() {
        for tool in ["read", "write", "edit", "bash", "exec", "browser"] {
            let semantics = derive_action_semantics_for_tool(tool);
            assert_eq!(semantics.plane, ActionPlane::Tool, "tool={tool}");
            assert!(semantics.required_for_safe_completion(), "tool={tool}");
            assert_eq!(semantics.normalized_action, format!("tool.{tool}"));
        }
    }
}
