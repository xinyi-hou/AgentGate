package agentgate.authorization

import rego.v1

default decision := {
    "action": "DENY",
    "reasons": ["policy_denied"]
}

decision := {
    "action": "DENY",
    "reasons": failed
} if {
    failed := [sprintf("%s_mismatch", [name]) |
        some name
        input.checks[name] == false
    ]
    count(failed) > 0
}

decision := {
    "action": "REQUIRE_APPROVAL",
    "reasons": ["approval_required"]
} if {
    every _, matched in input.checks { matched == true }
    input.requires_approval == true
    input.approval_valid == false
}

decision := {
    "action": "REQUIRE_CONFIRMATION",
    "reasons": ["confirmation_required"]
} if {
    every _, matched in input.checks { matched == true }
    not input.requires_approval
    input.requires_confirmation == true
    input.confirmed == false
}

decision := {
    "action": "ALLOW",
    "reasons": []
} if {
    every _, matched in input.checks { matched == true }
    not input.requires_approval
    not input.requires_confirmation
}

decision := {
    "action": "ALLOW",
    "reasons": []
} if {
    every _, matched in input.checks { matched == true }
    input.requires_approval == true
    input.approval_valid == true
}

decision := {
    "action": "ALLOW",
    "reasons": []
} if {
    every _, matched in input.checks { matched == true }
    not input.requires_approval
    input.requires_confirmation == true
    input.confirmed == true
}
