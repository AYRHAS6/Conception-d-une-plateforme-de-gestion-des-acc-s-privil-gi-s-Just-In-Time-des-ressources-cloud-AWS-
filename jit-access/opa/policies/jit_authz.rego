package jit.authz

import future.keywords.if
import future.keywords.in

default allow := false

# ─────────────────────────────────────────────────────────
# Matrice de correspondance : role metier -> roles temporaires
# que ce metier a le droit de demander.
# ─────────────────────────────────────────────────────────
role_resource_matrix := {
    "devops-engineer":      {"s3-write-access", "s3-read-access", "ec2-session-access"},
    "backend-developer":     {"s3-write-access", "s3-read-access"},
    "system-administrator": {"ec2-session-access"},
    "qa-engineer":           {"s3-read-access"},
    "security-analyst":      {"s3-write-access", "s3-read-access", "ec2-session-access"},
    "hr-specialist":          set(),
}

# ─────────────────────────────────────────────────────────
# Regle principale : toutes les conditions doivent etre vraies
# ─────────────────────────────────────────────────────────
allow if {
    role_can_request_this
    ticket_is_active
    ticket_assigned_to_requester
    priority_is_sufficient
    duration_within_limit
    duration_above_minimum
    is_within_business_hours
}

# ─────────────────────────────────────────────────────────
# Le role metier de l'utilisateur autorise-t-il le role demande ?
# ─────────────────────────────────────────────────────────
role_can_request_this if {
    some role in input.user.roles
    input.request.requested_role in role_resource_matrix[role]
}

# ─────────────────────────────────────────────────────────
# Le ticket doit etre actif (pas deja termine)
# ─────────────────────────────────────────────────────────
ticket_is_active if {
    input.ticket.status == "À faire"
}

ticket_is_active if {
    input.ticket.status == "En cours"
}

# ─────────────────────────────────────────────────────────
# Le ticket doit etre assigne a celui qui fait la demande
# ─────────────────────────────────────────────────────────
ticket_assigned_to_requester if {
    input.ticket.assignee == input.user.email
}

# ─────────────────────────────────────────────────────────
# La priorite du ticket doit justifier l'acces demande
# ─────────────────────────────────────────────────────────
priority_is_sufficient if {
    input.ticket.priority in {"Highest", "High", "Medium"}
}

# ─────────────────────────────────────────────────────────
# La duree demandee ne doit pas depasser 4h (240 minutes)
# ─────────────────────────────────────────────────────────
duration_within_limit if {
    input.request.duration_minutes <= 240
}

# ─────────────────────────────────────────────────────────
# La duree demandee doit etre d'au moins 15 minutes
# AWS STS impose ce minimum technique 
# ─────────────────────────────────────────────────────────
duration_above_minimum if {
    input.request.duration_minutes >= 15
}

# ─────────────────────────────────────────────────────────
# La demande ne peut etre acceptee qu'entre une marge de temps precise,
# heure de Casablanca 
# ─────────────────────────────────────────────────────────
is_within_business_hours if {
    ts_ns := time.parse_rfc3339_ns(input.context.current_time)
    clock := time.clock([ts_ns, "Africa/Casablanca"])
    clock[0] >= 9
}

is_within_business_hours if {
    ts_ns := time.parse_rfc3339_ns(input.context.current_time)
    clock := time.clock([ts_ns, "Africa/Casablanca"])
    clock[0] < 17
}
