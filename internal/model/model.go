// Package model holds the identifiers and enums shared by every subsystem.
package model

import "fmt"

type OperatorID string
type BadgeID string
type CabinetID string

func (c CabinetID) String() string { return string(c) }

// Role is the operating role of a person in the chemical store.
type Role string

const (
	// RoleHandler is authorised to enter the cabinet and retrieve material.
	RoleHandler Role = "handler"
	// RoleCustodian keeps the second key and co-signs highly toxic withdrawals.
	RoleCustodian Role = "custodian"
	// RoleSupervisor can review and clear discrepancies.
	RoleSupervisor Role = "supervisor"
)

// HazardClass drives the policy level applied to a cabinet.
type HazardClass string

const (
	// HazardHighlyToxic is 剧毒品: two-person, dual-lock, full reconciliation.
	HazardHighlyToxic HazardClass = "highly_toxic"
	// HazardGeneral is a normal flammable/corrosive store.
	HazardGeneral HazardClass = "general"
)

// Product is a stored chemical. Containers reference a product by its SKU.
type Product struct {
	SKU           string
	Name          string
	CAS           string
	Hazard        HazardClass
	Unit          string
	DensityGPerML float64 // used to convert a measured mass delta into a volume
}

func SlotName(i int) string {
	if i == 0 {
		return "A"
	}
	return "B"
}

func OperatorLabel(id OperatorID) string {
	if id == "" {
		return "<none>"
	}
	return string(id)
}

func (r Role) Valid() bool {
	switch r {
	case RoleHandler, RoleCustodian, RoleSupervisor:
		return true
	}
	return false
}

func (h HazardClass) String() string {
	if h == "" {
		return string(HazardGeneral)
	}
	return string(h)
}

func (p Product) String() string {
	if p.CAS == "" {
		return p.Name
	}
	return fmt.Sprintf("%s (CAS %s)", p.Name, p.CAS)
}
