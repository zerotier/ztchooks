// Copyright 2023 ZeroTier, Inc. All rights reserved.
// Use of this source code is governed by the Mozilla Public License Version 2.0
// license that can be found in the LICENSE file.

// Package ztchooks provides primitives for serializing and verifying hooks
// fired from [ZeroTier Central](https://my.zerotier.com)
package ztchooks

type HookType string

// HooKTypes
const (
	HOOK_TYPE_UNKNOWN       HookType = "UNKNOWN"
	NETWORK_JOIN            HookType = "NETWORK_JOIN"
	NETWORK_AUTH            HookType = "NETWORK_AUTH"
	NETWORK_DEAUTH          HookType = "NETWORK_DEAUTH"
	NETWORK_SSO_LOGIN       HookType = "NETWORK_SSO_LOGIN"
	NETWORK_SSO_LOGIN_ERROR HookType = "NETWORK_SSO_LOGIN_ERROR"
	NETWORK_CREATED         HookType = "NETWORK_CREATED"
	NETWORK_CONFIG_CHANGED  HookType = "NETWORK_CONFIG_CHANGED"
	NETWORK_DELETED         HookType = "NETWORK_DELETED"
	MEMBER_CONFIG_CHANGED   HookType = "MEMBER_CONFIG_CHANGED"
	MEMBER_DELETED          HookType = "MEMBER_DELETED"
	ORG_INVITE_SENT         HookType = "ORG_INVITE_SENT"
	ORG_INVITE_ACCEPTED     HookType = "ORG_INVITE_ACCEPTED"
	ORG_INVITE_REJECTED     HookType = "ORG_INVITE_REJECTED"
	ORG_MEMBER_REMOVED      HookType = "ORG_MEMBER_REMOVED"
)

// HookTypeFromString is a convenience function to convert from a string
// to a HookType value
func HookTypeFromString(hType string) HookType {
	switch hType {
	case string(NETWORK_JOIN):
		return NETWORK_JOIN
	case string(NETWORK_AUTH):
		return NETWORK_AUTH
	case string(NETWORK_DEAUTH):
		return NETWORK_DEAUTH
	case string(NETWORK_SSO_LOGIN):
		return NETWORK_SSO_LOGIN
	case string(NETWORK_SSO_LOGIN_ERROR):
		return NETWORK_SSO_LOGIN_ERROR
	case string(NETWORK_CREATED):
		return NETWORK_CREATED
	case string(NETWORK_CONFIG_CHANGED):
		return NETWORK_CONFIG_CHANGED
	case string(NETWORK_DELETED):
		return NETWORK_DELETED
	case string(MEMBER_CONFIG_CHANGED):
		return MEMBER_CONFIG_CHANGED
	case string(MEMBER_DELETED):
		return MEMBER_DELETED
	case string(ORG_INVITE_SENT):
		return ORG_INVITE_SENT
	case string(ORG_INVITE_ACCEPTED):
		return ORG_INVITE_ACCEPTED
	case string(ORG_INVITE_REJECTED):
		return ORG_INVITE_REJECTED
	case string(ORG_MEMBER_REMOVED):
		return ORG_MEMBER_REMOVED
	default:
		return HOOK_TYPE_UNKNOWN
	}
}

// HookTypeToString is a convenience function to convert from HookType
// to a string
func HookTypeToString(hType HookType) string {
	return string(hType)
}

// HookBase contains the base information present in all webhooks sent by
// ZeroTier Central
type HookBase struct {
	// HookID is the internal ZeroTier Central ID of the hook being fired
	HookID string `json:"hook_id"`

	// OrgID is the internal Organization ID the hook belongs to
	OrgID string `json:"org_id"`

	// HookType is the type of hook being fired.
	HookType HookType `json:"hook_type"`
}

// NewMemberJoined is fired for `NETWORK_JOIN` hooks. This hook is fired
// the first time the controller sees a new member attempting to join
// a ZeroTier network
type NewMemberJoined struct {
	HookBase

	// NetworkID is the network a new member has joined
	NetworkID string `json:"network_id"`

	// MemberID is the member that is attempting to join the network.
	MemberID string `json:"member_id"`
}

// NetworkMemberAuth is fired for `NETWORK_AUTH` events
type NetworkMemberAuth struct {
	HookBase

	// NetworkID is the network that the member was authorized to join
	NetworkID string `json:"network_id"`

	// MemberID is the member authorized to join the network
	MemberID string `json:"member_id"`

	// UserID is the user that performed the authorization
	UserID string `json:"user_id"`

	// UserEmail is the email address of the user performing the authorization
	UserEmail string `json:"user_email"`
}

// NetworkMemberDeauth is fired for `NETWORK_DEAUTH` events
type NetworkMemberDeauth struct {
	HookBase

	// NetworkID is the network that new member was deauthorized from
	NetworkID string `json:"network_id"`

	// MemberID is the member deauthorized from accessing the network
	MemberID string `json:"member_id"`

	// UserID is the user that performed the deauthorization
	UserID string `json:"user_id"`

	// UserEmail is the email address of the user performing the deauthorization
	UserEmail string `json:"user_email"`
}

// NetworkSSOLogin is fired whenever a user logs into a network via a configured
// OIDC provider
type NetworkSSOLogin struct {
	HookBase

	// NetworkID is the network on which the SSO login was performed
	NetworkID string `json:"network_id"`

	// MemberID is the network member ID on which the SSO login was performed
	MemberID string `json:"member_id"`

	// SSOUserEmail is the email address of the user logging into the network
	SSOUserEmail string `json:"sso_user_email"`
}

// NetworkSSOLoginError is fired when there is a failure during the SSO login process
type NetworkSSOLoginError struct {
	HookBase

	// NetworkID is the network on which the SSO login attempt was performed
	NetworkID string `json:"network_id"`

	// MemberID is the network member ID on which the SSO login attempt was performed
	MemberID string `json:"member_id"`

	// SSOUserEmail is the email address of the user attempting to login into the network
	SSOUserEmail string `json:"sso_user_email"`

	// Error is a description of the error
	Error string `json:"error"`
}

// NetworkCreated is fired whenever an organization member creates a new network
type NetworkCreated struct {
	HookBase

	// NetworkID is the ID of the newly created network
	NetworkID string `json:"network_id"`

	// NetworkConfig is the initial configuration of the new network
	NetworkConfig map[string]any `json:"network_config"`

	// UserID is the ID of the user creating the network
	UserID string `json:"user_id"`

	// UserEmail is the email address of the user creating the network
	UserEmail string `json:"user_email"`
}

// NetworkConfigChanged is fired whenever the configuration of a ZeroTier network changes
type NetworkConfigChanged struct {
	HookBase

	// NetworkID is the network on which the SSO login attempt was performed
	NetworkID string `json:"network_id"`

	// UserID is the user that performed the network configuration change
	UserID string `json:"user_id"`

	// UserEmail is the email address of the user that performed the network configuration change
	UserEmail string `json:"user_email"`

	// OldConfig is the network configuration before the change was applied
	OldConfig map[string]any `json:"old_config"`

	// NewConfig is the new configuration for the network.
	NewConfig map[string]any `json:"new_config"`
}

// NetworkDeleted is fired whenever a network configuration is changed
type NetworkDeleted struct {
	HookBase

	// NetworkID is the network that was deleted
	NetworkID string `json:"network_id"`

	// OldConfig is the network configuration before the network was deleted
	OldConfig map[string]any `json:"old_config"`

	// UserID is the ID of the user that deleted the network
	UserID string `json:"user_id"`

	// UserEmail is the email address of the user that deleted the network
	UserEmail string `json:"user_email"`
}

// MemberConfigChanged is fired when a network member's configuration changes
type MemberConfigChanged struct {
	HookBase

	// NetworkID is the network the member was joined to
	NetworkID string `json:"network_id"`

	// MemberID is the network member that was changed
	MemberID string `json:"member_id"`

	// OldConfig is the network member configuration prior to the change
	OldConfig map[string]any `json:"old_config"`

	// NewConfig is the newly applied member configuration
	NewConfig map[string]any `json:"new_config"`

	// UserID is the ID of the user that modified the network member
	UserID string `json:"user_id"`

	// UserEmail is the email address of the user that modified the network member
	UserEmail string `json:"user_email"`
}

type MemberDeleted struct {
	HookBase

	// NetworkID is the network the member was joined to
	NetworkID string `json:"network_id"`

	// MemberID is the network member that was deleted
	MemberID string `json:"member_id"`

	// OldConfig is the network member configuration prior to the deletion
	OldConfig map[string]any `json:"old_config"`

	// UserID is the ID of the user that deleted the network member
	UserID string `json:"user_id"`

	// UserEmail is the email address of the user that deleted the network member
	UserEmail string `json:"user_email"`
}

// OrgInviteSent is fired whenever a new member is invited to join your ZeroTer organization
// in ZeroTier Central. Because only the org owner can add or remove people from the org,
// the ID of the person performing the invite is omitted.
type OrgInviteSent struct {
	HookBase

	// UserID is the user sending the invite
	UserID string `json:"user_id"`

	// InviteeEmail is the email address of the invitee
	InviteeEmail string `json:"invitee_email"`
}

// OrgInviteAccepted is fired when a user accepts the invitation to join your organization
type OrgInviteAccepted struct {
	HookBase

	// UserID is the user ID accepting the invite
	UserID string `json:"user_id"`

	// UserEmail is the email address of the user accepting the invite
	UserEmail string `json:"user_email"`

	// NetworkIDs
	NetworkIDs []string `json:"network_ids"`
}

// OrgInviteRejected is fired when a user rejects the invite to the organization
type OrgInviteRejected struct {
	HookBase

	// UserID is the user ID rejecting the invite
	UserID string `json:"user_id"`

	// UserEmail is the email address of the user rejecting the invite
	UserEmail string `json:"user_email"`
}

// OrgMemberRemoved is fired whenever an organization member is removed.
// Since currently only the org owner can add or remove people from the org,
// the ID of the person performing the removal is omitted.
type OrgMemberRemoved struct {
	HookBase

	// UserID is the user ID removed from the organization
	UserID string `json:"user_id"`

	// UserEmail is the email address of the user removed from the organization
	UserEmail string `json:"user_email"`
}
