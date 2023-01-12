package p4

import (
	"context"
	"github.com/antoninbas/p4runtime-go-client/pkg/client"
	p4_v1 "github.com/p4lang/p4runtime/go/p4/v1"
)

type P4RtCWrapper interface {
	NewTableEntry(p4RtC *client.Client, table string, mfs map[string]client.MatchInterface, action *p4_v1.TableAction, options *client.TableEntryOptions) *p4_v1.TableEntry
	NewTableActionDirect(p4RtC *client.Client, action string, params [][]byte) *p4_v1.TableAction
	InsertTableEntry(ctx context.Context, p4RtC *client.Client, entry *p4_v1.TableEntry) error
	DeleteTableEntry(ctx context.Context, p4RtC *client.Client, entry *p4_v1.TableEntry) error
	NewActionProfileMember(p4RtC *client.Client, actionProfile string, memberID uint32, action string, params [][]byte) *p4_v1.ActionProfileMember
	InsertActionProfileMember(ctx context.Context, p4RtC *client.Client, entry *p4_v1.ActionProfileMember) error
	DeleteActionProfileMember(ctx context.Context, p4RtC *client.Client, entry *p4_v1.ActionProfileMember) error
	NewActionProfileGroup(p4RtC *client.Client, actionProfile string, groupID uint32, members []*p4_v1.ActionProfileGroup_Member, size int32) *p4_v1.ActionProfileGroup
	InsertActionProfileGroup(ctx context.Context, p4RtC *client.Client, entry *p4_v1.ActionProfileGroup) error
	DeleteActionProfileGroup(ctx context.Context, p4RtC *client.Client, entry *p4_v1.ActionProfileGroup) error
	ModifyActionProfileMember(ctx context.Context, p4RtC *client.Client, entry *p4_v1.ActionProfileMember) error
	ModifyActionProfileGroup(ctx context.Context, p4RtC *client.Client, entry *p4_v1.ActionProfileGroup) error
	NewTableActionGroup(p4RtC *client.Client, groupID uint32) *p4_v1.TableAction
}

type P4RtCWrapperStruct struct {
	P4RtCWrapper
}

func GetP4Wrapper(env string) P4RtCWrapper {
	var p4w P4RtCWrapper
	if env == "test" {
		p4w = MockP4{}

	} else {
		p4w = P4RtCWrapperStruct{}
	}
	return p4w
}

func (P4RtC P4RtCWrapperStruct) NewTableEntry(p4RtC *client.Client, table string, mfs map[string]client.MatchInterface, action *p4_v1.TableAction, options *client.TableEntryOptions) *p4_v1.TableEntry {
	return p4RtC.NewTableEntry(table, mfs, action, nil)
}

func (P4RtC P4RtCWrapperStruct) NewTableActionDirect(p4RtC *client.Client, action string, params [][]byte) *p4_v1.TableAction {
	return p4RtC.NewTableActionDirect(action, params)
}

func (P4RtC P4RtCWrapperStruct) InsertTableEntry(ctx context.Context, p4RtC *client.Client, entry *p4_v1.TableEntry) error {
	return p4RtC.InsertTableEntry(ctx, entry)
}

func (P4RtC P4RtCWrapperStruct) DeleteTableEntry(ctx context.Context, p4RtC *client.Client, entry *p4_v1.TableEntry) error {
	return p4RtC.DeleteTableEntry(ctx, entry)
}

func (P4RtC P4RtCWrapperStruct) NewActionProfileMember(p4RtC *client.Client, actionProfile string, memberID uint32, action string, params [][]byte) *p4_v1.ActionProfileMember {
	return p4RtC.NewActionProfileMember(actionProfile, memberID, action, params)
}

func (P4RtC P4RtCWrapperStruct) InsertActionProfileMember(ctx context.Context, p4RtC *client.Client, entry *p4_v1.ActionProfileMember) error {
	return p4RtC.InsertActionProfileMember(ctx, entry)
}

func (P4RtC P4RtCWrapperStruct) DeleteActionProfileMember(ctx context.Context, p4RtC *client.Client, entry *p4_v1.ActionProfileMember) error {
	return p4RtC.DeleteActionProfileMember(ctx, entry)
}

func (P4RtC P4RtCWrapperStruct) NewActionProfileGroup(p4RtC *client.Client, actionProfile string, groupID uint32, members []*p4_v1.ActionProfileGroup_Member, size int32) *p4_v1.ActionProfileGroup {
	return p4RtC.NewActionProfileGroup(actionProfile, groupID, members, size)
}

func (P4RtC P4RtCWrapperStruct) InsertActionProfileGroup(ctx context.Context, p4RtC *client.Client, entry *p4_v1.ActionProfileGroup) error {
	return p4RtC.InsertActionProfileGroup(ctx, entry)
}

func (P4RtC P4RtCWrapperStruct) DeleteActionProfileGroup(ctx context.Context, p4RtC *client.Client, entry *p4_v1.ActionProfileGroup) error {
	return p4RtC.DeleteActionProfileGroup(ctx, entry)
}

func (P4RtC P4RtCWrapperStruct) ModifyActionProfileMember(ctx context.Context, p4RtC *client.Client, entry *p4_v1.ActionProfileMember) error {
	return p4RtC.ModifyActionProfileMember(ctx, entry)
}

func (P4RtC P4RtCWrapperStruct) ModifyActionProfileGroup(ctx context.Context, p4RtC *client.Client, entry *p4_v1.ActionProfileGroup) error {
	return p4RtC.ModifyActionProfileGroup(ctx, entry)
}

func (P4RtC P4RtCWrapperStruct) NewTableActionGroup(p4RtC *client.Client, groupID uint32) *p4_v1.TableAction {
	return p4RtC.NewTableActionGroup(groupID)
}
