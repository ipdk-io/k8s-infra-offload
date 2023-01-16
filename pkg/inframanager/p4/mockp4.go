package p4

import (
	"context"
	"fmt"
	"github.com/antoninbas/p4runtime-go-client/pkg/client"
	p4_v1 "github.com/p4lang/p4runtime/go/p4/v1"
)

type MockP4 struct {
	P4RtCWrapper
}

var (
	Errorcase    bool = false
	ASelMemError bool = false
	ASelGrpError bool = false
)

func (m MockP4) NewTableEntry(p4RtC *client.Client, table string, mfs map[string]client.MatchInterface, action *p4_v1.TableAction, options *client.TableEntryOptions) *p4_v1.TableEntry {
	entry := &p4_v1.TableEntry{
		TableId: 12345,
		Action:  nil,
	}
	return entry
}

func (m MockP4) NewTableActionDirect(p4RtC *client.Client, action string, params [][]byte) *p4_v1.TableAction {
	/*action := &p4_v1.TableAction{
		Type: &p4_v1.TableAction_Action{Action: &p4_v1.Action{ActionId: 111}},
	}*/

	return &p4_v1.TableAction{}
}

func (m MockP4) InsertTableEntry(ctx context.Context, p4RtC *client.Client, entry *p4_v1.TableEntry) error {
	if Errorcase {
		return fmt.Errorf("cannot insert entry into table")
	} else {
		return nil
	}
}

func (m MockP4) DeleteTableEntry(ctx context.Context, p4RtC *client.Client, entry *p4_v1.TableEntry) error {
	if Errorcase {
		return fmt.Errorf("cannot delete entry from table")
	} else {
		return nil
	}
}

func (m MockP4) NewActionProfileMember(p4RtC *client.Client, actionProfile string, memberID uint32, action string, params [][]byte) *p4_v1.ActionProfileMember {
	entry := &p4_v1.ActionProfileMember{
		ActionProfileId: 1,
		MemberId:        memberID,
	}
	return entry
}

func (m MockP4) InsertActionProfileMember(ctx context.Context, p4RtC *client.Client, entry *p4_v1.ActionProfileMember) error {
	if ASelMemError {
		return fmt.Errorf("cannot insert action profile member")
	} else {
		return nil
	}
}

func (m MockP4) DeleteActionProfileMember(ctx context.Context, p4RtC *client.Client, entry *p4_v1.ActionProfileMember) error {
	if ASelMemError {
		err := fmt.Errorf("cannot delete action profile member")
		return err
	} else {
		return nil
	}
}

func (m MockP4) NewActionProfileGroup(p4RtC *client.Client, actionProfile string, groupID uint32, members []*p4_v1.ActionProfileGroup_Member, size int32) *p4_v1.ActionProfileGroup {
	entry := &p4_v1.ActionProfileGroup{
		ActionProfileId: 1,
		GroupId:         groupID,
		Members:         members,
		MaxSize:         size,
	}

	return entry
}

func (m MockP4) InsertActionProfileGroup(ctx context.Context, p4RtC *client.Client, entry *p4_v1.ActionProfileGroup) error {
	if ASelGrpError {
		err := fmt.Errorf("cannot insert action profile group")
		return err
	} else {
		return nil
	}
}

func (m MockP4) DeleteActionProfileGroup(ctx context.Context, p4RtC *client.Client, entry *p4_v1.ActionProfileGroup) error {
	if ASelGrpError {
		err := fmt.Errorf("cannot delete action profile group")
		return err
	} else {
		return nil
	}
}

func (m MockP4) ModifyActionProfileMember(ctx context.Context, p4RtC *client.Client, entry *p4_v1.ActionProfileMember) error {
	if ASelMemError {
		err := fmt.Errorf("cannot modify action profile member")
		return err
	} else {
		return nil
	}
}

func (m MockP4) ModifyActionProfileGroup(ctx context.Context, p4RtC *client.Client, entry *p4_v1.ActionProfileGroup) error {
	if ASelGrpError {
		err := fmt.Errorf("cannot modify action profile group")
		return err
	} else {
		return nil
	}
}

func (m MockP4) NewTableActionGroup(p4RtC *client.Client, groupID uint32) *p4_v1.TableAction {
	return &p4_v1.TableAction{
		Type: &p4_v1.TableAction_ActionProfileGroupId{ActionProfileGroupId: groupID},
	}
}
