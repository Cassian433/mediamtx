package core

import (
	"fmt"
	"reflect"

	"github.com/google/uuid"

	"github.com/bluenviron/mediamtx/internal/conf"
	"github.com/bluenviron/mediamtx/internal/defs"
	"github.com/bluenviron/mediamtx/internal/logger"
)

func newInternalUserIDs(count int) []uuid.UUID {
	ids := make([]uuid.UUID, count)
	for i := range ids {
		ids[i] = uuid.New()
	}
	return ids
}

func internalUserIndex(ids []uuid.UUID, id uuid.UUID) int {
	for i, existing := range ids {
		if existing == id {
			return i
		}
	}
	return -1
}

type internalUserOp int

const (
	internalUserAdd internalUserOp = iota
	internalUserPatch
	internalUserReplace
	internalUserDelete
)

type internalUserSnapshot struct {
	conf *conf.Conf
	ids  []uuid.UUID
}

type configInternalUserRes struct {
	id  uuid.UUID
	err error
}

type configInternalUserReq struct {
	op       internalUserOp
	id       uuid.UUID
	user     conf.AuthInternalUser
	optional conf.OptionalAuthInternalUser
	res      chan configInternalUserRes
}

func (p *Core) doAPIConfigInternalUser(req configInternalUserReq) (*conf.Conf, []uuid.UUID, uuid.UUID, error) {
	current := p.conf.Load()
	newConf := current.Clone()
	ids := append([]uuid.UUID(nil), p.internalUserIDs...)
	id := req.id

	if req.op == internalUserAdd {
		if req.user.Pass == "<redacted>" {
			return nil, nil, uuid.Nil, fmt.Errorf("cannot add a user with a redacted password")
		}
		id = uuid.New()
		newConf.AuthInternalUsers = append(newConf.AuthInternalUsers, req.user)
		ids = append(ids, id)
	} else {
		index := internalUserIndex(ids, id)
		if index < 0 {
			return nil, nil, uuid.Nil, conf.ErrAuthInternalUserNotFound
		}

		old := newConf.AuthInternalUsers[index]
		switch req.op {
		case internalUserPatch:
			if req.optional.User != nil {
				old.User = *req.optional.User
			}
			if req.optional.Pass != nil && *req.optional.Pass != "<redacted>" {
				old.Pass = *req.optional.Pass
			}
			if req.optional.IPs != nil {
				old.IPs = *req.optional.IPs
			}
			if req.optional.Permissions != nil {
				old.Permissions = *req.optional.Permissions
			}
			newConf.AuthInternalUsers[index] = old

		case internalUserReplace:
			if req.user.Pass == "<redacted>" {
				req.user.Pass = old.Pass
			}
			newConf.AuthInternalUsers[index] = req.user

		case internalUserDelete:
			newConf.AuthInternalUsers = append(newConf.AuthInternalUsers[:index], newConf.AuthInternalUsers[index+1:]...)
			ids = append(ids[:index], ids[index+1:]...)
		}
	}

	if err := newConf.Validate(nil); err != nil {
		return nil, nil, uuid.Nil, err
	}
	if len(ids) != len(newConf.AuthInternalUsers) {
		ids = newInternalUserIDs(len(newConf.AuthInternalUsers))
	} else if req.op == internalUserAdd && !reflect.DeepEqual(newConf.AuthInternalUsers[:len(newConf.AuthInternalUsers)-1],
		current.AuthInternalUsers) {
		ids = newInternalUserIDs(len(newConf.AuthInternalUsers))
		id = ids[len(ids)-1]
	}

	p.Log(logger.Info, "reloading configuration (API request)")
	return newConf, ids, id, nil
}

// APIConfigInternalUsersSnapshot implements apiParent.
func (p *Core) APIConfigInternalUsersSnapshot() []defs.APIInternalUser {
	snapshot := p.internalUsers.Load()
	redacted := conf.Redact(snapshot.conf)
	items := make([]defs.APIInternalUser, len(redacted.AuthInternalUsers))
	for i, user := range redacted.AuthInternalUsers {
		items[i] = defs.APIInternalUser{
			ID:          snapshot.ids[i],
			Pos:         i + 1,
			User:        user.User,
			Pass:        user.Pass,
			IPs:         user.IPs,
			Permissions: user.Permissions,
		}
	}
	return items
}

func (p *Core) apiConfigInternalUser(req configInternalUserReq) (uuid.UUID, error) {
	req.res = make(chan configInternalUserRes)
	select {
	case p.chAPIConfigInternalUser <- req:
		res := <-req.res
		return res.id, res.err
	case <-p.ctx.Done():
		return uuid.Nil, fmt.Errorf("terminated")
	}
}

// APIConfigInternalUsersAdd implements apiParent.
func (p *Core) APIConfigInternalUsersAdd(user conf.AuthInternalUser) (uuid.UUID, error) {
	return p.apiConfigInternalUser(configInternalUserReq{op: internalUserAdd, user: user})
}

// APIConfigInternalUsersPatch implements apiParent.
func (p *Core) APIConfigInternalUsersPatch(id uuid.UUID, optional conf.OptionalAuthInternalUser) error {
	_, err := p.apiConfigInternalUser(configInternalUserReq{op: internalUserPatch, id: id, optional: optional})
	return err
}

// APIConfigInternalUsersReplace implements apiParent.
func (p *Core) APIConfigInternalUsersReplace(id uuid.UUID, user conf.AuthInternalUser) error {
	_, err := p.apiConfigInternalUser(configInternalUserReq{op: internalUserReplace, id: id, user: user})
	return err
}

// APIConfigInternalUsersDelete implements apiParent.
func (p *Core) APIConfigInternalUsersDelete(id uuid.UUID) error {
	_, err := p.apiConfigInternalUser(configInternalUserReq{op: internalUserDelete, id: id})
	return err
}
