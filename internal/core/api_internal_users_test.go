package core

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/bluenviron/mediamtx/internal/auth"
	"github.com/bluenviron/mediamtx/internal/conf"
)

func internalUserRequest(t *testing.T, client *http.Client, method string, path string, body any, status int) map[string]any {
	t.Helper()

	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		require.NoError(t, err)
	}

	req, err := http.NewRequest(method, "http://localhost:9997/v3/config/internal-users/"+path, bytes.NewReader(payload))
	require.NoError(t, err)
	res, err := client.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	require.Equal(t, status, res.StatusCode)

	var out map[string]any
	require.NoError(t, json.NewDecoder(res.Body).Decode(&out))
	return out
}

func internalUserList(t *testing.T, client *http.Client) []any {
	t.Helper()
	return internalUserRequest(t, client, http.MethodGet, "list", nil, http.StatusOK)["items"].([]any)
}

func TestAPIConfigInternalUsers(t *testing.T) {
	p, ok := newInstance(t, "api: yes\n")
	require.True(t, ok)
	defer p.Close()

	tr := &http.Transport{}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}

	items := internalUserList(t, client)
	require.Len(t, items, 2)
	first, second := items[0].(map[string]any), items[1].(map[string]any)
	firstID, secondID := apiMapUUID(t, first, "id"), apiMapUUID(t, second, "id")
	require.NotEqual(t, firstID, secondID)
	require.Equal(t, float64(1), first["pos"])
	require.Equal(t, float64(2), second["pos"])
	require.Equal(t, "any", first["user"])
	require.Equal(t, "any", second["user"])
	require.NotContains(t, first, "conf")
	require.Contains(t, first, "permissions")
	require.Contains(t, first, "ips")

	page := internalUserRequest(t, client, http.MethodGet, "list?itemsPerPage=1&page=1", nil, http.StatusOK)
	require.Equal(t, float64(2), page["itemCount"])
	require.Equal(t, float64(2), page["pageCount"])
	require.Equal(t, secondID, apiMapUUID(t, page["items"].([]any)[0].(map[string]any), "id"))

	user := map[string]any{"user": "alice", "pass": "secret", "permissions": []any{map[string]any{"action": "api"}}}
	added := internalUserRequest(t, client, http.MethodPost, "add", user, http.StatusOK)
	require.Equal(t, "ok", added["status"])
	id := apiMapUUID(t, added, "id")
	require.Equal(t, float64(3), internalUserRequest(t, client, http.MethodGet, "get/"+id.String(), nil, http.StatusOK)["pos"])
	require.Equal(t, "<redacted>", internalUserRequest(t, client, http.MethodGet,
		"get/"+id.String(), nil, http.StatusOK)["pass"])
	items = internalUserList(t, client)
	require.Equal(t, "<redacted>", items[2].(map[string]any)["pass"])
	require.NotContains(t, items[2].(map[string]any), "conf")

	internalUserRequest(t, client, http.MethodPatch, "patch/"+id.String(), map[string]any{
		"user": "bob", "pass": "<redacted>",
	}, http.StatusOK)
	require.Equal(t, conf.Credential("secret"), p.conf.Load().AuthInternalUsers[2].Pass)
	_, authErr := p.authManager.Authenticate(&auth.Request{
		Action:      conf.AuthActionAPI,
		IP:          net.ParseIP("127.0.0.1"),
		Credentials: &auth.Credentials{User: "bob", Pass: "secret"},
	})
	require.Nil(t, authErr)
	require.Equal(t, "bob", internalUserRequest(t, client, http.MethodGet, "get/"+id.String(), nil,
		http.StatusOK)["user"])

	internalUserRequest(t, client, http.MethodPost, "replace/"+id.String(), map[string]any{
		"user": "carol", "pass": "<redacted>", "permissions": []any{map[string]any{"action": "api"}},
	}, http.StatusOK)
	require.Equal(t, conf.Credential("secret"), p.conf.Load().AuthInternalUsers[2].Pass)
	require.Equal(t, "carol", internalUserRequest(t, client, http.MethodGet, "get/"+id.String(), nil,
		http.StatusOK)["user"])

	internalUserRequest(t, client, http.MethodPatch, "patch/"+id.String(), map[string]any{"user": ""}, http.StatusBadRequest)
	require.Equal(t, "carol", internalUserRequest(t, client, http.MethodGet, "get/"+id.String(), nil,
		http.StatusOK)["user"])
	internalUserRequest(t, client, http.MethodPost, "add", map[string]any{"user": "bad", "pass": "<redacted>"},
		http.StatusBadRequest)
	internalUserRequest(t, client, http.MethodPost, "add", map[string]any{"unknown": true}, http.StatusBadRequest)
	internalUserRequest(t, client, http.MethodPost, "replace/"+id.String(), map[string]any{
		"user": "carol",
	}, http.StatusOK)
	require.Empty(t, p.conf.Load().AuthInternalUsers[2].Pass)
	require.Empty(t, p.conf.Load().AuthInternalUsers[2].Permissions)
	internalUserRequest(t, client, http.MethodPatch, "patch/"+id.String(), map[string]any{"unknown": true},
		http.StatusBadRequest)
	internalUserRequest(t, client, http.MethodGet, "get/invalid", nil, http.StatusBadRequest)
	internalUserRequest(t, client, http.MethodGet, "get/"+uuid.NewString(), nil, http.StatusNotFound)
	internalUserRequest(t, client, http.MethodPatch, "patch/"+uuid.NewString(), map[string]any{}, http.StatusNotFound)
	internalUserRequest(t, client, http.MethodPost, "replace/"+uuid.NewString(), user, http.StatusNotFound)
	internalUserRequest(t, client, http.MethodDelete, "delete/"+uuid.NewString(), nil, http.StatusNotFound)

	internalUserRequest(t, client, http.MethodDelete, "delete/"+firstID.String(), nil, http.StatusOK)
	items = internalUserList(t, client)
	require.Len(t, items, 2)
	require.Equal(t, secondID, apiMapUUID(t, items[0].(map[string]any), "id"))
	require.Equal(t, id, apiMapUUID(t, items[1].(map[string]any), "id"))
	internalUserRequest(t, client, http.MethodDelete, "delete/"+id.String(), nil, http.StatusOK)
	internalUserRequest(t, client, http.MethodGet, "get/"+id.String(), nil, http.StatusNotFound)
}

func TestAPIConfigInternalUsersReconciliation(t *testing.T) {
	p, ok := newInstance(t, "api: yes\n")
	require.True(t, ok)
	defer p.Close()

	tr := &http.Transport{}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}

	firstID := apiMapUUID(t, internalUserList(t, client)[0].(map[string]any), "id")
	httpRequest(t, client, http.MethodPatch, "http://localhost:9997/v3/config/global/patch",
		map[string]any{"writeQueueSize": 1024}, nil)
	require.Eventually(t, func() bool {
		return p.conf.Load().WriteQueueSize == 1024
	}, time.Second, 10*time.Millisecond)
	require.Equal(t, firstID, apiMapUUID(t, internalUserList(t, client)[0].(map[string]any), "id"))

	httpRequest(t, client, http.MethodPatch, "http://localhost:9997/v3/config/global/patch",
		map[string]any{"authInternalUsers": []any{map[string]any{
			"user": "new", "pass": "password", "permissions": []any{map[string]any{"action": "api"}},
		}}}, nil)
	require.Eventually(t, func() bool {
		return len(p.conf.Load().AuthInternalUsers) == 1
	}, time.Second, 10*time.Millisecond)
	items := p.APIConfigInternalUsersSnapshot()
	require.Len(t, items, 1)
	require.NotEqual(t, firstID, items[0].ID)

	_, authErr := p.authManager.Authenticate(&auth.Request{
		Action:      conf.AuthActionAPI,
		IP:          net.ParseIP("127.0.0.1"),
		Credentials: &auth.Credentials{},
	})
	require.Error(t, authErr)
}
