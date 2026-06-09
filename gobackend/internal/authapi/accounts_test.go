package authapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zwarder/waf/gobackend/internal/auth"
)

func TestStashCodecRoundTrip(t *testing.T) {
	toks := []string{"v4.local.aaa", "v4.local.bbb"}
	enc := encodeStash(toks)
	assert.NotEmpty(t, enc)
	assert.NotContains(t, enc, ",")
	assert.NotContains(t, enc, ";")
	assert.Equal(t, toks, decodeStash(enc))
	assert.Nil(t, decodeStash(""))
	assert.Nil(t, decodeStash("@@bad@@"))
}

func TestPruneStashDropsInvalidDedupesExcludes(t *testing.T) {
	iss := auth.NewIssuer(testKey())
	svc := &Service{decoder: auth.NewDecoder(testKey())}
	t1, _ := iss.CreateSessionToken(1, "client", nil, nil)
	t2, _ := iss.CreateSessionToken(2, "client", nil, nil)
	t2dup, _ := iss.CreateSessionToken(2, "client", nil, nil)

	out := svc.pruneStash([]string{t1, "garbage", t2, t2dup}, 1)
	assert.Len(t, out, 1)
	uid, ok := svc.tokenUID(out[0])
	assert.True(t, ok)
	assert.Equal(t, int64(2), uid)
}
