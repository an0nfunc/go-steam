/*
Wrapper around the HTTP trading api for type safety 'n' stuff.
*/
package tradeapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Philipp15b/go-steam/economy/inventory"
	"github.com/Philipp15b/go-steam/netutil"
	"github.com/Philipp15b/go-steam/steamid"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

const tradeUrl = "http://steamcommunity.com/trade/%d/"
const cookiePath = "http://steamcommunity.com/"

type Trade struct {
	client *http.Client
	other  steamid.SteamId

	LogPos  uint // not automatically updated
	Version uint // Incremented for each item change by Steam; not automatically updated.

	// the `sessionid` cookie is sent as a parameter/POST data for CSRF protection.
	sessionId string
	baseUrl   string
}

// Creates a new Trade based on the given cookies `sessionid` and `steamLogin` and the trade partner's Steam ID.
func New(sessionId, steamLogin string, other steamid.SteamId) *Trade {
	client := new(http.Client)
	client.Timeout = 10 * time.Second

	t := &Trade{
		client:    client,
		other:     other,
		sessionId: sessionId,
		baseUrl:   fmt.Sprintf(tradeUrl, other),
		Version:   1,
	}
	t.setCookies(sessionId, steamLogin)
	return t
}

type Main struct {
	PartnerOnProbation bool
}

var onProbationRegex = regexp.MustCompile(`var g_bTradePartnerProbation = (\w+);`)

// Fetches the main HTML page and parses it. Thread-safe.
func (t *Trade) GetMain() (*Main, error) {
	resp, err := t.client.Get(t.baseUrl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	match := onProbationRegex.FindSubmatch(body)
	if len(match) == 0 {
		return nil, errors.New("tradeapi.GetMain: Could not find probation info")
	}

	return &Main{
		string(match[1]) == "true",
	}, nil
}

func (t *Trade) GetStatus() (*Status, error) {
	return t.postWithStatus(t.baseUrl+"tradestatus/", map[string]string{
		"sessionid": t.sessionId,
		"logpos":    strconv.FormatUint(uint64(t.LogPos), 10),
		"version":   strconv.FormatUint(uint64(t.Version), 10),
	})
}

func (t *Trade) runInventoryRequest(req *http.Request) (*inventory.PartialInventory, error) {
	req.Header.Add("Referer", t.baseUrl)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	inv := new(inventory.PartialInventory)
	err = json.NewDecoder(resp.Body).Decode(inv)
	if err != nil {
		return nil, err
	}
	return inv, nil
}

// Thread-safe.
func (t *Trade) GetForeignInventory(contextId uint64, appId uint32, start *uint) (*inventory.PartialInventory, error) {
	data := map[string]string{
		"sessionid": t.sessionId,
		"steamid":   fmt.Sprintf("%d", t.other),
		"contextid": strconv.FormatUint(contextId, 10),
		"appid":     strconv.FormatUint(uint64(appId), 10),
	}
	if start != nil {
		data["start"] = strconv.FormatUint(uint64(*start), 10)
	}

	req, err := http.NewRequest("GET", t.baseUrl+"foreigninventory?"+netutil.ToUrlValues(data).Encode(), nil)
	if err != nil {
		panic(err)
	}
	return t.runInventoryRequest(req)
}

// Thread-safe.
func (t *Trade) GetOwnInventory(contextId uint64, appId uint32, start *uint) (*inventory.PartialInventory, error) {
	// TODO: the "trading" parameter can be left off to return non-tradable items too
	url := fmt.Sprintf("http://steamcommunity.com/my/inventory/json/%d/%d?trading=1", appId, contextId)
	if start != nil {
		url += "&start=" + strconv.FormatUint(uint64(*start), 10)
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		panic(err)
	}
	return t.runInventoryRequest(req)
}

func (t *Trade) Chat(message string) (*Status, error) {
	return t.postWithStatus(t.baseUrl+"chat", map[string]string{
		"sessionid": t.sessionId,
		"logpos":    strconv.FormatUint(uint64(t.LogPos), 10),
		"version":   strconv.FormatUint(uint64(t.Version), 10),
		"message":   message,
	})
}

func (t *Trade) AddItem(slot uint, itemId, contextId uint64, appId uint32) (*Status, error) {
	return t.postWithStatus(t.baseUrl+"additem", map[string]string{
		"sessionid": t.sessionId,
		"slot":      strconv.FormatUint(uint64(slot), 10),
		"itemid":    strconv.FormatUint(itemId, 10),
		"contextid": strconv.FormatUint(contextId, 10),
		"appid":     strconv.FormatUint(uint64(appId), 10),
	})
}

func (t *Trade) RemoveItem(slot uint, itemId, contextId uint64, appId uint32) (*Status, error) {
	return t.postWithStatus(t.baseUrl+"removeitem", map[string]string{
		"sessionid": t.sessionId,
		"slot":      strconv.FormatUint(uint64(slot), 10),
		"itemid":    strconv.FormatUint(itemId, 10),
		"contextid": strconv.FormatUint(contextId, 10),
		"appid":     strconv.FormatUint(uint64(appId), 10),
	})
}

func (t *Trade) SetCurrency(amount uint, currencyId, contextId uint64, appId uint32) (*Status, error) {
	return t.postWithStatus(t.baseUrl+"setcurrency", map[string]string{
		"sessionid":  t.sessionId,
		"amount":     strconv.FormatUint(uint64(amount), 10),
		"currencyid": strconv.FormatUint(uint64(currencyId), 10),
		"contextid":  strconv.FormatUint(contextId, 10),
		"appid":      strconv.FormatUint(uint64(appId), 10),
	})
}

func (t *Trade) SetReady(ready bool) (*Status, error) {
	return t.postWithStatus(t.baseUrl+"toggleready", map[string]string{
		"sessionid": t.sessionId,
		"version":   strconv.FormatUint(uint64(t.Version), 10),
		"ready":     fmt.Sprint(ready),
	})
}

func (t *Trade) Confirm() (*Status, error) {
	return t.postWithStatus(t.baseUrl+"confirm", map[string]string{
		"sessionid": t.sessionId,
		"version":   strconv.FormatUint(uint64(t.Version), 10),
	})
}

func (t *Trade) Cancel() (*Status, error) {
	return t.postWithStatus(t.baseUrl+"cancel", map[string]string{
		"sessionid": t.sessionId,
	})
}

func isSuccess(v interface{}) bool {
	if m, ok := v.(map[string]interface{}); ok {
		return m["success"] == true
	}
	return false
}