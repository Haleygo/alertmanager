// Copyright 2018 Prometheus Team
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cli

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/alecthomas/kingpin/v2"

	"github.com/prometheus/alertmanager/api/v2/client/alert"
	"github.com/prometheus/alertmanager/api/v2/models"
	"github.com/prometheus/alertmanager/cli/format"
	"github.com/prometheus/alertmanager/matchers/compat"
	"github.com/prometheus/alertmanager/pkg/labels"
)

type alertQueryCmd struct {
	inhibited, silenced, active, unprocessed bool
	receiver                                 string
	matcherGroups                            []string
}

const alertQueryHelp = `View and search through current alerts.

Amtool has a simplified prometheus query syntax, but contains robust support for
bash variable expansions. The non-option section of arguments constructs a list
of "Matcher Groups" that will be used to filter your query. The following
examples will attempt to show this behaviour in action:

amtool alert query alertname=foo node=bar

	This query will match all alerts with the alertname=foo and node=bar label
	value pairs set.

amtool alert query foo node=bar

	If alertname is omitted and the first argument does not contain a '=' or a
	'=~' then it will be assumed to be the value of the alertname pair.

amtool alert query 'alertname=~foo.*'

	As well as direct equality, regex matching is also supported. The '=~' syntax
	(similar to prometheus) is used to represent a regex match. Regex matching
	can be used in combination with a direct match.

Amtool supports several flags for filtering the returned alerts by state
(inhibited, silenced, active, unprocessed). If none of these flags is given,
only active alerts are returned.
`

func configureQueryAlertsCmd(cc *kingpin.CmdClause) {
	var (
		a        = &alertQueryCmd{}
		queryCmd = cc.Command("query", alertQueryHelp).Default()
	)
	queryCmd.Flag("inhibited", "Show inhibited alerts").Short('i').BoolVar(&a.inhibited)
	queryCmd.Flag("silenced", "Show silenced alerts").Short('s').BoolVar(&a.silenced)
	queryCmd.Flag("active", "Show active alerts").Short('a').BoolVar(&a.active)
	queryCmd.Flag("unprocessed", "Show unprocessed alerts").Short('u').BoolVar(&a.unprocessed)
	queryCmd.Flag("receiver", "Show alerts matching receiver (Supports regex syntax)").Short('r').StringVar(&a.receiver)
	queryCmd.Arg("matcher-groups", "Query filter").StringsVar(&a.matcherGroups)
	queryCmd.Action(execWithTimeout(a.queryAlerts))
}

func (a *alertQueryCmd) queryAlerts(ctx context.Context, _ *kingpin.ParseContext) error {
	if len(a.matcherGroups) > 0 {
		// Attempt to parse the first argument. If the parser fails
		// then we likely don't have a (=|=~|!=|!~) so lets assume that
		// the user wants alertname=<arg> and prepend `alertname=` to
		// the front.
		m := a.matcherGroups[0]
		_, err := compat.Matcher(m, "cli")
		if err != nil {
			a.matcherGroups[0] = fmt.Sprintf("alertname=%s", strconv.Quote(m))
		}
	}

	// If no selector was passed, default to showing active alerts.
	if !a.silenced && !a.inhibited && !a.active && !a.unprocessed {
		a.active = true
	}

	alertParams := alert.NewGetAlertsParams().WithContext(ctx).
		WithActive(&a.active).
		WithInhibited(&a.inhibited).
		WithSilenced(&a.silenced).
		WithUnprocessed(&a.unprocessed).
		WithReceiver(&a.receiver).
		WithFilter(a.matcherGroups)

	amclient := NewAlertmanagerClient(alertmanagerURL)

	getOk, err := amclient.Alert.GetAlerts(alertParams)
	if err != nil {
		return err
	}

	psils, err := amclient.Silence.GetSilences(nil)
	if err != nil {
		return fmt.Errorf("error when list silences: %v", err)
	}
	silenceMap := make(map[string]*models.GettableSilence)
	silenceMatcherMap := make(map[string][]*labels.Matcher)
	for _, sil := range psils.Payload {
		if *sil.Status.State != "expired" {
			continue
		}
		silenceMap[*sil.ID] = sil
		ms := make([]*labels.Matcher, 0, len(sil.Matchers))
		for _, v := range sil.Matchers {
			var tt labels.MatchType
			if v.IsEqual != nil {
				if *v.IsEqual {
					if *v.IsRegex {
						tt = labels.MatchRegexp
					} else {
						tt = labels.MatchEqual
					}
				} else {
					if *v.IsRegex {
						tt = labels.MatchNotRegexp
					} else {
						tt = labels.MatchNotEqual
					}
				}
			}
			nm, err := labels.NewMatcher(tt, *v.Name, *v.Value)
			if err != nil {
				return fmt.Errorf("failed to new matcher: %v", err)
			}
			ms = append(ms, nm)
		}
		silenceMatcherMap[*sil.ID] = ms
	}

	for _, alert := range getOk.Payload {
		sms := make(map[string]string)
		for k, v := range alert.Alert.Labels {
			sms[k] = string(v)
		}

		var matches []*models.GettableSilence
		for id, ms := range silenceMatcherMap {
			if matchFilterLabels(ms, sms) {
				matches = append(matches, silenceMap[id])
			}
		}
		sort.Slice(matches, func(i, j int) bool {
			return time.Time(*matches[i].StartsAt).After(time.Time(*matches[j].StartsAt))
		})

		for i, sil := range matches {
			alert.Labels[fmt.Sprintf("silenceID-%d", i)] = fmt.Sprintf("%s/#/silences/%s", alertmanagerURL.String(), *sil.ID)
		}
		alert.Annotations = nil
		alert.GeneratorURL = ""
	}

	formatter, found := format.Formatters[output]
	if !found {
		return errors.New("unknown output formatter")
	}
	return formatter.FormatAlerts(getOk.Payload)
}

func matchFilterLabels(matchers []*labels.Matcher, sms map[string]string) bool {
	for _, m := range matchers {
		v, prs := sms[m.Name]
		switch m.Type {
		case labels.MatchNotRegexp, labels.MatchNotEqual:
			if m.Value == "" && prs {
				continue
			}
			if !m.Matches(v) {
				return false
			}
		default:
			if m.Value == "" && !prs {
				continue
			}
			if !m.Matches(v) {
				return false
			}
		}
	}

	return true
}
