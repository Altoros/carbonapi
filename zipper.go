package main

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"

	"github.com/go-graphite/carbonapi/expr"
	"github.com/go-graphite/carbonapi/util"
	pb "github.com/go-graphite/carbonzipper/carbonzipperpb3"
)

var errNoMetrics = errors.New("no metrics")

type unmarshaler interface {
	Unmarshal([]byte) error
}

type zipper struct {
	z      string
	client *http.Client
}

func (z zipper) Find(ctx context.Context, metric string) (pb.GlobResponse, error) {
	u, _ := url.Parse(z.z + "/metrics/find/")

	u.RawQuery = url.Values{
		"query":  []string{metric},
		"format": []string{"protobuf"},
	}.Encode()

	var pbresp pb.GlobResponse

	err := z.get(ctx, "Find", u, &pbresp)
	if err != nil {
		return pbresp, err
	}

	user := userFromContext(ctx)
	if user != nil {
		matches := make([]*pb.GlobMatch, 0, len(pbresp.Matches))
		for _, m := range pbresp.Matches {
			if !user.Can(m.Path) {
				//fmt.Printf("- %s\n", m.Path) // TODO: remove
				continue
			}

			//fmt.Printf("+ %s\n", m.Path) // TODO: remove
			matches = append(matches, m)
		}
		pbresp.Matches = matches
	}
	return pbresp, nil
}

func (z zipper) get(ctx context.Context, who string, u *url.URL, msg unmarshaler) error {
	request, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return fmt.Errorf("http.NewRequest: %+v", err)
	}

	request = util.MarshalCtx(ctx, request)

	resp, err := z.client.Do(request.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("http.Get: %+v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("ioutil.ReadAll: %+v", err)
	}

	err = msg.Unmarshal(body)
	if err != nil {
		return fmt.Errorf("proto.Unmarshal: %+v", err)
	}

	return nil
}

func (z zipper) Passthrough(ctx context.Context, metric string) ([]byte, error) {

	u, _ := url.Parse(z.z + metric)

	request, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("http.NewRequest: %+v", err)
	}
	request = util.MarshalCtx(ctx, request)

	resp, err := z.client.Do(request.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("http.Get: %+v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ioutil.ReadAll: %+v", err)
	}

	return body, nil
}

func (z zipper) Render(ctx context.Context, metric string, from, until int32) ([]*expr.MetricData, error) {
	var result []*expr.MetricData

	u, _ := url.Parse(z.z + "/render/")

	u.RawQuery = url.Values{
		"target": []string{metric},
		"format": []string{"protobuf"},
		"from":   []string{strconv.Itoa(int(from))},
		"until":  []string{strconv.Itoa(int(until))},
	}.Encode()

	var pbresp pb.MultiFetchResponse
	err := z.get(ctx, "Render", u, &pbresp)
	if err != nil {
		return result, err
	}

	if len(pbresp.Metrics) == 0 {
		return result, errNoMetrics
	}

	user := userFromContext(ctx)
	for _, m := range pbresp.Metrics {
		if user != nil && !user.Can(m.Name) {
			//fmt.Printf("- %s\n", m.Name) // TODO: remove
			continue
		}
		//fmt.Printf("+ %s\n", m.Name) // TODO: remove
		result = append(result, &expr.MetricData{FetchResponse: *m})
	}

	return result, nil
}
