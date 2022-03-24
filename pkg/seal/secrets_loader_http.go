package seal

import (
	"fmt"
	"github.com/Azure/go-ntlmssp"
	"github.com/kluctl/kluctl/pkg/types"
	"github.com/kluctl/kluctl/pkg/utils"
	"github.com/kluctl/kluctl/pkg/utils/uo"
	"github.com/docker/distribution/registry/client/auth/challenge"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
)

func (s *SecretsLoader) doHttp(httpSource *types.SecretSourceHttp, username string, password string) (*http.Response, string, error) {
	client := &http.Client{
		Transport: ntlmssp.Negotiator{
			RoundTripper: &http.Transport{},
		},
	}

	method := "GET"
	if httpSource.Method != nil {
		method = *httpSource.Method
	}

	var reqBody io.Reader
	if httpSource.Body != nil {
		reqBody = strings.NewReader(*httpSource.Body)
	}

	req, err := http.NewRequest(method, httpSource.Url.String(), reqBody)
	if err != nil {
		return nil, "", err
	}

	if username != "" || password != "" {
		req.SetBasicAuth(username, password)
	}

	for k, v := range httpSource.Headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp, string(respBody), fmt.Errorf("http request to %s failed with status code %d", httpSource.Url.String(), resp.StatusCode)
	}

	return resp, string(respBody), nil
}

func (s *SecretsLoader) loadSecretsHttp(source *types.SecretSource) (*uo.UnstructuredObject, error) {
	resp, respBody, err := s.doHttp(source.Http, "", "")
	if err != nil {
		chgs := challenge.ResponseChallenges(resp)
		if len(chgs) == 0 {
			return nil, err
		}

		if len(chgs) != 1 {
			return nil, fmt.Errorf("only one challenge type supported at the moment")
		}

		if chgs[0].Scheme != "basic" {
			return nil, fmt.Errorf("only Basic challenge type supported at the moment")
		}

		realm, _ := chgs[0].Parameters["realm"]
		if realm == "" {
			realm = source.Http.Url.String()
		}

		credsKey := fmt.Sprintf("%s|%s", source.Http.Url.Host, realm)
		creds, ok := s.credentialsCache[credsKey]
		if !ok {
			username, password, err := utils.AskForCredentials(fmt.Sprintf("Please enter credentials for host '%s' and realm '%s'", source.Http.Url.Host, realm))
			if err != nil {
				return nil, err
			}
			creds = usernamePassword{
				username: username,
				password: password,
			}
			s.credentialsCache[credsKey] = creds
		}

		resp, respBody, err = s.doHttp(source.Http, creds.username, creds.password)
		if err != nil {
			return nil, err
		}
	}

	secrets, err := uo.FromString(respBody)
	if err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	if source.Http.JsonPath != nil {
		p, err := uo.NewMyJsonPath(*source.Http.JsonPath)
		if err != nil {
			return nil, err
		}
		x, ok, err := secrets.GetNestedString(p)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("%s not found in result from http request %s", *source.Http.JsonPath, source.Http.Url.String())
		}
		secrets, err = uo.FromString(x)
		if err != nil {
			return nil, err
		}
	}
	secrets, ok, err := secrets.GetNestedObject("secrets")
	if err != nil {
		return nil, err
	}
	if !ok {
		return uo.New(), nil
	}
	return secrets, nil
}
