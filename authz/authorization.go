package authz

import (
	"encoding/json"
	"fmt"
	"log/syslog"
	"os"
	"path"
	"time"

	"github.com/Sirupsen/logrus"
	logrus_syslog "github.com/Sirupsen/logrus/hooks/syslog"
	"github.com/authz/core"
	"github.com/docker/docker/pkg/authorization"

	"github.com/docker/engine-api/types"

	//	"fmt"

	"github.com/docker/engine-api/client"
	"golang.org/x/net/context"
)

// BasicPolicy represent a single policy object that is evaluated in the authorization flow.
// Each policy object consists of multiple users and docker actions, where each user belongs to a single policy.
//
// The policies are evaluated according to the following flow:
//   For each policy object check
//      If the user belongs to the policy
//         If action in request in policy allow otherwise deny
//   If no appropriate policy found, return deny
//
// Remark: In basic flow, each user must have a unique policy.
// If a user is used by more than one policy, the results may be inconsistent
type BasicPolicy struct {
	Actions []string `json:"actions"` // Actions are the docker actions (mapped to authz terminology) that are allowed according to this policy
	// Action are are specified as regular expressions
	Users    []string `json:"users"`    // Users are the users for which this policy apply to
	Name     string   `json:"name"`     // Name is the policy name
	Readonly bool     `json:"readonly"` // Readonly indicates this policy only allow get commands
}

const (
	// AuditHookSyslog indicates logs are streamed  to local syslog
	AuditHookSyslog = "syslog"

	// AuditHookFile indicates logs are streamed  to local syslog
	AuditHookFile = "file"

	// AuditHookStdout indicates logs are streamed to stdout
	AuditHookStdout = ""
)

// defaultAuditLogPath is the file test hook log path
const defaultAuditLogPath = "/var/log/authz-broker.log"

type basicAuthorizer struct {
	settings *BasicAuthorizerSettings
	// policies []BasicPolicy
}

// BasicAuthorizerSettings provides settings for the basic authoerizer flow
type BasicAuthorizerSettings struct {
}

// NewBasicAuthZAuthorizer creates a new basic authorizer
func NewBasicAuthZAuthorizer(settings *BasicAuthorizerSettings) core.Authorizer {
	return &basicAuthorizer{settings: settings}
}

// Init loads the basic authz plugin configuration from disk
func (f *basicAuthorizer) Init() error {

	return nil
}

//AuthZTenantIDHeaderName - TenantId HTPP header name.
var AuthZTenantIDHeaderName = "X-Auth-Tenantid"

func (f *basicAuthorizer) AuthZReq(authZReq *authorization.Request) *authorization.Response {

	logrus.Infof("Received AuthZ request, method: '%s', url: '%s' , headers: '%s'", authZReq.RequestMethod, authZReq.RequestURI, authZReq.RequestHeaders)
	if authZReq.RequestHeaders[AuthZTenantIDHeaderName] == "" {
		return &authorization.Response{
			Allow: false,
			Msg:   fmt.Sprintf("No action allowed without tenant identification"),
		}
	}

	action, idOrName := core.ParseRoute(authZReq.RequestMethod, authZReq.RequestURI)

	//TODO - Actaully ban container create
	if action == core.ActionServiceCreate {
		return &authorization.Response{
			Allow: true,
			Msg:   fmt.Sprintf("OK for  (tenant: '%s' action: '%s')", authZReq.RequestHeaders[AuthZTenantIDHeaderName], action),
		}
	}
	if action == core.ActionContainerCreate {
		return &authorization.Response{
			Allow: false,
			Msg:   fmt.Sprintf("You are only allowed to create services"),
		}
	}
	//Check in my map
	if core.ID2TenantMap[idOrName] == authZReq.RequestHeaders[AuthZTenantIDHeaderName] ||
		core.ID2TenantMap[core.Name2TIDMap[idOrName+authZReq.RequestHeaders[AuthZTenantIDHeaderName]]] == authZReq.RequestHeaders[AuthZTenantIDHeaderName] {
		return &authorization.Response{
			Allow: true,
			Msg:   fmt.Sprintf("OK for  (tenant: '%s' action: '%s')", authZReq.RequestHeaders[AuthZTenantIDHeaderName], action),
		}
	}

	return &authorization.Response{
		Allow: false,
		Msg:   fmt.Sprintf("Not authorized for (tenant: '%s' action: '%s')", authZReq.RequestHeaders[AuthZTenantIDHeaderName], action),
	}
}

// AuthZRes always allow responses from server
func (f *basicAuthorizer) AuthZRes(authZReq *authorization.Request) *authorization.Response {
	action, _ := core.ParseRoute(authZReq.RequestMethod, authZReq.RequestURI)

	if action == core.ActionServiceCreate {

		var response interface{}
		err := json.Unmarshal(authZReq.ResponseBody, &response)
		if err != nil {
			logrus.Error(err)
			return &authorization.Response{Allow: false}
		}
		m := response.(map[string]interface{})

		if m["ID"] == nil {
			logrus.Error("Not good no container ID")
			return &authorization.Response{Allow: true}
		}
		srvID := m["ID"].(string) //panic when create fails!
		logrus.Info(authZReq.RequestHeaders[AuthZTenantIDHeaderName])
		if err == nil && action == core.ActionServiceCreate {
			core.ID2TenantMap[srvID] = authZReq.RequestHeaders[AuthZTenantIDHeaderName]
		}

		go func(id string, tenantID string) {
			defaultHeaders := map[string]string{"User-Agent": "engine-api-cli-1.0", AuthZTenantIDHeaderName: tenantID}
			cli, err := client.NewClient("unix:///var/run/docker.sock", "v1.24", nil, defaultHeaders)
			if err != nil {
				panic(err)
			}

			swrmService, byt, err := cli.ServiceInspectWithRaw(context.Background(), id)
			if err != nil {
				panic(err)
			}

			swrmService.Spec.Name = swrmService.Spec.Name + authZReq.RequestHeaders[AuthZTenantIDHeaderName]
			core.Name2TIDMap[swrmService.Spec.Name] = swrmService.ID
			logrus.Info("swrmService.Spec.Name")
			logrus.Info(swrmService)
			logrus.Info("swrmService.Spec.Name")
			s := string(byt[:len(byt)])
			logrus.Info(s)
			logrus.Info("swrmService.Spec.Name")
			t0 := time.Now()
			e1 := cli.ServiceUpdate(context.Background(), swrmService.ID, swrmService.Version, swrmService.Spec, types.ServiceUpdateOptions{})
			t1 := time.Now()
			d := t1.Sub(t0)
			logrus.Info(d)
			logrus.Error(e1)
		}(srvID, authZReq.RequestHeaders[AuthZTenantIDHeaderName])

	}
	return &authorization.Response{Allow: true}

}

// basicAuditor audit requset/response directly to standard output
type basicAuditor struct {
	logger   *logrus.Logger
	settings *BasicAuditorSettings
}

// NewBasicAuditor returns a new authz auditor that uses the specified logging hook (e.g., syslog or stdout)
func NewBasicAuditor(settings *BasicAuditorSettings) core.Auditor {
	b := &basicAuditor{settings: settings}
	return b
}

// BasicAuditorSettings are settings used by the basic auditor
type BasicAuditorSettings struct {
	LogHook string // LogHook is the log hook used to audit authorization data
	LogPath string // LogPath is the path to audit log file (if file hook is specified)
}

func (b *basicAuditor) AuditRequest(req *authorization.Request, pluginRes *authorization.Response) error {

	if req == nil {
		return fmt.Errorf("Authorization request is nil")
	}

	if pluginRes == nil {
		return fmt.Errorf("Authorization response is nil")
	}

	err := b.init()
	if err != nil {
		return err
	}
	// Default - file
	fields := logrus.Fields{
		"method": req.RequestMethod,
		"uri":    req.RequestURI,
		"user":   req.User,
		"allow":  pluginRes.Allow,
		"msg":    pluginRes.Msg,
	}

	if pluginRes != nil || pluginRes.Err != "" {
		fields["err"] = pluginRes.Err
	}

	b.logger.WithFields(fields).Info("Request")
	return nil
}

func (b *basicAuditor) AuditResponse(req *authorization.Request, pluginRes *authorization.Response) error {
	// Only log requests
	return nil
}

// init inits the auditor logger
func (b *basicAuditor) init() error {

	if b.settings == nil {
		return fmt.Errorf("Settings is not defeined")
	}

	if b.logger != nil {
		return nil
	}

	b.logger = logrus.New()
	b.logger.Formatter = &logrus.JSONFormatter{}

	switch b.settings.LogHook {
	case AuditHookSyslog:
		{
			hook, err := logrus_syslog.NewSyslogHook("", "", syslog.LOG_ERR, "authz")
			if err != nil {
				return err
			}
			b.logger.Hooks.Add(hook)
		}
	case AuditHookFile:
		{
			logPath := b.settings.LogPath
			if logPath == "" {
				logrus.Infof("Using default log file path '%s'", logPath)
				logPath = defaultAuditLogPath
			}

			os.MkdirAll(path.Dir(logPath), 0700)
			f, err := os.OpenFile(logPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0750)
			if err != nil {
				return err
			}
			b.logger.Out = f
		}
	case AuditHookStdout:
		{
			// Default - stdout
		}
	default:
		return fmt.Errorf("Wrong log hook value '%s'", b.settings.LogHook)
	}

	return nil
}
