package main

import (
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "log/slog"
 "net"
 "net/http"
 "os"
 "os/signal"
 "strings"
 "syscall"
 "time"
)

type config struct { token, account, app, policy, ipURL string; interval time.Duration; dry bool }
type apiResponse struct { Success bool `json:"success"`; Errors []struct {Code int `json:"code"`; Message string `json:"message"`} `json:"errors"`; Result json.RawMessage `json:"result"` }
type policy struct { ID string `json:"id"`; Name string `json:"name"`; Decision string `json:"decision"`; Include []json.RawMessage `json:"include"`; Exclude []json.RawMessage `json:"exclude,omitempty"`; Require []json.RawMessage `json:"require,omitempty"`; Precedence int `json:"precedence"`; PurposeJustificationRequired bool `json:"purpose_justification_required"`; ApprovalRequired bool `json:"approval_required"` }

func required(name string) string { v:=strings.TrimSpace(os.Getenv(name)); if v=="" {slog.Error("missing environment variable", "name",name); os.Exit(2)}; return v }
func load() config { c:=config{token:required("CF_API_TOKEN"),account:required("CF_ACCOUNT_ID"),app:strings.TrimSpace(os.Getenv("CF_APP_ID")),policy:required("CF_POLICY_ID"),ipURL:env("IP_CHECK_URL","https://api.ipify.org"),interval:5*time.Minute,dry:strings.EqualFold(os.Getenv("DRY_RUN"),"true")}; if v:=os.Getenv("CHECK_INTERVAL");v!="" {d,e:=time.ParseDuration(v);if e!=nil||d<time.Minute {slog.Error("CHECK_INTERVAL must be >= 1m", "value",v);os.Exit(2)};c.interval=d};return c }
func env(k, fallback string) string {if s:=strings.TrimSpace(os.Getenv(k));s!="" {return s};return fallback}
func publicIP(ctx context.Context, client *http.Client, url string)(string,error){req,e:=http.NewRequestWithContext(ctx,"GET",url,nil);if e!=nil{return "",e};res,e:=client.Do(req);if e!=nil{return "",e};defer res.Body.Close();if res.StatusCode!=200{return "",fmt.Errorf("IP endpoint returned %d",res.StatusCode)};b,e:=io.ReadAll(io.LimitReader(res.Body,128));if e!=nil{return "",e};ip:=net.ParseIP(strings.TrimSpace(string(b)));if ip==nil||ip.To4()==nil{return "",errors.New("IP endpoint did not return an IPv4 address")};return ip.String(),nil}
func api(ctx context.Context, client *http.Client, c config, method, endpoint string, body io.Reader)(json.RawMessage,error){req,e:=http.NewRequestWithContext(ctx,method,"https://api.cloudflare.com/client/v4"+endpoint,body);if e!=nil{return nil,e};req.Header.Set("Authorization","Bearer "+c.token);if body!=nil {req.Header.Set("Content-Type","application/json")};res,e:=client.Do(req);if e!=nil{return nil,e};defer res.Body.Close();b,e:=io.ReadAll(io.LimitReader(res.Body,1<<20));if e!=nil{return nil,e};var out apiResponse;if e:=json.Unmarshal(b,&out);e!=nil{return nil,fmt.Errorf("unexpected API response (%d): %w",res.StatusCode,e)};if !out.Success||res.StatusCode<200||res.StatusCode>=300 {return nil,fmt.Errorf("Cloudflare API status %d: %+v",res.StatusCode,out.Errors)};return out.Result,nil}
func policyEndpoint(c config) string {if c.app==""{return fmt.Sprintf("/accounts/%s/access/policies/%s",c.account,c.policy)};return fmt.Sprintf("/accounts/%s/access/apps/%s/policies/%s",c.account,c.app,c.policy)}
func selectorIP(raw json.RawMessage)(string,bool){var obj map[string]json.RawMessage;if json.Unmarshal(raw,&obj)!=nil{return "",false};v,ok:=obj["ip"];if !ok{return "",false};var s struct{IP string `json:"ip"`};if json.Unmarshal(v,&s)!=nil{return "",false};return s.IP,s.IP!=""}
func syncOnce(ctx context.Context, client *http.Client, c config) error {ip,e:=publicIP(ctx,client,c.ipURL);if e!=nil{return fmt.Errorf("detect IP: %w",e)};endpoint:=policyEndpoint(c);raw,e:=api(ctx,client,c,"GET",endpoint,nil);if e!=nil{return fmt.Errorf("read policy: %w",e)};var p policy;if e:=json.Unmarshal(raw,&p);e!=nil{return e};if p.Decision!="bypass" {return fmt.Errorf("refusing to modify policy %q: decision must be bypass",p.Decision)}
 // A dedicated policy with exactly one IP selector is required to avoid accidentally deleting other rules.
 if len(p.Include)!=1{return fmt.Errorf("refusing to modify policy: expected exactly one Include selector, found %d",len(p.Include))};old,ok:=selectorIP(p.Include[0]);if !ok{return errors.New("refusing to modify policy: Include selector must be an IP range")};newCIDR:=ip+"/32";if old==newCIDR||old==ip {slog.Info("IP unchanged", "ip",newCIDR,"policy",p.Name);return nil};slog.Info("IP changed", "previous",old,"current",newCIDR,"policy",p.Name,"dry_run",c.dry);if c.dry{return nil}
 // Preserve the entire policy JSON, modifying only the IP selector. Unknown API fields are retained.
 var full map[string]json.RawMessage;if e:=json.Unmarshal(raw,&full);e!=nil{return e};selector,_:=json.Marshal(map[string]any{"ip":map[string]string{"ip":newCIDR}});include,_:=json.Marshal([]json.RawMessage{selector});full["include"]=include
 // Strip read-only fields; use only documented writable fields to avoid Cloudflare rejecting PUT.
 writable:=map[string]bool{"name":true,"decision":true,"include":true,"exclude":true,"require":true,"precedence":true,"purpose_justification_required":true,"approval_required":true,"session_duration":true,"isolation_required":true,"purpose_justification_prompt":true,"approval_groups":true,"app_count":false}
 // Reusable policies have no precedence of their own; it is set per application.
 if c.app=="" {delete(writable,"precedence")}
 payload:=map[string]json.RawMessage{};for k,v:=range full {if writable[k]{payload[k]=v}};data,e:=json.Marshal(payload);if e!=nil{return e};_,e=api(ctx,client,c,"PUT",endpoint,strings.NewReader(string(data)));if e!=nil{return fmt.Errorf("update policy: %w",e)};slog.Info("Access bypass IP updated", "ip",newCIDR,"policy",p.Name);return nil}
func main(){slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout,nil)));c:=load();client:=&http.Client{Timeout:15*time.Second};ctx,stop:=signal.NotifyContext(context.Background(),syscall.SIGINT,syscall.SIGTERM);defer stop();run:=func(){rctx,cancel:=context.WithTimeout(ctx,40*time.Second);defer cancel();if e:=syncOnce(rctx,client,c);e!=nil{slog.Error("sync failed", "error",e)}};slog.Info("starting", "interval",c.interval.String(),"dry_run",c.dry,"reusable_policy",c.app=="");run();ticker:=time.NewTicker(c.interval);defer ticker.Stop();for {select{case <-ctx.Done():slog.Info("stopped");return;case <-ticker.C:run()}}}
