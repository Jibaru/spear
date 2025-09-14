package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"reflect"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/sammwyy/spear/api"
)

// SMTPPlugin is the main plugin struct
type SMTPPlugin struct {
	api    api.CoreAPI
	logger api.Logger
	mutex  sync.RWMutex
}

// SMTPTriggerConfig represents the configuration for an SMTP trigger
type SMTPTriggerConfig struct {
	Host        string   `toml:"host"`         // SMTP server host
	Port        int      `toml:"port"`         // SMTP server port (default: 587)
	Username    string   `toml:"username"`     // SMTP username
	Password    string   `toml:"password"`     // SMTP password
	From        string   `toml:"from"`         // From email address
	To          []string `toml:"to"`           // Recipient email addresses
	CC          []string `toml:"cc"`           // CC email addresses
	BCC         []string `toml:"bcc"`          // BCC email addresses
	Subject     string   `toml:"subject"`      // Email subject template
	Template    string   `toml:"template"`     // Email body template
	UseStartTLS bool     `toml:"use_starttls"` // Use STARTTLS (default: true)
	UseTLS      bool     `toml:"use_tls"`      // Use TLS connection (default: false)
	Timeout     int      `toml:"timeout"`      // Connection timeout in seconds (default: 30)
	MaxRetries  int      `toml:"max_retries"`  // Maximum retry attempts (default: 3)
	RetryDelay  int      `toml:"retry_delay"`  // Delay between retries in seconds (default: 5)
}

// SMTPTrigger represents an instance of the SMTP trigger
type SMTPTrigger struct {
	id     string
	config SMTPTriggerConfig
	plugin *SMTPPlugin
	logger api.Logger
	mutex  sync.Mutex
}

// EmailData represents the data structure for email templating
type EmailData struct {
	TriggerID string                 `json:"trigger_id"`
	Timestamp string                 `json:"timestamp"`
	Args      map[string]interface{} `json:"args"`
}

// NewPlugin creates a new SMTP plugin instance
func NewPlugin() api.Plugin {
	return &SMTPPlugin{}
}

// Meta returns plugin metadata
func (p *SMTPPlugin) Meta() api.PluginMeta {
	return api.PluginMeta{
		ID:          "smtp",
		DisplayName: "SMTP Email Trigger",
		Author:      "Spear Team",
		Repository:  "https://github.com/sammwyy/spear",
		Description: "Provides SMTP email triggers to send alerts via email",
		Version:     "1.0.0",
	}
}

// Initialize initializes the plugin
func (p *SMTPPlugin) Initialize(apiInstance api.CoreAPI) error {
	p.api = apiInstance
	p.logger = apiInstance.GetLogger("smtp")
	p.logger.Info("SMTP plugin initialized")
	return nil
}

// Shutdown shuts down the plugin
func (p *SMTPPlugin) Shutdown() error {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.logger.Info("SMTP plugin shut down")
	return nil
}

// ValidateConfig validates the plugin configuration
func (p *SMTPPlugin) ValidateConfig(config interface{}) error {
	smtpConfig, ok := config.(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid config type for SMTP trigger")
	}

	// Check required fields
	if _, exists := smtpConfig["host"]; !exists {
		return fmt.Errorf("SMTP trigger config must specify 'host' parameter")
	}

	if _, exists := smtpConfig["from"]; !exists {
		return fmt.Errorf("SMTP trigger config must specify 'from' parameter")
	}

	if _, exists := smtpConfig["to"]; !exists {
		return fmt.Errorf("SMTP trigger config must specify 'to' parameter")
	}

	// Validate host
	host := fmt.Sprintf("%v", smtpConfig["host"])
	if host == "" {
		return fmt.Errorf("SMTP trigger 'host' parameter cannot be empty")
	}

	// Validate from address
	from := fmt.Sprintf("%v", smtpConfig["from"])
	if from == "" || !strings.Contains(from, "@") {
		return fmt.Errorf("SMTP trigger 'from' parameter must be a valid email address")
	}

	// Validate to addresses
	if toVal, exists := smtpConfig["to"]; exists {
		if toSlice, ok := toVal.([]interface{}); ok {
			if len(toSlice) == 0 {
				return fmt.Errorf("SMTP trigger 'to' parameter must contain at least one email address")
			}
			for _, email := range toSlice {
				emailStr := fmt.Sprintf("%v", email)
				if !strings.Contains(emailStr, "@") {
					return fmt.Errorf("invalid email address in 'to' list: %s", emailStr)
				}
			}
		} else {
			return fmt.Errorf("SMTP trigger 'to' parameter must be an array of email addresses")
		}
	}

	// Validate port range
	if portVal, exists := smtpConfig["port"]; exists {
		if port, ok := portVal.(int64); ok {
			if port < 1 || port > 65535 {
				return fmt.Errorf("SMTP trigger 'port' must be between 1 and 65535")
			}
		}
	}

	// Validate timeout
	if timeoutVal, exists := smtpConfig["timeout"]; exists {
		if timeout, ok := timeoutVal.(int64); ok && timeout <= 0 {
			return fmt.Errorf("SMTP trigger 'timeout' must be positive")
		}
	}

	// Validate max retries
	if maxRetriesVal, exists := smtpConfig["max_retries"]; exists {
		if maxRetries, ok := maxRetriesVal.(int64); ok && maxRetries < 0 {
			return fmt.Errorf("SMTP trigger 'max_retries' must be non-negative")
		}
	}

	// Validate retry delay
	if retryDelayVal, exists := smtpConfig["retry_delay"]; exists {
		if retryDelay, ok := retryDelayVal.(int64); ok && retryDelay <= 0 {
			return fmt.Errorf("SMTP trigger 'retry_delay' must be positive")
		}
	}

	return nil
}

// GetConfigSchema returns the configuration schema
func (p *SMTPPlugin) GetConfigSchema() interface{} {
	return SMTPTriggerConfig{}
}

// RegisterModules returns the modules provided by this plugin
func (p *SMTPPlugin) RegisterModules() []api.ModuleDefinition {
	return []api.ModuleDefinition{} // This plugin doesn't provide modules
}

// RegisterTriggers returns the triggers provided by this plugin
func (p *SMTPPlugin) RegisterTriggers() []api.TriggerDefinition {
	return []api.TriggerDefinition{
		{
			Name:        "send_email",
			Description: "Sends email alerts via SMTP",
			ConfigType:  reflect.TypeOf(SMTPTriggerConfig{}),
			Factory:     p.createSMTPTrigger,
		},
	}
}

// createSMTPTrigger creates a new SMTP trigger instance
func (p *SMTPPlugin) createSMTPTrigger(config interface{}) (api.TriggerInstance, error) {
	p.logger.Debug("Creating SMTP trigger with config", "config", config)

	configMap, ok := config.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid config format for SMTP trigger, expected map[string]interface{}, got %T", config)
	}

	p.logger.Debug("Config map contents", "map", configMap)

	// Parse configuration with defaults
	cfg := SMTPTriggerConfig{
		Port:        587,
		UseStartTLS: true,
		UseTLS:      false,
		Timeout:     30,
		MaxRetries:  3,
		RetryDelay:  5,
		Subject:     "Spear Security Alert - {{.Args.alert_type}}",
		Template:    "Security Alert: {{.Args.alert_type}}\n\nTimestamp: {{.Timestamp}}\nTrigger ID: {{.TriggerID}}\n\nEvent Details:\n{{range $key, $value := .Args}}  • {{$key}}: {{$value}}\n{{end}}\n---\nThis alert was generated by Spear Security Monitor.",
	}

	// Parse required fields
	if host, exists := configMap["host"]; exists {
		cfg.Host = fmt.Sprintf("%v", host)
	} else {
		return nil, fmt.Errorf("SMTP trigger config must specify 'host' parameter")
	}

	if from, exists := configMap["from"]; exists {
		cfg.From = fmt.Sprintf("%v", from)
	} else {
		return nil, fmt.Errorf("SMTP trigger config must specify 'from' parameter")
	}

	// Parse recipient lists
	if err := p.parseEmailList(configMap, "to", &cfg.To); err != nil {
		return nil, fmt.Errorf("error parsing 'to' addresses: %w", err)
	}
	if len(cfg.To) == 0 {
		return nil, fmt.Errorf("SMTP trigger config must specify at least one 'to' address")
	}

	p.parseEmailList(configMap, "cc", &cfg.CC)
	p.parseEmailList(configMap, "bcc", &cfg.BCC)

	// Parse optional fields
	if username, exists := configMap["username"]; exists {
		cfg.Username = fmt.Sprintf("%v", username)
	}

	if password, exists := configMap["password"]; exists {
		cfg.Password = fmt.Sprintf("%v", password)
	}

	if subject, exists := configMap["subject"]; exists {
		cfg.Subject = fmt.Sprintf("%v", subject)
	}

	if template, exists := configMap["template"]; exists {
		cfg.Template = fmt.Sprintf("%v", template)
	}

	if port, exists := configMap["port"]; exists {
		if p, ok := port.(int64); ok {
			cfg.Port = int(p)
		}
	}

	if useStartTLS, exists := configMap["use_starttls"]; exists {
		if tls, ok := useStartTLS.(bool); ok {
			cfg.UseStartTLS = tls
		}
	}

	if useTLS, exists := configMap["use_tls"]; exists {
		if tls, ok := useTLS.(bool); ok {
			cfg.UseTLS = tls
		}
	}

	if timeout, exists := configMap["timeout"]; exists {
		if t, ok := timeout.(int64); ok {
			cfg.Timeout = int(t)
		}
	}

	if maxRetries, exists := configMap["max_retries"]; exists {
		if mr, ok := maxRetries.(int64); ok {
			cfg.MaxRetries = int(mr)
		}
	}

	if retryDelay, exists := configMap["retry_delay"]; exists {
		if rd, ok := retryDelay.(int64); ok {
			cfg.RetryDelay = int(rd)
		}
	}

	p.logger.Info("Final SMTP trigger config",
		"host", cfg.Host,
		"port", cfg.Port,
		"from", cfg.From,
		"to_count", len(cfg.To),
		"cc_count", len(cfg.CC),
		"bcc_count", len(cfg.BCC),
		"use_starttls", cfg.UseStartTLS,
		"use_tls", cfg.UseTLS,
		"timeout", cfg.Timeout,
		"max_retries", cfg.MaxRetries)

	// Validate config
	if err := p.ValidateConfig(configMap); err != nil {
		return nil, err
	}

	// Create trigger instance
	trigger := &SMTPTrigger{
		id:     fmt.Sprintf("smtp_%d", time.Now().UnixNano()),
		config: cfg,
		plugin: p,
		logger: p.api.GetLogger(fmt.Sprintf("smtp.%s", cfg.Host)),
	}

	p.logger.Debug("Created SMTP trigger", "id", trigger.id, "host", cfg.Host)
	return trigger, nil
}

// parseEmailList parses a list of email addresses from config
func (p *SMTPPlugin) parseEmailList(configMap map[string]interface{}, key string, target *[]string) error {
	if val, exists := configMap[key]; exists {
		if slice, ok := val.([]interface{}); ok {
			*target = make([]string, len(slice))
			for i, email := range slice {
				(*target)[i] = fmt.Sprintf("%v", email)
			}
		} else {
			return fmt.Errorf("%s must be an array of email addresses", key)
		}
	}
	return nil
}

// SMTPTrigger methods

func (t *SMTPTrigger) ID() string {
	return t.id
}

func (t *SMTPTrigger) Execute(args map[string]interface{}) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	t.logger.Debug("Executing SMTP trigger", "args_count", len(args))

	// Create email data for templating
	emailData := EmailData{
		TriggerID: t.id,
		Timestamp: time.Now().Format("2006-01-02 15:04:05 MST"),
		Args:      args,
	}

	// Build email subject and body
	subject, err := t.processTemplate(t.config.Subject, emailData)
	if err != nil {
		return fmt.Errorf("failed to process subject template: %w", err)
	}

	body, err := t.processTemplate(t.config.Template, emailData)
	if err != nil {
		return fmt.Errorf("failed to process body template: %w", err)
	}

	// Send email with retries
	for attempt := 0; attempt <= t.config.MaxRetries; attempt++ {
		if attempt > 0 {
			t.logger.Debug("Retrying email send", "attempt", attempt)
			time.Sleep(time.Duration(t.config.RetryDelay) * time.Second)
		}

		err = t.sendEmail(subject, body)
		if err == nil {
			t.logger.Info("Email sent successfully",
				"to", t.config.To,
				"subject", subject,
				"attempt", attempt+1)
			return nil
		}

		t.logger.Error("Failed to send email",
			"attempt", attempt+1,
			"max_attempts", t.config.MaxRetries+1,
			"error", err)
	}

	return fmt.Errorf("failed to send email after %d attempts: %w", t.config.MaxRetries+1, err)
}

func (t *SMTPTrigger) GetArgumentSchema() map[string]api.ArgumentSpec {
	return map[string]api.ArgumentSpec{
		"alert_type": {
			Type:        "string",
			Required:    false,
			Description: "Type of security alert",
		},
		"*": {
			Type:        "any",
			Required:    false,
			Description: "Any arguments will be included in the email template",
		},
	}
}

// processTemplate processes a template string with the provided data using Go templates
func (t *SMTPTrigger) processTemplate(templateStr string, data EmailData) (string, error) {
	// Create a new template with the provided string
	tmpl, err := template.New("email").Parse(templateStr)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	// Execute the template with the data
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

// sendEmail sends an email using SMTP
func (t *SMTPTrigger) sendEmail(subject, body string) error {
	// Build server address
	serverAddr := fmt.Sprintf("%s:%d", t.config.Host, t.config.Port)

	// Prepare email message
	msg := t.buildEmailMessage(subject, body)

	// Collect all recipients
	var allRecipients []string
	allRecipients = append(allRecipients, t.config.To...)
	allRecipients = append(allRecipients, t.config.CC...)
	allRecipients = append(allRecipients, t.config.BCC...)

	// Connect and send
	if t.config.UseTLS {
		return t.sendEmailTLS(serverAddr, msg, allRecipients)
	} else {
		return t.sendEmailStartTLS(serverAddr, msg, allRecipients)
	}
}

// buildEmailMessage builds the email message with headers
func (t *SMTPTrigger) buildEmailMessage(subject, body string) []byte {
	var msg strings.Builder

	// Headers
	msg.WriteString(fmt.Sprintf("From: %s\r\n", t.config.From))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(t.config.To, ", ")))

	if len(t.config.CC) > 0 {
		msg.WriteString(fmt.Sprintf("Cc: %s\r\n", strings.Join(t.config.CC, ", ")))
	}

	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	msg.WriteString("\r\n")

	// Body
	msg.WriteString(body)

	return []byte(msg.String())
}

// sendEmailTLS sends email using direct TLS connection
func (t *SMTPTrigger) sendEmailTLS(serverAddr string, msg []byte, recipients []string) error {
	tlsConfig := &tls.Config{
		ServerName: t.config.Host,
	}

	// Create connection with timeout
	dialer := &net.Dialer{
		Timeout: time.Duration(t.config.Timeout) * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", serverAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to connect with TLS: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, t.config.Host)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %w", err)
	}
	defer client.Quit()

	return t.authenticateAndSend(client, msg, recipients)
}

// sendEmailStartTLS sends email using STARTTLS
func (t *SMTPTrigger) sendEmailStartTLS(serverAddr string, msg []byte, recipients []string) error {
	// Create connection with timeout
	dialer := &net.Dialer{
		Timeout: time.Duration(t.config.Timeout) * time.Second,
	}

	conn, err := dialer.Dial("tcp", serverAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server: %w", err)
	}

	client, err := smtp.NewClient(conn, t.config.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to create SMTP client: %w", err)
	}
	defer client.Quit()

	if t.config.UseStartTLS {
		tlsConfig := &tls.Config{
			ServerName: t.config.Host,
		}

		if err = client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("failed to start TLS: %w", err)
		}
	}

	return t.authenticateAndSend(client, msg, recipients)
}

// authenticateAndSend handles authentication and sending
func (t *SMTPTrigger) authenticateAndSend(client *smtp.Client, msg []byte, recipients []string) error {
	// Authenticate if credentials provided
	if t.config.Username != "" && t.config.Password != "" {
		auth := smtp.PlainAuth("", t.config.Username, t.config.Password, t.config.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}
	}

	// Set sender
	if err := client.Mail(t.config.From); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}

	// Set recipients
	for _, recipient := range recipients {
		if err := client.Rcpt(recipient); err != nil {
			return fmt.Errorf("failed to set recipient %s: %w", recipient, err)
		}
	}

	// Send message
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to get data writer: %w", err)
	}

	if _, err = writer.Write(msg); err != nil {
		writer.Close()
		return fmt.Errorf("failed to write message: %w", err)
	}

	return writer.Close()
}
