package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"
)

// Policy represents a governance policy
type Policy struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   PolicyMetadata    `json:"metadata"`
	Spec       PolicySpec        `json:"spec"`
}

type PolicyMetadata struct {
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Severity    string            `json:"severity"`
	Labels      map[string]string `json:"labels,omitempty"`
	CreatedAt   time.Time         `json:"createdAt,omitempty"`
}

type PolicySpec struct {
	TargetResource string      `json:"targetResource"`
	Rules          []Rule      `json:"rules"`
	Remediation    Remediation `json:"remediation,omitempty"`
}

type Rule struct {
	Name      string `json:"name"`
	Condition string `json:"condition"`
	Message   string `json:"message,omitempty"`
}

type Remediation struct {
	Type     string `json:"type"`
	Template string `json:"template,omitempty"`
}

// EvaluationResult represents the result of evaluating a resource
type EvaluationResult struct {
	ResourceID  string          `json:"resourceId"`
	EvaluatedAt time.Time       `json:"evaluatedAt"`
	Compliant   bool            `json:"compliant"`
	Violations  []Violation     `json:"violations,omitempty"`
	Metrics     EvaluationMetrics `json:"metrics,omitempty"`
}

type Violation struct {
	PolicyID   string `json:"policyId"`
	RuleName   string `json:"ruleName"`
	Message    string `json:"message"`
	Severity   string `json:"severity"`
	Resource   string `json:"resource"`
}

type EvaluationMetrics struct {
	TotalPolicies   int `json:"totalPolicies"`
	EvaluatedRules  int `json:"evaluatedRules"`
	PassedRules     int `json:"passedRules"`
	FailedRules     int `json:"failedRules"`
	EvaluationTimeMs int64 `json:"evaluationTimeMs"`
}

// RulesEngine is the main engine for evaluating policies
type RulesEngine struct {
	policies  map[string]Policy
	validator *PolicyValidator
}

func NewRulesEngine() *RulesEngine {
	return &RulesEngine{
		policies:  make(map[string]Policy),
		validator: NewPolicyValidator(),
	}
}

func (e *RulesEngine) RegisterPolicy(policy Policy) error {
	if err := e.validator.Validate(policy); err != nil {
		return fmt.Errorf("invalid policy: %v", err)
	}
	
	e.policies[policy.Metadata.Name] = policy
	log.Printf("Registered policy: %s (severity: %s)", policy.Metadata.Name, policy.Metadata.Severity)
	return nil
}

func (e *RulesEngine) EvaluateResource(resource map[string]interface{}, context map[string]string) EvaluationResult {
	startTime := time.Now()
	result := EvaluationResult{
		ResourceID:  fmt.Sprintf("%v", resource["id"]),
		EvaluatedAt: time.Now(),
		Compliant:   true,
		Violations:  []Violation{},
		Metrics: EvaluationMetrics{
			TotalPolicies: len(e.policies),
		},
	}
	
	for _, policy := range e.policies {
		// Check if policy applies to this resource type
		resourceType, ok := resource["type"].(string)
		if !ok || resourceType != policy.Spec.TargetResource {
			continue
		}
		
		for _, rule := range policy.Spec.Rules {
			result.Metrics.EvaluatedRules++
			
			// In a real implementation, this would evaluate the JSONPath condition
			compliant := e.evaluateRule(rule.Condition, resource, context)
			
			if !compliant {
				result.Compliant = false
				result.Violations = append(result.Violations, Violation{
					PolicyID: policy.Metadata.Name,
					RuleName: rule.Name,
					Message:  rule.Message,
					Severity: policy.Metadata.Severity,
					Resource: fmt.Sprintf("%v", resource["id"]),
				})
				result.Metrics.FailedRules++
			} else {
				result.Metrics.PassedRules++
			}
		}
	}
	
	result.Metrics.EvaluationTimeMs = time.Since(startTime).Milliseconds()
	return result
}

func (e *RulesEngine) evaluateRule(condition string, resource map[string]interface{}, context map[string]string) bool {
	// Simplified evaluation - in production, use a JSONPath library
	// This is a placeholder for actual evaluation logic
	return true
}

// PolicyValidator validates policies
type PolicyValidator struct{}

func NewPolicyValidator() *PolicyValidator {
	return &PolicyValidator{}
}

func (v *PolicyValidator) Validate(policy Policy) error {
	if policy.APIVersion == "" {
		return fmt.Errorf("apiVersion is required")
	}
	if policy.Kind != "Policy" {
		return fmt.Errorf("kind must be 'Policy'")
	}
	if policy.Metadata.Name == "" {
		return fmt.Errorf("metadata.name is required")
	}
	if policy.Metadata.Severity == "" {
		return fmt.Errorf("metadata.severity is required")
	}
	if policy.Spec.TargetResource == "" {
		return fmt.Errorf("spec.targetResource is required")
	}
	if len(policy.Spec.Rules) == 0 {
		return fmt.Errorf("spec.rules must contain at least one rule")
	}
	
	for i, rule := range policy.Spec.Rules {
		if rule.Condition == "" {
			return fmt.Errorf("rule[%d].condition is required", i)
		}
	}
	
	return nil
}

// CLI Commands
func main() {
	registerCmd := flag.NewFlagSet("register", flag.ExitOnError)
	registerFile := registerCmd.String("file", "", "Policy file to register")
	
	evaluateCmd := flag.NewFlagSet("evaluate", flag.ExitOnError)
	evaluateResource := evaluateCmd.String("resource", "", "Resource file to evaluate")
	evaluateContext := evaluateCmd.String("context", "", "Evaluation context")
	
	listCmd := flag.NewFlagSet("list", flag.ExitOnError)
	
	if len(os.Args) < 2 {
		fmt.Println("Expected 'register', 'evaluate', or 'list' subcommands")
		os.Exit(1)
	}
	
	engine := NewRulesEngine()
	
	switch os.Args[1] {
	case "register":
		registerCmd.Parse(os.Args[2:])
		if *registerFile == "" {
			log.Fatal("--file flag is required")
		}
		
		data, err := os.ReadFile(*registerFile)
		if err != nil {
			log.Fatalf("Failed to read policy file: %v", err)
		}
		
		var policy Policy
		if err := json.Unmarshal(data, &policy); err != nil {
			log.Fatalf("Failed to parse policy: %v", err)
		}
		
		if err := engine.RegisterPolicy(policy); err != nil {
			log.Fatalf("Failed to register policy: %v", err)
		}
		
		fmt.Printf("✓ Policy '%s' registered successfully\n", policy.Metadata.Name)
		
	case "evaluate":
		evaluateCmd.Parse(os.Args[2:])
		if *evaluateResource == "" {
			log.Fatal("--resource flag is required")
		}
		
		data, err := os.ReadFile(*evaluateResource)
		if err != nil {
			log.Fatalf("Failed to read resource file: %v", err)
		}
		
		var resource map[string]interface{}
		if err := json.Unmarshal(data, &resource); err != nil {
			log.Fatalf("Failed to parse resource: %v", err)
		}
		
		context := make(map[string]string)
		if *evaluateContext != "" {
			// Parse context key=value pairs
			// Simplified parsing
		}
		
		result := engine.EvaluateResource(resource, context)
		
		output, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(output))
		
	case "list":
		listCmd.Parse(os.Args[2:])
		fmt.Println("Registered Policies:")
		for name, policy := range engine.policies {
			fmt.Printf("  - %s (severity: %s)\n", name, policy.Metadata.Severity)
		}
		
	default:
		fmt.Println("Expected 'register', 'evaluate', or 'list' subcommands")
		os.Exit(1)
	}
}
