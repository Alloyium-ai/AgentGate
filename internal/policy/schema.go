// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package policy

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed schema.v2.json
var schemaBytes []byte
var schemaOnce sync.Once
var compiledSchema *jsonschema.Schema
var compiledFileRules *jsonschema.Schema
var compiledNetworkSection *jsonschema.Schema
var compiledProgramsSection *jsonschema.Schema
var compiledSocketsSection *jsonschema.Schema
var compiledRuntimeSection *jsonschema.Schema
var compiledMemorySection *jsonschema.Schema
var schemaError error

// Schema returns a copy so API callers cannot alter the compiler's contract.
func Schema() json.RawMessage { return append(json.RawMessage(nil), schemaBytes...) }
func SchemaDigest() string    { sum := sha256.Sum256(schemaBytes); return hex.EncodeToString(sum[:]) }
func SelectedSchema() (map[string]any, error) {
	var root map[string]any
	if err := json.Unmarshal(schemaBytes, &root); err != nil {
		return nil, err
	}
	return schemaReference(root, "#/$defs/selected")
}
func APIContract() (map[string]any, error) {
	capabilities, err := CapabilityIDs()
	if err != nil {
		return nil, err
	}
	return map[string]any{"schema": Schema(), "schema_digest": SchemaDigest(), "compiler_version": CompilerVersion, "selected_profile": SelectedProfile, "kernel_profile": KernelProfile, "capability_ids": capabilities, "default": "deny", "admission_available": false, "compatibility_purpose": "inspection-only", "runtime_templates": []any{}, "inventory_pending": true}, nil
}
func validateSchema(value any) error {
	schemaOnce.Do(loadSchema)
	if schemaError != nil {
		return schemaError
	}
	if err := compiledSchema.Validate(value); err != nil {
		return fmt.Errorf("policy schema validation failed: %w", err)
	}
	return nil
}

// ValidateFileRules uses the shared schema for a compiler component.
// It does not validate or authorize a complete policy document.
func ValidateFileRules(rules []FileRule) error {
	schemaOnce.Do(loadSchema)
	if schemaError != nil {
		return schemaError
	}
	raw, err := json.Marshal(append([]FileRule{}, rules...))
	if err != nil {
		return err
	}
	value, err := parseValue(raw, "json")
	if err != nil {
		return err
	}
	if err = compiledFileRules.Validate(value); err != nil {
		return err
	}
	return validateFiles(Files{Rules: rules}, map[string]bool{})
}

// ValidateNetworkSection checks a private component against the shared contract.
// A valid section cannot authorize a full policy or qualify a target mechanism.
func ValidateNetworkSection(network Network) error {
	schemaOnce.Do(loadSchema)
	if schemaError != nil {
		return schemaError
	}
	network.Rules = append([]NetworkRule{}, network.Rules...)
	raw, err := json.Marshal(network)
	if err != nil {
		return err
	}
	value, err := parseValue(raw, "json")
	if err != nil {
		return err
	}
	if err = compiledNetworkSection.Validate(value); err != nil {
		return err
	}
	return validateNetwork(network, map[string]bool{})
}

// ValidateProgramsSection checks explicit executable permissions without admission.
func ValidateProgramsSection(programs Programs) error {
	schemaOnce.Do(loadSchema)
	if schemaError != nil {
		return schemaError
	}
	programs.Rules = append([]ProgramRule{}, programs.Rules...)
	raw, err := json.Marshal(programs)
	if err != nil {
		return err
	}
	value, err := parseValue(raw, "json")
	if err != nil {
		return err
	}
	if err = compiledProgramsSection.Validate(value); err != nil {
		return err
	}
	return validatePrograms(programs, map[string]bool{})
}

// ValidateSocketSection preserves the shared socket contract for private compilers.
func ValidateSocketSection(sockets SocketPolicy) error {
	schemaOnce.Do(loadSchema)
	if schemaError != nil {
		return schemaError
	}
	sockets.Rules = append([]SocketRule{}, sockets.Rules...)
	raw, err := json.Marshal(sockets)
	if err != nil {
		return err
	}
	value, err := parseValue(raw, "json")
	if err != nil {
		return err
	}
	if err = compiledSocketsSection.Validate(value); err != nil {
		return err
	}
	return validateSockets(sockets, map[string]bool{})
}

// ValidateMemorySection preserves explicit memory semantics for private compilers.
func ValidateMemorySection(memory MemoryPolicy) error {
	schemaOnce.Do(loadSchema)
	if schemaError != nil {
		return schemaError
	}
	raw, err := json.Marshal(memory)
	if err != nil {
		return err
	}
	value, err := parseValue(raw, "json")
	if err != nil {
		return err
	}
	return compiledMemorySection.Validate(value)
}

// ValidateRuntimeSection checks explicit runtime controls without granting admission.
func ValidateRuntimeSection(runtime Runtime) error {
	schemaOnce.Do(loadSchema)
	if schemaError != nil {
		return schemaError
	}
	raw, err := json.Marshal(runtime)
	if err != nil {
		return err
	}
	value, err := parseValue(raw, "json")
	if err != nil {
		return err
	}
	return compiledRuntimeSection.Validate(value)
}
func loadSchema() {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(schemaBytes))
	decoder.UseNumber()
	if schemaError = decoder.Decode(&value); schemaError != nil {
		return
	}
	compiler := jsonschema.NewCompiler()
	if schemaError = compiler.AddResource("urn:agentgate:policy:v2", value); schemaError != nil {
		return
	}
	compiledSchema, schemaError = compiler.Compile("urn:agentgate:policy:v2")
	if schemaError == nil {
		compiledFileRules, schemaError = compiler.Compile("urn:agentgate:policy:v2#/$defs/files/properties/rules")
	}
	if schemaError == nil {
		compiledNetworkSection, schemaError = compiler.Compile("urn:agentgate:policy:v2#/$defs/network")
	}
	if schemaError == nil {
		compiledProgramsSection, schemaError = compiler.Compile("urn:agentgate:policy:v2#/$defs/programs")
	}
	if schemaError == nil {
		compiledSocketsSection, schemaError = compiler.Compile("urn:agentgate:policy:v2#/$defs/sockets")
	}
	if schemaError == nil {
		compiledRuntimeSection, schemaError = compiler.Compile("urn:agentgate:policy:v2#/$defs/runtime")
	}
	if schemaError == nil {
		compiledMemorySection, schemaError = compiler.Compile("urn:agentgate:policy:v2#/$defs/memory")
	}
}
